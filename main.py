import datetime
import logging
import os
from pathlib import Path
from typing import List

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from database import LogEntry, SecurityAlert, SessionLocal, init_db
from engine.auth import verify_api_key
from engine.detection import analyze_and_respond

logger = logging.getLogger("siem")

app = FastAPI(title="Enterprise SIEM & SOAR Engine")

# Absolute path: a relative "app/templates" only resolves when the process is
# started from the repository root, which is not guaranteed by a host's start command.
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Key handed to the browser. Analyst-scoped by default — never the admin key,
# since anything injected into the page is readable from the page source.
DASHBOARD_API_KEY = os.getenv(
    "DASHBOARD_API_KEY", os.getenv("ANALYST_API_KEY", "analyst-tier1-key-44")
)

init_db()


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        # Guarded: a socket can be dropped by both the request handler and a
        # failed broadcast, and list.remove() raises on an already-removed item.
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """
        Send to every live client, tolerating dead ones.

        Iterating the live list and letting a failed send propagate means one
        disconnected browser aborts the broadcast for every other analyst.
        """
        dead: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for connection in dead:
            self.disconnect(connection)


manager = ConnectionManager()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_demo_data() -> None:
    """
    Populate a first-run database with representative traffic.

    A freshly deployed instance otherwise renders an empty dashboard, and on a host
    with an ephemeral filesystem that happens after every restart. Skipped as soon
    as any log exists, and disabled entirely with SEED_DEMO_DATA=false.
    """
    if os.getenv("SEED_DEMO_DATA", "true").lower() not in ("1", "true", "yes"):
        return

    db = SessionLocal()
    try:
        if db.query(LogEntry).count() > 0:
            return

        samples = [
            ("10.0.2.15", "ENDPOINT_SYS", "GET /dashboard HTTP/1.1 200 OK"),
            ("10.0.2.15", "ENDPOINT_SYS", "User admin logged in from workstation-01"),
            (
                "192.168.1.100",
                "WEB_REQUEST",
                "GET /index.php?id=1 UNION SELECT 1,2,3,username,password FROM users",
            ),
            (
                "10.0.0.50",
                "ENDPOINT_AUTH",
                "Failed password for invalid user root from 10.0.0.50 port 55432 ssh2",
            ),
            (
                "192.168.1.105",
                "ENDPOINT_ANOMALY",
                "POWERSHELL_EXEC: powershell.exe -e AAGUAaABvAHMAdA==",
            ),
        ]

        for ip, event_type, message in samples:
            entry = LogEntry(source_ip=ip, event_type=event_type, raw_payload=message)
            db.add(entry)
            db.commit()
            analyze_and_respond(message, ip, db)

        logger.info("Seeded %d demo log events", len(samples))
    except Exception:
        logger.exception("Demo seeding failed; continuing with an empty database")
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    seed_demo_data()


@app.get("/healthz")
def health_check():
    """Liveness probe for the host's health check."""
    return {"status": "ok", "service": "enterprise-siem-soar"}


@app.get("/", response_class=HTMLResponse)
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.id.desc()).limit(20).all()
    logs = db.query(LogEntry).order_by(LogEntry.id.desc()).limit(20).all()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "alerts": alerts,
            "logs": logs,
            "dashboard_api_key": DASHBOARD_API_KEY,
        },
    )


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Client frames are heartbeats only; read and discard to keep the
            # connection open and to detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.post("/api/v1/ingest")
async def ingest_log(
    payload: dict,
    db: Session = Depends(get_db),
    auth_context: dict = Depends(verify_api_key),
):
    source_ip = payload.get("ip", "127.0.0.1")
    event_type = payload.get("event_type", "SYSLOG")
    raw_message = payload.get("message", "")

    if not raw_message:
        raise HTTPException(status_code=400, detail="Log message cannot be empty")

    log_entry = LogEntry(
        source_ip=source_ip, event_type=event_type, raw_payload=raw_message
    )
    db.add(log_entry)
    db.commit()

    triggered_rules, intel, playbook_actions = analyze_and_respond(
        raw_message, source_ip, db
    )

    event_data = {
        "time": log_entry.timestamp.strftime("%H:%M:%S"),
        "ip": source_ip,
        "message": raw_message,
        "threats": triggered_rules,
        "country": intel["country"],
        "isp": intel["isp"],
        "threat_score": intel["threat_score"],
        "playbook_actions": playbook_actions,
        "status": "OPEN",
        "priority": "P1" if intel["threat_score"] >= 80 else "P2",
    }
    await manager.broadcast(event_data)

    return {
        "status": "PROCESSED",
        "authorized_user": auth_context["user"],
        "role": auth_context["role"],
        "log_id": log_entry.id,
        "threats_detected": triggered_rules,
        "intel": intel,
        "playbook_actions": playbook_actions,
    }


@app.post("/api/v1/alert/{alert_id}/update")
async def update_incident_status(
    alert_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    auth_context: dict = Depends(verify_api_key),
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert / Case ID not found")

    alert.status = payload.get("status", alert.status)
    alert.analyst_notes = f"Updated by {auth_context['user']} ({auth_context['role']})"
    db.commit()

    return {
        "status": "SUCCESS",
        "updated_by": auth_context["user"],
        "role": auth_context["role"],
        "alert_id": alert_id,
        "updated_status": alert.status,
    }


# Phase 10: Automated Forensic Incident Reporting Endpoint
@app.get("/api/v1/report/export")
async def export_forensic_report(
    db: Session = Depends(get_db),
    auth_context: dict = Depends(verify_api_key),
):
    alerts = db.query(SecurityAlert).all()
    logs = db.query(LogEntry).all()

    report_payload = {
        "report_metadata": {
            "title": "Enterprise SIEM/SOAR Forensic Audit Report",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            "generated_by": auth_context["user"],
            "total_logs_ingested": len(logs),
            "total_incidents_logged": len(alerts),
        },
        "incidents": [
            {
                "case_id": alert.id,
                "timestamp": str(alert.timestamp),
                "rule_triggered": alert.rule_name,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "origin_country": alert.country,
                "isp": alert.isp,
                "threat_score": alert.threat_score,
                "soar_remediation_action": alert.action_taken,
                "status": alert.status,
                "notes": alert.analyst_notes,
            }
            for alert in alerts
        ],
    }
    return JSONResponse(content=report_payload)
