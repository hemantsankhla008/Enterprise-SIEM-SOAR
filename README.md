# Enterprise SIEM & SOAR Platform

Real-time log ingestion, hybrid threat detection (signature rules + unsupervised ML),
threat-intel enrichment, and autonomous SOAR remediation playbooks, with a live
WebSocket dashboard and forensic JSON export.

**Stack:** Python 3.13 · FastAPI · Uvicorn · SQLAlchemy / SQLite · scikit-learn
(Isolation Forest) · WebSockets · Tailwind CSS · Chart.js

---

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Dashboard: http://127.0.0.1:8000 · Health: `/healthz` · API docs: `/docs`

Feed it simulated endpoint telemetry in a second terminal:

```bash
python agent.py
```

On first run the database is seeded with sample traffic that exercises all three
detection paths, so the dashboard is populated immediately. Disable with
`SEED_DEMO_DATA=false`.

---

## Deploy

### Render (blueprint included)

`render.yaml` is committed, so Render configures everything on import: Python 3.13,
build and start commands, `/healthz` health check, and freshly generated API keys.

1. Push this repository to GitHub.
2. Render Dashboard → **New** → **Blueprint** → select the repo.
3. Apply. Read the generated `ADMIN_API_KEY` / `AGENT_API_KEY` / `ANALYST_API_KEY`
   from the service's Environment tab.

### Docker (any host)

```bash
docker build -t siem-soar .
docker run -p 8000:8000 \
  -e ADMIN_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -e ANALYST_API_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  -v siem-data:/var/data \
  siem-soar
```

The named volume keeps incident history across restarts.

### Railway / Fly / Heroku-style hosts

`Procfile` and `runtime.txt` are included; the platform's buildpack detects both.
Set the API key environment variables before the first deploy.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_API_KEY` | `admin-sec-key-99` | ADMIN role key |
| `AGENT_API_KEY` | `agent-ingest-key-11` | ENDPOINT_AGENT role key |
| `ANALYST_API_KEY` | `analyst-tier1-key-44` | SOC_ANALYST role key |
| `DASHBOARD_API_KEY` | falls back to `ANALYST_API_KEY` | Key injected into the dashboard page |
| `DATABASE_URL` | `sqlite:///./logs.db` | SQLAlchemy URL |
| `SEED_DEMO_DATA` | `true` | Seed sample traffic when the database is empty |
| `PORT` | `8000` | Listen port |

The defaults exist so a fresh clone runs without setup. **Override all three keys
before exposing the app publicly.**

---

## API

All endpoints require an `x-api-key` header.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Live SOC dashboard |
| `GET` | `/healthz` | Liveness probe |
| `WS` | `/ws/alerts` | Real-time alert stream |
| `POST` | `/api/v1/ingest` | Ingest a log event |
| `POST` | `/api/v1/alert/{id}/update` | Transition case status |
| `GET` | `/api/v1/report/export` | Forensic audit report (JSON) |

```bash
curl -X POST http://127.0.0.1:8000/api/v1/ingest \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: admin-sec-key-99' \
  -d '{"ip":"192.168.1.100","event_type":"WEB",
       "message":"GET /p.php?id=1 UNION SELECT user,pass FROM admins"}'
```

---

## Architecture notes

**Single worker, deliberately.** Live WebSocket connections are held in process
memory, so with more than one worker a broadcast only reaches clients attached to
the worker that handled the ingest. SQLite also supports a single writer. Scaling
horizontally means moving the fan-out to Redis pub/sub and the database to Postgres.

**Ephemeral storage.** Most managed hosts give containers a disposable filesystem,
so on a free plan the SQLite database resets on restart or spin-down. Attach a
persistent disk and point `DATABASE_URL` at it to retain incident history.

**Threat intel is a local fixture.** `app/engine/threat_intel.py` resolves IPs
against an in-process dictionary. Swapping in a live provider (AbuseIPDB,
MaxMind GeoLite2) means replacing `enrich_ip_intel()` only.

**The dashboard holds an API key.** It is injected server-side and analyst-scoped,
never the admin key, because anything rendered into the page is readable from the
page source. A session-cookie login would be the next step for a multi-user
deployment.

---

## Layout

```
├── app/
│   ├── main.py              # FastAPI routes, WebSocket manager, seeding
│   ├── database.py          # SQLAlchemy models (raw_logs, security_alerts)
│   ├── engine/
│   │   ├── auth.py          # API key RBAC
│   │   ├── detection.py     # Rule engine + ML dispatch
│   │   ├── ml_engine.py     # Isolation Forest anomaly detector
│   │   ├── threat_intel.py  # IP reputation / GeoIP enrichment
│   │   └── soar_playbook.py # Automated remediation playbooks
│   └── templates/
│       └── dashboard.html   # Live SOC dashboard
├── agent.py                 # Endpoint collector simulator
├── Dockerfile · render.yaml · Procfile · runtime.txt
└── requirements.txt
```
