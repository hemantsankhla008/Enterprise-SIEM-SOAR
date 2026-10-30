"""
SIEM endpoint collector agent.

Simulates an endpoint forwarding telemetry to the ingestion API. Point it at a
deployed instance with SIEM_ENDPOINT and authenticate with SIEM_API_KEY:

    SIEM_ENDPOINT=https://your-app.onrender.com/api/v1/ingest \
    SIEM_API_KEY=your-agent-key \
    python agent.py
"""

import os
import random
import time

import requests

# Ingestion endpoint. Defaults to a local dev server.
SIEM_ENDPOINT = os.getenv("SIEM_ENDPOINT", "http://127.0.0.1:8000/api/v1/ingest")

# The ingest API rejects unauthenticated requests, so the agent must present a key.
SIEM_API_KEY = os.getenv("SIEM_API_KEY", "agent-ingest-key-11")

SEND_INTERVAL_SECONDS = float(os.getenv("SEND_INTERVAL_SECONDS", "3"))

# Endpoint Agent Log Streams
SIMULATED_LOG_STREAM = [
    {
        "ip": "10.0.2.15",
        "event_type": "ENDPOINT_SYS",
        "message": "GET /dashboard HTTP/1.1 200 OK",
    },
    {
        "ip": "10.0.2.15",
        "event_type": "ENDPOINT_SYS",
        "message": "User admin logged in from workstation-01",
    },
    {
        "ip": "192.168.1.220",
        "event_type": "ENDPOINT_AUTH",
        "message": "Failed password for invalid user root from 192.168.1.220 port 55432 ssh2",
    },
    {
        "ip": "10.0.2.15",
        "event_type": "ENDPOINT_SYS",
        "message": "GET /index.php?id=1 UNION SELECT 1,2,3,username,password FROM users",
    },
    {
        "ip": "192.168.1.88",
        "event_type": "ENDPOINT_ANOMALY",
        "message": "POWERSHELL_EXEC: powershell.exe -e AAGUAaABvAHMAdA...",
    },
]


def run_agent():
    print("SIEM Endpoint Collector Agent Active...")
    print(f"Forwarding telemetry to: {SIEM_ENDPOINT}\n")

    headers = {"x-api-key": SIEM_API_KEY, "Content-Type": "application/json"}

    try:
        while True:
            log_payload = random.choice(SIMULATED_LOG_STREAM)

            try:
                response = requests.post(
                    SIEM_ENDPOINT, json=log_payload, headers=headers, timeout=10
                )
                if response.status_code == 200:
                    print(f"[SENT] {log_payload['ip']} -> {log_payload['message'][:50]}...")
                elif response.status_code == 401:
                    print("[AUTH] Rejected: set SIEM_API_KEY to a key the server accepts.")
                else:
                    print(f"[ERROR] Failed to forward log: HTTP {response.status_code}")
            except requests.RequestException as exc:
                # A transient network fault should not kill a long-running collector.
                print(f"[NETWORK] {type(exc).__name__}: {exc}")

            time.sleep(SEND_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nEndpoint Agent Stopped.")


if __name__ == "__main__":
    run_agent()
