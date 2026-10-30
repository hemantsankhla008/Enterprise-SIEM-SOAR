import os
from fastapi import Header, HTTPException, status

# RBAC key store.
#
# Keys are read from the environment so that a deployed instance never ships the
# development values. Each var is optional; if unset, the local development key is
# used, which keeps `uvicorn` working out of the box on a laptop.
#
# Set all three in production:
#   ADMIN_API_KEY, AGENT_API_KEY, ANALYST_API_KEY
VALID_API_KEYS = {
    os.getenv("ADMIN_API_KEY", "admin-sec-key-99"): {
        "role": "ADMIN",
        "user": "admin_soc",
    },
    os.getenv("AGENT_API_KEY", "agent-ingest-key-11"): {
        "role": "ENDPOINT_AGENT",
        "user": "agent_collector",
    },
    os.getenv("ANALYST_API_KEY", "analyst-tier1-key-44"): {
        "role": "SOC_ANALYST",
        "user": "analyst_tier1",
    },
}


def verify_api_key(x_api_key: str | None = Header(default=None)):
    """
    Validates incoming request headers for authentic RBAC access.

    A missing header is rejected. Supplying a fallback key as the header default
    would make every unauthenticated request succeed as a valid analyst, which
    leaves the ingest API open to anyone who finds the URL.
    """
    if not x_api_key or x_api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized API Access: Invalid or missing Security Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return VALID_API_KEYS[x_api_key]
