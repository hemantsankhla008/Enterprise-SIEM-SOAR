# Matches the Python the project was built against; every pinned dependency
# (numpy, scipy, scikit-learn) has a prebuilt manylinux wheel for cp313, so the
# image builds without a compiler toolchain.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so the layer is cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Writable location for the SQLite database. Mount a volume here to persist
# incidents across restarts; without one the container filesystem is ephemeral.
RUN mkdir -p /var/data
ENV DATABASE_URL=sqlite:////var/data/logs.db

# Run as a non-root user.
RUN useradd --create-home --shell /usr/sbin/nologin siem \
    && chown -R siem:siem /app /var/data
USER siem

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status==200 else sys.exit(1)"

# Single worker, deliberately. Live WebSocket connections are held in process
# memory, so with multiple workers a broadcast would only reach the clients
# attached to the worker that handled the ingest. SQLite also tolerates exactly
# one writer. Scaling out requires moving the fan-out to Redis pub/sub and the
# database to Postgres.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
