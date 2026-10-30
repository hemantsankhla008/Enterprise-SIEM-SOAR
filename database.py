import datetime
import os

from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Configurable so the database can be pointed at a mounted persistent disk.
# Managed hosts give containers an ephemeral filesystem: with the default
# relative path, every restart or redeploy starts the database from empty.
# To persist, attach a disk and set e.g.
#   DATABASE_URL=sqlite:////var/data/logs.db
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./logs.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _utcnow():
    """Timezone-aware UTC. datetime.utcnow() is deprecated from Python 3.12."""
    return datetime.datetime.now(datetime.timezone.utc)


class LogEntry(Base):
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=_utcnow)
    source_ip = Column(String, index=True)
    event_type = Column(String)
    raw_payload = Column(String)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=_utcnow)
    rule_name = Column(String)
    severity = Column(String)
    source_ip = Column(String)
    action_taken = Column(String)

    # Phase 6 Extensions
    country = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")
    threat_score = Column(Integer, default=0)

    # Phase 8: Incident Case Management Extensions
    status = Column(String, default="OPEN")  # OPEN, INVESTIGATING, RESOLVED
    priority = Column(String, default="P2")  # P1 (Critical), P2 (High), P3 (Medium)
    analyst_notes = Column(String, default="Pending SOC Triage")


def init_db():
    Base.metadata.create_all(bind=engine)
