"""
DeepGuard NIDS - Database Models
SQLAlchemy ORM models for all database tables.
"""

import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    Text, Boolean, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session, relationship

Base = declarative_base()


# ─────────────────────────────────────────────
# TABLE: attacks
# ─────────────────────────────────────────────
class Attack(Base):
    __tablename__ = "attacks"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    attack_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    protocol = Column(String(10), nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    model_used = Column(String(50), nullable=False, default="random_forest")
    packet_size = Column(Integer, default=0)
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    alerts = relationship("Alert", back_populates="attack", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "protocol": self.protocol,
            "confidence": round(self.confidence, 4),
            "model_used": self.model_used,
            "packet_size": self.packet_size,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


# ─────────────────────────────────────────────
# TABLE: alerts
# ─────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")
    status = Column(String(20), nullable=False, default="new")  # new, acknowledged
    attack_id = Column(Integer, ForeignKey("attacks.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    attack = relationship("Attack", back_populates="alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "message": self.message,
            "severity": self.severity,
            "status": self.status,
            "attack_id": self.attack_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


# ─────────────────────────────────────────────
# TABLE: traffic_logs
# ─────────────────────────────────────────────
class TrafficLog(Base):
    __tablename__ = "traffic_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False)
    protocol = Column(String(10), nullable=False)
    packet_size = Column(Integer, default=0)
    source_port = Column(Integer, default=0)
    destination_port = Column(Integer, default=0)
    prediction = Column(String(50), nullable=False, default="Normal")
    confidence = Column(Float, default=0.0)
    model_used = Column(String(50), default="random_forest")
    is_attack = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "prediction": self.prediction,
            "confidence": round(self.confidence, 4),
            "model_used": self.model_used,
            "is_attack": self.is_attack,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


# ─────────────────────────────────────────────
# TABLE: blocked_ips
# ─────────────────────────────────────────────
class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    reason = Column(String(100), nullable=True)
    blocked_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None
        }


# ─────────────────────────────────────────────
# DATABASE ENGINE & SESSION FACTORY
# ─────────────────────────────────────────────
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

_engine = None
_session_factory = None


def get_engine():
    """Create or return the database engine, trying MySQL then SQLite."""
    global _engine
    if _engine is not None:
        return _engine

    from config.settings import DATABASE, DB_TYPE

    # Try MySQL first if configured
    if DB_TYPE == "mysql":
        try:
            uri = DATABASE["mysql"]["uri"]
            _engine = create_engine(
                uri, echo=DATABASE["mysql"]["echo"],
                pool_pre_ping=True, pool_recycle=280, pool_size=10, max_overflow=20
            )
            # Test connection
            with _engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print(f"[DB] Connected to MySQL: {uri}")
            return _engine
        except Exception as e:
            print(f"[DB] MySQL connection failed: {e}")
            print("[DB] Falling back to SQLite...")

    # Fallback to SQLite
    uri = DATABASE["sqlite"]["uri"]
    _engine = create_engine(
        uri,
        echo=DATABASE["sqlite"]["echo"],
        connect_args={"check_same_thread": False}
    )
    print(f"[DB] Connected to SQLite: {uri}")
    return _engine


def get_session():
    """Get a thread-safe database session."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    return _session_factory()


def remove_session():
    """Remove the current scoped session (call after each request)."""
    global _session_factory
    if _session_factory is not None:
        _session_factory.remove()


def init_db():
    """Create all tables."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    print("[DB] All tables created successfully.")


from sqlalchemy import text
