"""数据持久化层（SQLAlchemy ORM）。

默认用 SQLite（零配置，文件落在 backend/data/ipguard.db）；
换 Postgres 只需设置环境变量 DATABASE_URL=postgresql+psycopg2://user:pwd@host/db。
"""
from __future__ import annotations

import os
from datetime import datetime

from sqlalchemy import (JSON, Column, DateTime, Integer, String, Text, create_engine, event)
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ipguard.db")
DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DB_PATH}")

engine = create_engine(DB_URL, echo=False, future=True)
Session = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

# SQLite 并发优化：WAL 模式（读不阻塞写）+ 锁等待 5s，避免研判期间前端轮询读卡死
if DB_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_connection, _):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


# ---------------- 表结构 ----------------

class EventRow(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    event_hash = Column(String(64), unique=True, index=True)
    occurred_at = Column(DateTime, index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow)
    employee_id = Column(String, index=True)
    device_id = Column(String)
    category = Column(String, index=True)
    action = Column(String, index=True)
    target_type = Column(String)
    target_value = Column(String)
    size_bytes = Column(Integer, default=0)
    count = Column(Integer, default=1)
    source = Column(String, default="")  # ipguard / sangfor
    raw = Column(JSON)


class VerdictRow(Base):
    __tablename__ = "verdicts"
    id = Column(Integer, primary_key=True)
    employee_id = Column(String, index=True)
    device = Column(String)
    window_start = Column(DateTime, index=True)
    window_end = Column(DateTime)
    intent = Column(String)
    deviation = Column(String)
    risk_score = Column(Integer)
    explanation = Column(Text)
    channels = Column(JSON)
    ai_participated = Column(Integer, default=1)
    event_hashes = Column(JSON)
    model = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class AlertRow(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    employee_id = Column(String, index=True)
    scenario = Column(String)              # data_exfiltration / job_seeking / ...
    severity = Column(String)              # LOW/MED/HIGH/CRITICAL
    risk_score = Column(Integer)
    verdict_id = Column(Integer)
    summary = Column(Text)
    status = Column(String, default="NEW")  # NEW/TRIAGING/CONFIRMED/FP/CLOSED
    dedup_key = Column(String, index=True)
    window_start = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ProfileRow(Base):
    __tablename__ = "profiles"
    id = Column(Integer, primary_key=True)
    employee_id = Column(String, unique=True, index=True)
    as_of = Column(DateTime)
    payload = Column(JSON)


class FeedbackRow(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True)
    alert_id = Column(Integer, index=True)
    label = Column(String)                  # TP / FP
    reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class DictRow(Base):
    __tablename__ = "dicts"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)   # sensitive_keywords / job_sites / ...
    payload = Column(JSON)


class SettingRow(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)   # llm_base_url / llm_api_key / llm_model / syslog_* ...
    value = Column(Text)


class ExceptionRow(Base):
    """人工确认的误报豁免：某用户某类行为=正常（岗位/工作/时间需要）。"""
    __tablename__ = "exceptions"
    id = Column(Integer, primary_key=True)
    employee_id = Column(String, index=True)
    signal_type = Column(String)    # data_exfiltration / job_seeking / 等（与 intent 对应）
    reason = Column(String)         # 岗位需要 / 工作需要 / 时间正常 / 临时项目
    note = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # null=永久


# ---------------- 工具 ----------------

def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    Base.metadata.create_all(engine)
    # 兼容旧库：自动补 source 列（如果缺）
    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT source FROM events LIMIT 1"))
    except Exception:
        try:
            with engine.connect() as conn:
                conn.execute(__import__("sqlalchemy").text("ALTER TABLE events ADD COLUMN source VARCHAR DEFAULT ''"))
                conn.commit()
            print("DB: 已自动补 source 列")
        except Exception:
            pass


def upsert_event(session, ev) -> bool:
    """按 event_hash 幂等写入一条标准事件；已存在返回 False。"""
    from models import CanonicalEvent  # 局部导入，避免循环
    h = ev.event_hash()
    if session.query(EventRow).filter_by(event_hash=h).first():
        return False
    session.add(EventRow(
        event_hash=h, occurred_at=ev.occurred_at, employee_id=ev.employee_id,
        device_id=ev.device_id, category=ev.category, action=ev.action,
        target_type=ev.target_type, target_value=ev.target_value,
        size_bytes=ev.size_bytes, count=ev.count, source=getattr(ev, 'source', ''), raw=ev.raw,
    ))
    return True


def severity_of(score: int) -> str:
    if score >= 86: return "CRITICAL"
    if score >= 61: return "HIGH"
    if score >= 31: return "MEDIUM"
    return "LOW"


if __name__ == "__main__":
    init_db()
    print("DB 已初始化:", DB_URL)
