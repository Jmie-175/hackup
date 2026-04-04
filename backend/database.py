from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON
from datetime import datetime, timezone
from config import settings

DATABASE_URL = f"sqlite+aiosqlite:///{settings.db_path}"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    input_type = Column(String)          # email | url | attachment
    verdict = Column(String)             # safe | suspicious | threat
    score = Column(Integer)
    reasons = Column(JSON)
    signals = Column(JSON)
    chain = Column(JSON, nullable=True)
    campaign_id = Column(String, nullable=True)
    source = Column(String, default="paste")  # paste | extension


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String, primary_key=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    count = Column(Integer, default=1)
    brand_target = Column(String, nullable=True)
    sample_subject = Column(Text, nullable=True)
    avg_score = Column(Float, default=0.0)


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String, primary_key=True)
    scan_id = Column(String)
    correction = Column(String)   # false_positive | false_negative
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
