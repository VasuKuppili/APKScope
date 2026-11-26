import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# For SQLite, handle multithreading safely
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}

engine = create_engine(DB_URL, connect_args=connect_args, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    # Ensure backward-compatible schema updates for SQLite
    try:
        with engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(analysis_records)")).fetchall()
            cols = [r[1] for r in result]
            if cols and "threat_intelligence" not in cols:
                conn.execute(text("ALTER TABLE analysis_records ADD COLUMN threat_intelligence TEXT"))
                conn.commit()
    except Exception:
        pass
