import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy import create_engine, event

from database import ensure_schema

# Database configuration
DB_PATH = os.getenv("DB_PATH", "flowers.db")
DSN = f"sqlite:///{DB_PATH}"

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("flowers-api")

# JWT configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

# Password hashing configuration
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 scheme for JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# SQLAlchemy engine
engine = create_engine(DSN, connect_args={"check_same_thread": False}, echo=False)

# Base URL configuration
BASE_URL = os.getenv("BASE_URL", "http://95.140.158.180:8000")

# Static files configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
AVATARS_DIR = os.path.join(STATIC_DIR, "avatars")
PLANT_TYPES_DIR = os.path.join(STATIC_DIR, "plant-types")
GREENHOUSES_DIR = os.path.join(STATIC_DIR, "greenhouses")

# Создаём папки при старте, если их нет
os.makedirs(AVATARS_DIR, exist_ok=True)
os.makedirs(PLANT_TYPES_DIR, exist_ok=True)
os.makedirs(GREENHOUSES_DIR, exist_ok=True)


def get_full_static_url(relative_path: Optional[str]) -> Optional[str]:
    """Преобразует относительный путь в полный URL для статических файлов."""
    if not relative_path:
        return None
    if relative_path.startswith("http://") or relative_path.startswith("https://"):
        return relative_path
    # Убираем ведущий слэш, если есть, и добавляем BASE_URL
    path = relative_path.lstrip("/")
    return f"{BASE_URL.rstrip('/')}/{path}"


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable SQLite foreign keys for every connection."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler."""
    logger.info("Инициализация схемы базы данных...")
    try:
        ensure_schema(engine, DB_PATH)
        logger.info("Сервис запущен и готов к работе")
    except Exception as exc:  # pragma: no cover - critical startup failure
        logger.error("Ошибка при инициализации: %s", exc)
        raise

    yield

    logger.info("Завершение работы сервера...")

