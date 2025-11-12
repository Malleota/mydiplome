import os
import uuid
import logging
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

# ------------------ LOGGING ------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("zharko_api")

# ------------------ CONFIG ------------------
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "zharko_vkr")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")

log.info(f"Connecting to MySQL at {DB_HOST}:{DB_PORT}, DB={DB_NAME}, user={DB_USER}")

DSN = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
engine = create_engine(DSN, pool_pre_ping=True, future=True)

app = FastAPI(title="zharko_vkr simple API", version="0.1.1")

# Разрешаем все источники (для тестов)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ MODELS ------------------
class GreenhouseCreate(BaseModel):
    name: str
    description: Optional[str] = None
    target_temp_min: Optional[float] = None
    target_temp_max: Optional[float] = None
    target_hum_min: Optional[float] = None
    target_hum_max: Optional[float] = None

class GreenhouseOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    sensor_id: Optional[str] = None
    target_temp_min: Optional[float] = None
    target_temp_max: Optional[float] = None
    target_hum_min: Optional[float] = None
    target_hum_max: Optional[float] = None
    created_at: datetime

class BindSensorIn(BaseModel):
    ble_identifier: str

# ------------------ HELPERS ------------------
def new_id() -> str:
    return str(uuid.uuid4())

def db_execute(sql: str, params: dict = None, fetch: bool = False):
    """Вспомогательная функция с логами SQL."""
    params = params or {}
    try:
        with engine.begin() as conn:
            log.info(f"SQL: {sql.strip().splitlines()[0]}... | params={params}")
            res = conn.execute(text(sql), params)
            if fetch:
                rows = res.mappings().all()
                log.info(f"→ fetched {len(rows)} rows")
                return rows
            return None
    except SQLAlchemyError as e:
        log.error(f"DB ERROR: {e}")
        raise HTTPException(status_code=500, detail="Database error")

def one_or_404(row, msg="Not found"):
    if not row:
        log.warning(f"→ 404: {msg}")
        raise HTTPException(404, msg)

# ------------------ MIDDLEWARE: LOG REQUESTS ------------------
@app.middleware("http")
async def log_requests(request: Request, call_next):
    log.info(f"➡️ {request.method} {request.url.path}")
    response = await call_next(request)
    log.info(f"⬅️ {request.method} {request.url.path} → {response.status_code}")
    return response

# ------------------ ROUTES ------------------

@app.get("/health")
def health():
    """Проверка соединения с БД"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        log.info("Health check OK")
        return {"ok": True}
    except Exception as e:
        log.error(f"Health check failed: {e}")
        raise HTTPException(500, "DB connection failed")

@app.get("/greenhouses", response_model=List[GreenhouseOut])
def list_greenhouses():
    sql = """
    SELECT id, name, description, sensor_id,
           target_temp_min, target_temp_max,
           target_hum_min, target_hum_max, created_at
    FROM greenhouses
    ORDER BY created_at ASC
    """
    with engine.connect() as conn:
        log.info("Fetching greenhouses...")
        rows = conn.execute(text(sql)).mappings().all()
        log.info(f"Found {len(rows)} greenhouses")
        return [GreenhouseOut(**r) for r in rows]

@app.post("/greenhouses", response_model=GreenhouseOut, status_code=201)
def create_greenhouse(payload: GreenhouseCreate):
    gh_id = new_id()
    log.info(f"Creating greenhouse: {payload.name}")
    sql = """
    INSERT INTO greenhouses
      (id, name, description,
       target_temp_min, target_temp_max,
       target_hum_min, target_hum_max)
    VALUES
      (:id, :name, :description,
       :tmin, :tmax, :hmin, :hmax)
    """
    with engine.begin() as conn:
        conn.execute(text(sql), {
            "id": gh_id,
            "name": payload.name,
            "description": payload.description,
            "tmin": payload.target_temp_min,
            "tmax": payload.target_temp_max,
            "hmin": payload.target_hum_min,
            "hmax": payload.target_hum_max
        })
        row = conn.execute(text("""
            SELECT id, name, description, sensor_id,
                   target_temp_min, target_temp_max,
                   target_hum_min, target_hum_max, created_at
            FROM greenhouses WHERE id=:id
        """), {"id": gh_id}).mappings().first()
    log.info(f"Greenhouse created: {gh_id}")
    return GreenhouseOut(**row)

@app.get("/greenhouses/{gh_id}", response_model=GreenhouseOut)
def get_greenhouse(gh_id: str):
    log.info(f"Fetching greenhouse {gh_id}")
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT id, name, description, sensor_id,
                   target_temp_min, target_temp_max,
                   target_hum_min, target_hum_max, created_at
            FROM greenhouses WHERE id=:id
        """), {"id": gh_id}).mappings().first()
        one_or_404(row, "Greenhouse not found")
        return GreenhouseOut(**row)

@app.post("/greenhouses/{gh_id}/sensor", status_code=204)
def bind_sensor(gh_id: str, payload: BindSensorIn):
    log.info(f"Binding sensor {payload.ble_identifier} to greenhouse {gh_id}")
    with engine.begin() as conn:
        s = conn.execute(text("SELECT id FROM sensors WHERE ble_identifier=:b"),
                         {"b": payload.ble_identifier}).scalar()
        if s is None:
            s_id = new_id()
            conn.execute(text("INSERT INTO sensors (id, ble_identifier) VALUES (:id, :b)"),
                         {"id": s_id, "b": payload.ble_identifier})
            log.info(f"New sensor created {s_id}")
        else:
            s_id = s
        conn.execute(text("UPDATE greenhouses SET sensor_id=NULL WHERE sensor_id=:sid"), {"sid": s_id})
        updated = conn.execute(text("UPDATE greenhouses SET sensor_id=:sid WHERE id=:gh"),
                               {"sid": s_id, "gh": gh_id}).rowcount
        if updated == 0:
            log.warning(f"Greenhouse {gh_id} not found")
            raise HTTPException(404, "Greenhouse not found")
    log.info(f"Sensor bound successfully")
    return
