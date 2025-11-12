import os
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text

# ------------------ CONFIG ------------------
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "zharko_vkr")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")

DSN = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
engine = create_engine(DSN, pool_pre_ping=True, future=True)

app = FastAPI(title="zharko_vkr simple API", version="0.1.0")

# в dev-режиме разрешаем всё (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ SCHEMAS ------------------
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

class PlantTypeCreate(BaseModel):
    name: str
    description: Optional[str] = None
    temp_min: Optional[float] = None
    temp_max: Optional[float] = None
    humidity_min: Optional[float] = None
    humidity_max: Optional[float] = None
    watering_interval_days: Optional[int] = None
    fertilizing_interval_days: Optional[int] = None

class PlantTypeOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    temp_min: Optional[float] = None
    temp_max: Optional[float] = None
    humidity_min: Optional[float] = None
    humidity_max: Optional[float] = None
    watering_interval_days: Optional[int] = None
    fertilizing_interval_days: Optional[int] = None

class PlantInstanceCreate(BaseModel):
    plant_type_id: str
    quantity: int = Field(1, ge=1)
    note: Optional[str] = None

class PlantInstanceOut(BaseModel):
    id: str
    greenhouse_id: str
    plant_type_id: str
    quantity: int
    note: Optional[str] = None

class BindSensorIn(BaseModel):
    ble_identifier: str

class WaterEventCreate(BaseModel):
    greenhouse_id: str
    user_id: Optional[str] = None
    plant_instance_id: Optional[str] = None
    type: str = Field(..., pattern="^(watering|fertilizing)$")
    comment: Optional[str] = None

class WaterEventOut(BaseModel):
    id: str
    greenhouse_id: str
    user_id: Optional[str] = None
    plant_instance_id: Optional[str] = None
    type: str
    created_at: datetime
    comment: Optional[str] = None

# ------------------ HELPERS ------------------
def new_id() -> str:
    return str(uuid.uuid4())

def one_or_404(row, msg="Not found"):
    if not row:
        raise HTTPException(404, msg)

# ------------------ ENDPOINTS ------------------
@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True}

# --- Greenhouses ---
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
        rows = conn.execute(text(sql)).mappings().all()
        return [GreenhouseOut(**r) for r in rows]

@app.post("/greenhouses", response_model=GreenhouseOut, status_code=201)
def create_greenhouse(payload: GreenhouseCreate):
    gh_id = new_id()
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
    return GreenhouseOut(**row)

@app.get("/greenhouses/{gh_id}", response_model=GreenhouseOut)
def get_greenhouse(gh_id: str):
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
    with engine.begin() as conn:
        s = conn.execute(text("SELECT id FROM sensors WHERE ble_identifier=:b"),
                         {"b": payload.ble_identifier}).scalar()
        if s is None:
            s_id = new_id()
            conn.execute(text("INSERT INTO sensors (id, ble_identifier) VALUES (:id, :b)"),
                         {"id": s_id, "b": payload.ble_identifier})
        else:
            s_id = s
        conn.execute(text("UPDATE greenhouses SET sensor_id=NULL WHERE sensor_id=:sid"), {"sid": s_id})
        updated = conn.execute(text("UPDATE greenhouses SET sensor_id=:sid WHERE id=:gh"),
                               {"sid": s_id, "gh": gh_id}).rowcount
        if updated == 0:
            raise HTTPException(404, "Greenhouse not found")
    return

# --- Plant types ---
@app.get("/plant-types", response_model=List[PlantTypeOut])
def list_plant_types():
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, name, description, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types ORDER BY name ASC
        """)).mappings().all()
        return [PlantTypeOut(**r) for r in rows]

@app.post("/plant-types", response_model=PlantTypeOut, status_code=201)
def create_plant_type(payload: PlantTypeCreate):
    pt_id = new_id()
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO plant_types
              (id, name, description, temp_min, temp_max,
               humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days)
            VALUES
              (:id, :name, :description, :tmin, :tmax, :hmin, :hmax, :wi, :fi)
        """), {
            "id": pt_id,
            "name": payload.name,
            "description": payload.description,
            "tmin": payload.temp_min,
            "tmax": payload.temp_max,
            "hmin": payload.humidity_min,
            "hmax": payload.humidity_max,
            "wi": payload.watering_interval_days,
            "fi": payload.fertilizing_interval_days
        })
        row = conn.execute(text("""
            SELECT id, name, description, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types WHERE id=:id
        """), {"id": pt_id}).mappings().first()
    return PlantTypeOut(**row)

# --- Plant instances in greenhouse ---
@app.post("/greenhouses/{gh_id}/plants", response_model=PlantInstanceOut, status_code=201)
def add_plant_instance(gh_id: str, payload: PlantInstanceCreate):
    pi_id = new_id()
    with engine.begin() as conn:
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}).scalar()
        if not gh:
            raise HTTPException(404, "Greenhouse not found")
        pt = conn.execute(text("SELECT 1 FROM plant_types WHERE id=:id"), {"id": payload.plant_type_id}).scalar()
        if not pt:
            raise HTTPException(404, "Plant type not found")

        conn.execute(text("""
            INSERT INTO plant_instances (id, greenhouse_id, plant_type_id, quantity, note)
            VALUES (:id, :gh, :pt, :q, :note)
        """), {"id": pi_id, "gh": gh_id, "pt": payload.plant_type_id, "q": payload.quantity, "note": payload.note})

        row = conn.execute(text("""
            SELECT id, greenhouse_id, plant_type_id, quantity, note
            FROM plant_instances WHERE id=:id
        """), {"id": pi_id}).mappings().first()
    return PlantInstanceOut(**row)

# --- Watering events ---
@app.get("/watering-events", response_model=List[WaterEventOut])
def list_watering_events(greenhouse_id: Optional[str] = None,
                         date_from: Optional[str] = None,
                         date_to: Optional[str] = None):
    clauses = []
    params = {}
    if greenhouse_id:
        clauses.append("greenhouse_id = :gh")
        params["gh"] = greenhouse_id
    if date_from:
        clauses.append("created_at >= :df")
        params["df"] = date_from
    if date_to:
        clauses.append("created_at <= :dt")
        params["dt"] = date_to

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, greenhouse_id, user_id, plant_instance_id, type, created_at, comment
        FROM watering_events
        {where}
        ORDER BY created_at DESC
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return [WaterEventOut(**r) for r in rows]

@app.post("/watering-events", response_model=WaterEventOut, status_code=201)
def create_watering_event(payload: WaterEventCreate):
    ev_id = new_id()
    with engine.begin() as conn:
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"),
                          {"id": payload.greenhouse_id}).scalar()
        if not gh:
            raise HTTPException(404, "Greenhouse not found")

        conn.execute(text("""
            INSERT INTO watering_events
              (id, greenhouse_id, user_id, plant_instance_id, type, comment)
            VALUES
              (:id, :gh, :uid, :pid, :type, :comment)
        """), {
            "id": ev_id,
            "gh": payload.greenhouse_id,
            "uid": payload.user_id,
            "pid": payload.plant_instance_id,
            "type": payload.type,
            "comment": payload.comment
        })

        row = conn.execute(text("""
            SELECT id, greenhouse_id, user_id, plant_instance_id, type, created_at, comment
            FROM watering_events WHERE id=:id
        """), {"id": ev_id}).mappings().first()
    return WaterEventOut(**row)
