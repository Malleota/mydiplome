import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import List, Optional, AsyncGenerator

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, text, event
from database import ensure_schema

# ------------------ CONFIG ------------------
# SQLite локальная база данных
DB_PATH = os.getenv("DB_PATH", "flowers.db")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("flowers-api")

# JWT конфигурация
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 часа

# Настройка хеширования паролей (используем argon2 - более безопасный и без ограничения длины)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 схема для токенов
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# SQLite подключение (файловая БД)
DSN = f"sqlite:///{DB_PATH}"
engine = create_engine(DSN, connect_args={"check_same_thread": False}, echo=False)

# Включаем поддержку внешних ключей для всех соединений SQLite
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Включает поддержку внешних ключей для каждого соединения SQLite."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Обработчик жизненного цикла приложения."""
    # Startup
    logger.info("Инициализация схемы базы данных...")
    try:
        ensure_schema(engine, DB_PATH)
        logger.info("Сервис запущен и готов к работе")
    except Exception as e:
        logger.error(f"Ошибка при инициализации: {e}")
        raise
    
    yield
    
    # Shutdown (если нужно что-то закрыть)
    logger.info("Завершение работы сервера...")


app = FastAPI(title="zharko_vkr simple API", version="0.1.0", lifespan=lifespan)

# в dev-режиме разрешаем всё (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------ SCHEMAS ------------------
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    name: Optional[str] = None
    role: str = Field("worker", pattern="^(admin|worker)$")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserOut(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime

class TokenData(BaseModel):
    user_id: Optional[str] = None

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

class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|worker)$")

class BindWorkerIn(BaseModel):
    user_id: str

class SensorDataIn(BaseModel):
    ble_identifier: str
    temperature: float
    humidity: float

class AlertOut(BaseModel):
    id: str
    greenhouse_id: Optional[str] = None
    user_id: Optional[str] = None
    type: str
    message: str
    severity: str
    is_read: bool
    created_at: datetime

class ReportOut(BaseModel):
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    greenhouse_id: Optional[str] = None
    greenhouse_name: Optional[str] = None
    event_type: str
    event_id: str
    plant_instance_id: Optional[str] = None
    created_at: datetime
    comment: Optional[str] = None

# ------------------ HELPERS ------------------
def new_id() -> str:
    return str(uuid.uuid4())

def one_or_404(row, msg="Not found"):
    if not row:
        raise HTTPException(404, msg)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль с хешем."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Хеширует пароль."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Создаёт JWT токен."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Получает текущего пользователя из JWT токена."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """), {"id": token_data.user_id}).mappings().first()
        
        if not row:
            raise credentials_exception
        
        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Пользователь неактивен"
            )
        
        return dict(row)

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Проверяет, что текущий пользователь является администратором."""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуются права администратора"
        )
    return current_user

def send_push_notification(user_id: Optional[str], message: str, title: str = "Уведомление"):
    """Отправляет push-уведомление пользователю (заглушка для интеграции с FCM)."""
    # TODO: Интеграция с Firebase Cloud Messaging или другим сервисом
    logger.info(f"Push notification to user {user_id}: {title} - {message}")
    # В реальной реализации здесь будет вызов FCM API




# ------------------ ENDPOINTS ------------------
@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True}

# --- Auth ---
@app.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister):
    """Регистрация нового пользователя."""
    user_id = new_id()
    
    with engine.begin() as conn:
        # Проверяем, существует ли пользователь с таким email
        existing = conn.execute(
            text("SELECT id FROM users WHERE email=:email"),
            {"email": payload.email}
        ).scalar()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким email уже существует"
            )
        
        # Хешируем пароль
        password_hash = get_password_hash(payload.password)
        
        # Создаём пользователя
        conn.execute(text("""
            INSERT INTO users (id, email, password_hash, name, role, is_active)
            VALUES (:id, :email, :pwd, :name, :role, 1)
        """), {
            "id": user_id,
            "email": payload.email,
            "pwd": password_hash,
            "name": payload.name,
            "role": payload.role
        })
        
        # Получаем созданного пользователя
        row = conn.execute(text("""
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """), {"id": user_id}).mappings().first()
    
    logger.info(f"Зарегистрирован новый пользователь: {payload.email} (ID: {user_id})")
    return UserOut(**row)

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Авторизация пользователя и получение JWT токена."""
    with engine.connect() as conn:
        # Ищем пользователя по email
        row = conn.execute(text("""
            SELECT id, email, password_hash, is_active
            FROM users WHERE email=:email
        """), {"email": form_data.username}).mappings().first()
        
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный email или пароль",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Проверяем пароль
        if not verify_password(form_data.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный email или пароль",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Проверяем активность
        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Пользователь неактивен"
            )
        
        # Создаём токен
        access_token_expires = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": row["id"]},
            expires_delta=access_token_expires
        )
    
    logger.info(f"Пользователь авторизован: {form_data.username} (ID: {row['id']})")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=UserOut)
def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем авторизованном пользователе."""
    return UserOut(**current_user)

# --- Users (Admin only) ---
@app.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(user_id: str, payload: UserRoleUpdate, admin: dict = Depends(require_admin)):
    """Изменение статуса пользователя (с worker на admin и с admin на worker). Доступ: admin."""
    with engine.begin() as conn:
        # Проверяем существование пользователя
        user = conn.execute(text("""
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """), {"id": user_id}).mappings().first()
        
        if not user:
            raise HTTPException(404, "User not found")
        
        # Обновляем роль
        conn.execute(text("""
            UPDATE users SET role=:role WHERE id=:id
        """), {"id": user_id, "role": payload.role})
        
        # Получаем обновленного пользователя
        updated_user = conn.execute(text("""
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """), {"id": user_id}).mappings().first()
    
    logger.info(f"Роль пользователя {user_id} изменена на {payload.role} администратором {admin['id']}")
    return UserOut(**updated_user)

# --- Greenhouses ---
@app.get("/greenhouses", response_model=List[GreenhouseOut])
def list_greenhouses(current_user: dict = Depends(get_current_user)):
    """Получение списка теплиц. Админ видит все, рабочий - только привязанные."""
    with engine.connect() as conn:
        if current_user["role"] == "admin":
            # Админ видит все теплицы
            sql = """
                SELECT id, name, description, sensor_id,
                       target_temp_min, target_temp_max,
                       target_hum_min, target_hum_max, created_at
                FROM greenhouses
                ORDER BY created_at ASC
            """
            rows = conn.execute(text(sql)).mappings().all()
        else:
            # Рабочий видит только привязанные теплицы
            sql = """
                SELECT g.id, g.name, g.description, g.sensor_id,
                       g.target_temp_min, g.target_temp_max,
                       g.target_hum_min, g.target_hum_max, g.created_at
                FROM greenhouses g
                INNER JOIN user_greenhouses ug ON g.id = ug.greenhouse_id
                WHERE ug.user_id = :user_id
                ORDER BY g.created_at ASC
            """
            rows = conn.execute(text(sql), {"user_id": current_user["id"]}).mappings().all()
        
        return [GreenhouseOut(**r) for r in rows]

@app.post("/greenhouses", response_model=GreenhouseOut, status_code=201)
def create_greenhouse(payload: GreenhouseCreate, admin: dict = Depends(require_admin)):
    """Создание теплицы. Доступ: admin."""
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
def get_greenhouse(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение информации о теплице."""
    with engine.connect() as conn:
        # Проверяем доступ для рабочего
        if current_user["role"] == "worker":
            has_access = conn.execute(text("""
                SELECT 1 FROM user_greenhouses
                WHERE user_id=:user_id AND greenhouse_id=:gh_id
            """), {"user_id": current_user["id"], "gh_id": gh_id}).scalar()
            if not has_access:
                raise HTTPException(403, "Access denied to this greenhouse")
        
        row = conn.execute(text("""
            SELECT id, name, description, sensor_id,
                   target_temp_min, target_temp_max,
                   target_hum_min, target_hum_max, created_at
            FROM greenhouses WHERE id=:id
        """), {"id": gh_id}).mappings().first()
        one_or_404(row, "Greenhouse not found")
        return GreenhouseOut(**row)

@app.delete("/greenhouses/{gh_id}", status_code=204)
def delete_greenhouse(gh_id: str, admin: dict = Depends(require_admin)):
    """Удаление теплицы. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(text("DELETE FROM greenhouses WHERE id=:id"), {"id": gh_id}).rowcount
        if deleted == 0:
            raise HTTPException(404, "Greenhouse not found")
    logger.info(f"Теплица {gh_id} удалена администратором {admin['id']}")

@app.post("/greenhouses/{gh_id}/sensor", status_code=204)
def bind_sensor(gh_id: str, payload: BindSensorIn, admin: dict = Depends(require_admin)):
    """Привязка датчика BLE к теплице. Доступ: admin."""
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
    logger.info(f"Датчик {payload.ble_identifier} привязан к теплице {gh_id}")
    return

@app.delete("/greenhouses/{gh_id}/sensor", status_code=204)
def unbind_sensor(gh_id: str, admin: dict = Depends(require_admin)):
    """Отвязка датчика BLE от теплицы. Доступ: admin."""
    with engine.begin() as conn:
        updated = conn.execute(text("UPDATE greenhouses SET sensor_id=NULL WHERE id=:gh"),
                               {"gh": gh_id}).rowcount
        if updated == 0:
            raise HTTPException(404, "Greenhouse not found")
    logger.info(f"Датчик отвязан от теплицы {gh_id}")

@app.post("/greenhouses/{gh_id}/workers", status_code=204)
def bind_worker(gh_id: str, payload: BindWorkerIn, admin: dict = Depends(require_admin)):
    """Привязка рабочего к теплице. Доступ: admin."""
    with engine.begin() as conn:
        # Проверяем существование теплицы
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}).scalar()
        if not gh:
            raise HTTPException(404, "Greenhouse not found")
        
        # Проверяем существование пользователя и что он worker
        user = conn.execute(text("SELECT role FROM users WHERE id=:id"), {"id": payload.user_id}).mappings().first()
        if not user:
            raise HTTPException(404, "User not found")
        if user["role"] != "worker":
            raise HTTPException(400, "User must be a worker")
        
        # Привязываем
        try:
            conn.execute(text("""
                INSERT INTO user_greenhouses (user_id, greenhouse_id)
                VALUES (:user_id, :gh_id)
            """), {"user_id": payload.user_id, "gh_id": gh_id})
        except Exception:
            # Уже привязан
            pass
    logger.info(f"Рабочий {payload.user_id} привязан к теплице {gh_id}")

@app.delete("/greenhouses/{gh_id}/workers/{user_id}", status_code=204)
def unbind_worker(gh_id: str, user_id: str, admin: dict = Depends(require_admin)):
    """Отвязка рабочего от теплицы. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(text("""
            DELETE FROM user_greenhouses
            WHERE user_id=:user_id AND greenhouse_id=:gh_id
        """), {"user_id": user_id, "gh_id": gh_id}).rowcount
        if deleted == 0:
            raise HTTPException(404, "Binding not found")
    logger.info(f"Рабочий {user_id} отвязан от теплицы {gh_id}")

# --- Plant types ---
@app.get("/plant-types", response_model=List[PlantTypeOut])
def list_plant_types(current_user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, name, description, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types ORDER BY name ASC
        """)).mappings().all()
        return [PlantTypeOut(**r) for r in rows]

@app.post("/plant-types", response_model=PlantTypeOut, status_code=201)
def create_plant_type(payload: PlantTypeCreate, admin: dict = Depends(require_admin)):
    """Добавление растения в справочник. Доступ: admin."""
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
    logger.info(f"Тип растения {payload.name} добавлен в справочник")
    return PlantTypeOut(**row)

@app.delete("/plant-types/{pt_id}", status_code=204)
def delete_plant_type(pt_id: str, admin: dict = Depends(require_admin)):
    """Удаление растения из справочника. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(text("DELETE FROM plant_types WHERE id=:id"), {"id": pt_id}).rowcount
        if deleted == 0:
            raise HTTPException(404, "Plant type not found")
    logger.info(f"Тип растения {pt_id} удален из справочника")

# --- Plant instances in greenhouse ---
@app.post("/greenhouses/{gh_id}/plants", response_model=PlantInstanceOut, status_code=201)
def add_plant_instance(gh_id: str, payload: PlantInstanceCreate, admin: dict = Depends(require_admin)):
    """Добавление растения в теплицу. Доступ: admin."""
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
    logger.info(f"Растение добавлено в теплицу {gh_id}")
    return PlantInstanceOut(**row)

@app.delete("/greenhouses/{gh_id}/plants/{pi_id}", status_code=204)
def delete_plant_instance(gh_id: str, pi_id: str, admin: dict = Depends(require_admin)):
    """Удаление растения из теплицы. Доступ: admin."""
    with engine.begin() as conn:
        # Проверяем, что растение принадлежит этой теплице
        pi = conn.execute(text("""
            SELECT id FROM plant_instances
            WHERE id=:pi_id AND greenhouse_id=:gh_id
        """), {"pi_id": pi_id, "gh_id": gh_id}).scalar()
        if not pi:
            raise HTTPException(404, "Plant instance not found in this greenhouse")
        
        deleted = conn.execute(text("DELETE FROM plant_instances WHERE id=:id"), {"id": pi_id}).rowcount
    logger.info(f"Растение {pi_id} удалено из теплицы {gh_id}")

# --- Watering events ---
@app.get("/watering-events", response_model=List[WaterEventOut])
def list_watering_events(
    greenhouse_id: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Получение списка событий полива/удобрения с фильтрацией."""
    clauses = []
    params = {}
    
    # Для рабочих ограничиваем доступ только их теплицами
    if current_user["role"] == "worker":
        clauses.append("""
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = we.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """)
        params["current_user_id"] = current_user["id"]
    
    if greenhouse_id:
        clauses.append("we.greenhouse_id = :gh")
        params["gh"] = greenhouse_id
    if user_id:
        clauses.append("we.user_id = :uid")
        params["uid"] = user_id
    if date_from:
        clauses.append("we.created_at >= :df")
        params["df"] = date_from
    if date_to:
        clauses.append("we.created_at <= :dt")
        params["dt"] = date_to

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT we.id, we.greenhouse_id, we.user_id, we.plant_instance_id, 
               we.type, we.created_at, we.comment
        FROM watering_events we
        {where}
        ORDER BY we.created_at DESC
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return [WaterEventOut(**r) for r in rows]

@app.get("/reports", response_model=List[ReportOut])
def get_reports(
    greenhouse_id: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Получение отчетов о поливах и удобрениях. Вывод по юзеру или по теплице."""
    clauses = []
    params = {}
    
    # Для рабочих ограничиваем доступ только их теплицами
    if current_user["role"] == "worker":
        clauses.append("""
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = we.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """)
        params["current_user_id"] = current_user["id"]
    
    if greenhouse_id:
        clauses.append("we.greenhouse_id = :gh")
        params["gh"] = greenhouse_id
    if user_id:
        clauses.append("we.user_id = :uid")
        params["uid"] = user_id
    if date_from:
        clauses.append("we.created_at >= :df")
        params["df"] = date_from
    if date_to:
        clauses.append("we.created_at <= :dt")
        params["dt"] = date_to

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT 
            we.id as event_id,
            we.user_id,
            u.email as user_email,
            u.name as user_name,
            we.greenhouse_id,
            g.name as greenhouse_name,
            we.type as event_type,
            we.plant_instance_id,
            we.created_at,
            we.comment
        FROM watering_events we
        LEFT JOIN users u ON we.user_id = u.id
        LEFT JOIN greenhouses g ON we.greenhouse_id = g.id
        {where}
        ORDER BY we.created_at DESC
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return [ReportOut(**r) for r in rows]

@app.post("/watering-events", response_model=WaterEventOut, status_code=201)
def create_watering_event(payload: WaterEventCreate, current_user: dict = Depends(get_current_user)):
    ev_id = new_id()
    with engine.begin() as conn:
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"),
                          {"id": payload.greenhouse_id}).scalar()
        if not gh:
            raise HTTPException(404, "Greenhouse not found")
        
        # Для рабочих проверяем доступ к теплице
        if current_user["role"] == "worker":
            has_access = conn.execute(text("""
                SELECT 1 FROM user_greenhouses
                WHERE user_id=:user_id AND greenhouse_id=:gh_id
            """), {"user_id": current_user["id"], "gh_id": payload.greenhouse_id}).scalar()
            if not has_access:
                raise HTTPException(403, "Access denied to this greenhouse")
        
        # Используем текущего пользователя, если user_id не указан
        user_id = payload.user_id or current_user["id"]

        conn.execute(text("""
            INSERT INTO watering_events
              (id, greenhouse_id, user_id, plant_instance_id, type, comment)
            VALUES
              (:id, :gh, :uid, :pid, :type, :comment)
        """), {
            "id": ev_id,
            "gh": payload.greenhouse_id,
            "uid": user_id,
            "pid": payload.plant_instance_id,
            "type": payload.type,
            "comment": payload.comment
        })

        row = conn.execute(text("""
            SELECT id, greenhouse_id, user_id, plant_instance_id, type, created_at, comment
            FROM watering_events WHERE id=:id
        """), {"id": ev_id}).mappings().first()
    
    logger.info(f"Событие {payload.type} создано для теплицы {payload.greenhouse_id}")
    return WaterEventOut(**row)

# --- BLE Sensor Data ---
@app.post("/sensors/data", status_code=204)
def receive_sensor_data(payload: SensorDataIn):
    """
    Приём данных от BLE-датчика (температура, влажность).
    Проверяет значения относительно норм, сохраняет предупреждения в alerts и отправляет push-уведомление.
    Доступ: сервисный вызов (без роли, используется системой).
    """
    with engine.begin() as conn:
        # Находим датчик и теплицу
        sensor = conn.execute(text("""
            SELECT s.id, s.ble_identifier, g.id as greenhouse_id, g.name as greenhouse_name,
                   g.target_temp_min, g.target_temp_max,
                   g.target_hum_min, g.target_hum_max
            FROM sensors s
            LEFT JOIN greenhouses g ON s.id = g.sensor_id
            WHERE s.ble_identifier = :ble_id
        """), {"ble_id": payload.ble_identifier}).mappings().first()
        
        if not sensor:
            raise HTTPException(404, "Sensor not found")
        
        # Обновляем данные датчика
        conn.execute(text("""
            UPDATE sensors
            SET last_temperature = :temp,
                last_humidity = :hum,
                last_update = CURRENT_TIMESTAMP
            WHERE id = :sensor_id
        """), {
            "sensor_id": sensor["id"],
            "temp": payload.temperature,
            "hum": payload.humidity
        })
        
        # Если датчик привязан к теплице, проверяем нормы
        if sensor["greenhouse_id"]:
            alerts_created = []
            
            # Проверка температуры
            if sensor["target_temp_min"] is not None and payload.temperature < sensor["target_temp_min"]:
                alert_id = new_id()
                message = f"Температура ниже нормы: {payload.temperature}°C (минимум: {sensor['target_temp_min']}°C)"
                severity = "critical" if payload.temperature < sensor["target_temp_min"] - 5 else "warning"
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'temperature', :msg, :sev)
                """), {
                    "id": alert_id,
                    "gh_id": sensor["greenhouse_id"],
                    "msg": message,
                    "sev": severity
                })
                alerts_created.append((sensor["greenhouse_id"], message))
            
            elif sensor["target_temp_max"] is not None and payload.temperature > sensor["target_temp_max"]:
                alert_id = new_id()
                message = f"Температура выше нормы: {payload.temperature}°C (максимум: {sensor['target_temp_max']}°C)"
                severity = "critical" if payload.temperature > sensor["target_temp_max"] + 5 else "warning"
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'temperature', :msg, :sev)
                """), {
                    "id": alert_id,
                    "gh_id": sensor["greenhouse_id"],
                    "msg": message,
                    "sev": severity
                })
                alerts_created.append((sensor["greenhouse_id"], message))
            
            # Проверка влажности
            if sensor["target_hum_min"] is not None and payload.humidity < sensor["target_hum_min"]:
                alert_id = new_id()
                message = f"Влажность ниже нормы: {payload.humidity}% (минимум: {sensor['target_hum_min']}%)"
                severity = "critical" if payload.humidity < sensor["target_hum_min"] - 10 else "warning"
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'humidity', :msg, :sev)
                """), {
                    "id": alert_id,
                    "gh_id": sensor["greenhouse_id"],
                    "msg": message,
                    "sev": severity
                })
                alerts_created.append((sensor["greenhouse_id"], message))
            
            elif sensor["target_hum_max"] is not None and payload.humidity > sensor["target_hum_max"]:
                alert_id = new_id()
                message = f"Влажность выше нормы: {payload.humidity}% (максимум: {sensor['target_hum_max']}%)"
                severity = "critical" if payload.humidity > sensor["target_hum_max"] + 10 else "warning"
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'humidity', :msg, :sev)
                """), {
                    "id": alert_id,
                    "gh_id": sensor["greenhouse_id"],
                    "msg": message,
                    "sev": severity
                })
                alerts_created.append((sensor["greenhouse_id"], message))
            
            # Отправляем push-уведомления рабочим, привязанным к теплице
            if alerts_created:
                workers = conn.execute(text("""
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """), {"gh_id": sensor["greenhouse_id"]}).mappings().all()
                
                for alert_gh_id, alert_msg in alerts_created:
                    for worker in workers:
                        send_push_notification(
                            worker["user_id"],
                            alert_msg,
                            f"Предупреждение: {sensor['greenhouse_name']}"
                        )
    
    logger.info(f"Данные от датчика {payload.ble_identifier}: temp={payload.temperature}, hum={payload.humidity}")

# --- Alerts ---
@app.get("/alerts", response_model=List[AlertOut])
def list_alerts(
    greenhouse_id: Optional[str] = None,
    is_read: Optional[bool] = None,
    current_user: dict = Depends(get_current_user)
):
    """Получение списка предупреждений."""
    clauses = []
    params = {}
    
    # Для рабочих показываем только предупреждения их теплиц
    if current_user["role"] == "worker":
        clauses.append("""
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = a.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """)
        params["current_user_id"] = current_user["id"]
    
    if greenhouse_id:
        clauses.append("a.greenhouse_id = :gh_id")
        params["gh_id"] = greenhouse_id
    if is_read is not None:
        clauses.append("a.is_read = :is_read")
        params["is_read"] = 1 if is_read else 0
    
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, greenhouse_id, user_id, type, message, severity, is_read, created_at
        FROM alerts a
        {where}
        ORDER BY created_at DESC
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return [AlertOut(**{**r, "is_read": bool(r["is_read"])}) for r in rows]

# --- Watering Check (Background Task) ---
def check_watering_schedules():
    """
    Проверка теплиц, где подошло время полива.
    Если срок истёк — создаётся запись в alerts и отправляется push-уведомление.
    """
    with engine.begin() as conn:
        # Находим растения, которым нужен полив
        overdue_plants = conn.execute(text("""
            SELECT 
                pi.id as plant_instance_id,
                pi.greenhouse_id,
                g.name as greenhouse_name,
                pt.name as plant_name,
                pt.watering_interval_days,
                MAX(we.created_at) as last_watering
            FROM plant_instances pi
            INNER JOIN greenhouses g ON pi.greenhouse_id = g.id
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            LEFT JOIN watering_events we ON we.plant_instance_id = pi.id 
                AND we.type = 'watering'
            WHERE pt.watering_interval_days IS NOT NULL
            GROUP BY pi.id, pi.greenhouse_id, g.name, pt.name, pt.watering_interval_days
            HAVING 
                last_watering IS NULL 
                OR datetime(last_watering, '+' || pt.watering_interval_days || ' days') < datetime('now')
        """)).mappings().all()
        
        for plant in overdue_plants:
            # Проверяем, не создавали ли мы уже предупреждение сегодня
            today_alerts = conn.execute(text("""
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'watering_overdue'
                AND date(created_at) = date('now')
            """), {"gh_id": plant["greenhouse_id"]}).scalar()
            
            if not today_alerts:
                alert_id = new_id()
                days_overdue = 0
                if plant["last_watering"]:
                    try:
                        if isinstance(plant["last_watering"], str):
                            last_date = datetime.fromisoformat(plant["last_watering"].replace("Z", "+00:00"))
                        else:
                            last_date = plant["last_watering"]
                        if isinstance(last_date, datetime):
                            days_passed = (datetime.now() - last_date.replace(tzinfo=None)).days
                            days_overdue = max(0, days_passed - plant["watering_interval_days"])
                    except Exception:
                        days_overdue = 0
                
                message = f"Требуется полив: {plant['plant_name']}"
                if days_overdue > 0:
                    message += f" (просрочено на {days_overdue} дней)"
                
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'watering_overdue', :msg, 'warning')
                """), {
                    "id": alert_id,
                    "gh_id": plant["greenhouse_id"],
                    "msg": message
                })
                
                # Отправляем уведомления рабочим
                workers = conn.execute(text("""
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """), {"gh_id": plant["greenhouse_id"]}).mappings().all()
                
                for worker in workers:
                    send_push_notification(
                        worker["user_id"],
                        message,
                        f"Требуется полив: {plant['greenhouse_name']}"
                    )
        
        # Аналогично для удобрений
        overdue_fertilizing = conn.execute(text("""
            SELECT 
                pi.id as plant_instance_id,
                pi.greenhouse_id,
                g.name as greenhouse_name,
                pt.name as plant_name,
                pt.fertilizing_interval_days,
                MAX(we.created_at) as last_fertilizing
            FROM plant_instances pi
            INNER JOIN greenhouses g ON pi.greenhouse_id = g.id
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            LEFT JOIN watering_events we ON we.plant_instance_id = pi.id 
                AND we.type = 'fertilizing'
            WHERE pt.fertilizing_interval_days IS NOT NULL
            GROUP BY pi.id, pi.greenhouse_id, g.name, pt.name, pt.fertilizing_interval_days
            HAVING 
                last_fertilizing IS NULL 
                OR datetime(last_fertilizing, '+' || pt.fertilizing_interval_days || ' days') < datetime('now')
        """)).mappings().all()
        
        for plant in overdue_fertilizing:
            today_alerts = conn.execute(text("""
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'fertilizing_overdue'
                AND date(created_at) = date('now')
            """), {"gh_id": plant["greenhouse_id"]}).scalar()
            
            if not today_alerts:
                alert_id = new_id()
                days_overdue = 0
                if plant["last_fertilizing"]:
                    try:
                        if isinstance(plant["last_fertilizing"], str):
                            last_date = datetime.fromisoformat(plant["last_fertilizing"].replace("Z", "+00:00"))
                        else:
                            last_date = plant["last_fertilizing"]
                        if isinstance(last_date, datetime):
                            days_passed = (datetime.now() - last_date.replace(tzinfo=None)).days
                            days_overdue = max(0, days_passed - plant["fertilizing_interval_days"])
                    except Exception:
                        days_overdue = 0
                
                message = f"Требуется удобрение: {plant['plant_name']}"
                if days_overdue > 0:
                    message += f" (просрочено на {days_overdue} дней)"
                
                conn.execute(text("""
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'fertilizing_overdue', :msg, 'warning')
                """), {
                    "id": alert_id,
                    "gh_id": plant["greenhouse_id"],
                    "msg": message
                })
                
                workers = conn.execute(text("""
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """), {"gh_id": plant["greenhouse_id"]}).mappings().all()
                
                for worker in workers:
                    send_push_notification(
                        worker["user_id"],
                        message,
                        f"Требуется удобрение: {plant['greenhouse_name']}"
                    )

@app.post("/check-watering", status_code=200)
def trigger_watering_check(admin: dict = Depends(require_admin)):
    """Ручной запуск проверки времени полива. Доступ: admin."""
    check_watering_schedules()
    return {"message": "Watering check completed"}


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    logger.info("Запуск FastAPI сервера на %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)