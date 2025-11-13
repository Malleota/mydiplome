from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text

from .config import JWT_ACCESS_TOKEN_EXPIRE_MINUTES, engine, logger
from .dependencies import (
    create_access_token,
    get_current_user,
    get_password_hash,
    new_id,
    one_or_404,
    require_admin,
    send_push_notification,
    verify_password,
)
from .schemas import (
    AlertOut,
    BindSensorIn,
    BindWorkerIn,
    GreenhouseCreate,
    GreenhouseOut,
    PlantInstanceCreate,
    PlantInstanceOut,
    PlantTypeCreate,
    PlantTypeOut,
    ReportOut,
    SensorDataIn,
    Token,
    UserOut,
    UserRegister,
    UserRoleUpdate,
    WaterEventCreate,
    WaterEventOut,
)

router = APIRouter()


@router.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True}


# --- Auth ---
@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister):
    """Регистрация нового пользователя."""
    user_id = new_id()

    with engine.begin() as conn:
        existing = conn.execute(
            text("SELECT id FROM users WHERE email=:email"),
            {"email": payload.email},
        ).scalar()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким email уже существует",
            )

        password_hash = get_password_hash(payload.password)

        conn.execute(
            text(
                """
            INSERT INTO users (id, email, password_hash, name, role, is_active)
            VALUES (:id, :email, :pwd, :name, :role, 1)
        """
            ),
            {
                "id": user_id,
                "email": payload.email,
                "pwd": password_hash,
                "name": payload.name,
                "role": payload.role,
            },
        )

        row = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": user_id},
            )
            .mappings()
            .first()
        )

    logger.info("Зарегистрирован новый пользователь: %s (ID: %s)", payload.email, user_id)
    return UserOut(**row)


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Авторизация пользователя и получение JWT токена."""
    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    """
            SELECT id, email, password_hash, is_active
            FROM users WHERE email=:email
        """
                ),
                {"email": form_data.username},
            )
            .mappings()
            .first()
        )

        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный email или пароль",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not verify_password(form_data.password, row["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный email или пароль",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Пользователь неактивен",
            )

        access_token_expires = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": row["id"]},
            expires_delta=access_token_expires,
        )

    logger.info("Пользователь авторизован: %s (ID: %s)", form_data.username, row["id"])
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserOut)
def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем авторизованном пользователе."""
    return UserOut(**current_user)


# --- Users (Admin only) ---
@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: str, payload: UserRoleUpdate, admin: dict = Depends(require_admin)
):
    """Изменение статуса пользователя (с worker на admin и с admin на worker). Доступ: admin."""
    with engine.begin() as conn:
        user = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": user_id},
            )
            .mappings()
            .first()
        )

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        conn.execute(
            text(
                """
            UPDATE users SET role=:role WHERE id=:id
        """
            ),
            {"id": user_id, "role": payload.role},
        )

        updated_user = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": user_id},
            )
            .mappings()
            .first()
        )

    logger.info(
        "Роль пользователя %s изменена на %s администратором %s",
        user_id,
        payload.role,
        admin["id"],
    )
    return UserOut(**updated_user)


# --- Greenhouses ---
@router.get("/greenhouses", response_model=List[GreenhouseOut])
def list_greenhouses(current_user: dict = Depends(get_current_user)):
    """Получение списка теплиц. Админ видит все, рабочий - только привязанные."""
    with engine.connect() as conn:
        if current_user["role"] == "admin":
            sql = """
                SELECT id, name, description, sensor_id,
                       target_temp_min, target_temp_max,
                       target_hum_min, target_hum_max, created_at
                FROM greenhouses
                ORDER BY created_at ASC
            """
            rows = conn.execute(text(sql)).mappings().all()
        else:
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


@router.post("/greenhouses", response_model=GreenhouseOut, status_code=201)
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
        conn.execute(
            text(sql),
            {
                "id": gh_id,
                "name": payload.name,
                "description": payload.description,
                "tmin": payload.target_temp_min,
                "tmax": payload.target_temp_max,
                "hmin": payload.target_hum_min,
                "hmax": payload.target_hum_max,
            },
        )
        row = (
            conn.execute(
                text(
                    """
            SELECT id, name, description, sensor_id,
                   target_temp_min, target_temp_max,
                   target_hum_min, target_hum_max, created_at
            FROM greenhouses WHERE id=:id
        """
                ),
                {"id": gh_id},
            )
            .mappings()
            .first()
        )
    return GreenhouseOut(**row)


@router.get("/greenhouses/{gh_id}", response_model=GreenhouseOut)
def get_greenhouse(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение информации о теплице."""
    with engine.connect() as conn:
        if current_user["role"] == "worker":
            has_access = conn.execute(
                text(
                    """
                SELECT 1 FROM user_greenhouses
                WHERE user_id=:user_id AND greenhouse_id=:gh_id
            """
                ),
                {"user_id": current_user["id"], "gh_id": gh_id},
            ).scalar()
            if not has_access:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this greenhouse")

        row = (
            conn.execute(
                text(
                    """
            SELECT id, name, description, sensor_id,
                   target_temp_min, target_temp_max,
                   target_hum_min, target_hum_max, created_at
            FROM greenhouses WHERE id=:id
        """
                ),
                {"id": gh_id},
            )
            .mappings()
            .first()
        )
        one_or_404(row, "Greenhouse not found")
        return GreenhouseOut(**row)


@router.delete("/greenhouses/{gh_id}", status_code=204)
def delete_greenhouse(gh_id: str, admin: dict = Depends(require_admin)):
    """Удаление теплицы. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(
            text("DELETE FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).rowcount
        if deleted == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
    logger.info("Теплица %s удалена администратором %s", gh_id, admin["id"])


@router.post("/greenhouses/{gh_id}/sensor", status_code=204)
def bind_sensor(gh_id: str, payload: BindSensorIn, admin: dict = Depends(require_admin)):
    """Привязка датчика BLE к теплице. Доступ: admin."""
    with engine.begin() as conn:
        sensor_id = conn.execute(
            text("SELECT id FROM sensors WHERE ble_identifier=:b"),
            {"b": payload.ble_identifier},
        ).scalar()
        if sensor_id is None:
            sensor_id = new_id()
            conn.execute(
                text("INSERT INTO sensors (id, ble_identifier) VALUES (:id, :b)"),
                {"id": sensor_id, "b": payload.ble_identifier},
            )

        conn.execute(
            text("UPDATE greenhouses SET sensor_id=NULL WHERE sensor_id=:sid"),
            {"sid": sensor_id},
        )
        updated = conn.execute(
            text("UPDATE greenhouses SET sensor_id=:sid WHERE id=:gh"),
            {"sid": sensor_id, "gh": gh_id},
        ).rowcount
        if updated == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
    logger.info("Датчик %s привязан к теплице %s", payload.ble_identifier, gh_id)


@router.delete("/greenhouses/{gh_id}/sensor", status_code=204)
def unbind_sensor(gh_id: str, admin: dict = Depends(require_admin)):
    """Отвязка датчика BLE от теплицы. Доступ: admin."""
    with engine.begin() as conn:
        updated = conn.execute(
            text("UPDATE greenhouses SET sensor_id=NULL WHERE id=:gh"),
            {"gh": gh_id},
        ).rowcount
        if updated == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
    logger.info("Датчик отвязан от теплицы %s", gh_id)


@router.post("/greenhouses/{gh_id}/workers", status_code=204)
def bind_worker(gh_id: str, payload: BindWorkerIn, admin: dict = Depends(require_admin)):
    """Привязка рабочего к теплице. Доступ: admin."""
    with engine.begin() as conn:
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")

        user = conn.execute(
            text("SELECT role FROM users WHERE id=:id"), {"id": payload.user_id}
        ).mappings().first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if user["role"] != "worker":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User must be a worker")

        try:
            conn.execute(
                text(
                    """
                INSERT INTO user_greenhouses (user_id, greenhouse_id)
                VALUES (:user_id, :gh_id)
            """
                ),
                {"user_id": payload.user_id, "gh_id": gh_id},
            )
        except Exception:
            pass
    logger.info("Рабочий %s привязан к теплице %s", payload.user_id, gh_id)


@router.delete("/greenhouses/{gh_id}/workers/{user_id}", status_code=204)
def unbind_worker(gh_id: str, user_id: str, admin: dict = Depends(require_admin)):
    """Отвязка рабочего от теплицы. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(
            text(
                """
            DELETE FROM user_greenhouses
            WHERE user_id=:user_id AND greenhouse_id=:gh_id
        """
            ),
            {"user_id": user_id, "gh_id": gh_id},
        ).rowcount
        if deleted == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")
    logger.info("Рабочий %s отвязан от теплицы %s", user_id, gh_id)


# --- Plant types ---
@router.get("/plant-types", response_model=List[PlantTypeOut])
def list_plant_types(current_user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
            SELECT id, name, description, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types ORDER BY name ASC
        """
            )
        ).mappings().all()
        return [PlantTypeOut(**r) for r in rows]


@router.post("/plant-types", response_model=PlantTypeOut, status_code=201)
def create_plant_type(payload: PlantTypeCreate, admin: dict = Depends(require_admin)):
    """Добавление растения в справочник. Доступ: admin."""
    pt_id = new_id()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
            INSERT INTO plant_types
              (id, name, description, temp_min, temp_max,
               humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days)
            VALUES
              (:id, :name, :description, :tmin, :tmax, :hmin, :hmax, :wi, :fi)
        """
            ),
            {
                "id": pt_id,
                "name": payload.name,
                "description": payload.description,
                "tmin": payload.temp_min,
                "tmax": payload.temp_max,
                "hmin": payload.humidity_min,
                "hmax": payload.humidity_max,
                "wi": payload.watering_interval_days,
                "fi": payload.fertilizing_interval_days,
            },
        )
        row = (
            conn.execute(
                text(
                    """
            SELECT id, name, description, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types WHERE id=:id
        """
                ),
                {"id": pt_id},
            )
            .mappings()
            .first()
        )
    logger.info("Тип растения %s добавлен в справочник", payload.name)
    return PlantTypeOut(**row)


@router.delete("/plant-types/{pt_id}", status_code=204)
def delete_plant_type(pt_id: str, admin: dict = Depends(require_admin)):
    """Удаление растения из справочника. Доступ: admin."""
    with engine.begin() as conn:
        deleted = conn.execute(
            text("DELETE FROM plant_types WHERE id=:id"), {"id": pt_id}
        ).rowcount
        if deleted == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plant type not found")
    logger.info("Тип растения %s удален из справочника", pt_id)


# --- Plant instances in greenhouse ---
@router.post("/greenhouses/{gh_id}/plants", response_model=PlantInstanceOut, status_code=201)
def add_plant_instance(gh_id: str, payload: PlantInstanceCreate, admin: dict = Depends(require_admin)):
    """Добавление растения в теплицу. Доступ: admin."""
    pi_id = new_id()
    with engine.begin() as conn:
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}).scalar()
        if not gh:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
        pt = conn.execute(
            text("SELECT 1 FROM plant_types WHERE id=:id"), {"id": payload.plant_type_id}
        ).scalar()
        if not pt:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plant type not found")

        conn.execute(
            text(
                """
            INSERT INTO plant_instances (id, greenhouse_id, plant_type_id, quantity, note)
            VALUES (:id, :gh, :pt, :q, :note)
        """
            ),
            {
                "id": pi_id,
                "gh": gh_id,
                "pt": payload.plant_type_id,
                "q": payload.quantity,
                "note": payload.note,
            },
        )

        row = (
            conn.execute(
                text(
                    """
            SELECT id, greenhouse_id, plant_type_id, quantity, note
            FROM plant_instances WHERE id=:id
        """
                ),
                {"id": pi_id},
            )
            .mappings()
            .first()
        )
    logger.info("Растение добавлено в теплицу %s", gh_id)
    return PlantInstanceOut(**row)


@router.delete("/greenhouses/{gh_id}/plants/{pi_id}", status_code=204)
def delete_plant_instance(gh_id: str, pi_id: str, admin: dict = Depends(require_admin)):
    """Удаление растения из теплицы. Доступ: admin."""
    with engine.begin() as conn:
        pi = conn.execute(
            text(
                """
            SELECT id FROM plant_instances
            WHERE id=:pi_id AND greenhouse_id=:gh_id
        """
            ),
            {"pi_id": pi_id, "gh_id": gh_id},
        ).scalar()
        if not pi:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Plant instance not found in this greenhouse",
            )

        conn.execute(text("DELETE FROM plant_instances WHERE id=:id"), {"id": pi_id})
    logger.info("Растение %s удалено из теплицы %s", pi_id, gh_id)


# --- Watering events ---
@router.get("/watering-events", response_model=List[WaterEventOut])
def list_watering_events(
    greenhouse_id: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Получение списка событий полива/удобрения с фильтрацией."""
    clauses: List[str] = []
    params = {}

    if current_user["role"] == "worker":
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = we.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """
        )
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


@router.get("/reports", response_model=List[ReportOut])
def get_reports(
    greenhouse_id: Optional[str] = None,
    user_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Получение отчетов о поливах и удобрениях. Вывод по юзеру или по теплице."""
    clauses: List[str] = []
    params = {}

    if current_user["role"] == "worker":
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = we.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """
        )
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


@router.post("/watering-events", response_model=WaterEventOut, status_code=201)
def create_watering_event(payload: WaterEventCreate, current_user: dict = Depends(get_current_user)):
    ev_id = new_id()
    with engine.begin() as conn:
        gh = conn.execute(text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": payload.greenhouse_id}).scalar()
        if not gh:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")

        if current_user["role"] == "worker":
            has_access = conn.execute(
                text(
                    """
                SELECT 1 FROM user_greenhouses
                WHERE user_id=:user_id AND greenhouse_id=:gh_id
            """
                ),
                {"user_id": current_user["id"], "gh_id": payload.greenhouse_id},
            ).scalar()
            if not has_access:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this greenhouse")

        user_id = payload.user_id or current_user["id"]

        conn.execute(
            text(
                """
            INSERT INTO watering_events
              (id, greenhouse_id, user_id, plant_instance_id, type, comment)
            VALUES
              (:id, :gh, :uid, :pid, :type, :comment)
        """
            ),
            {
                "id": ev_id,
                "gh": payload.greenhouse_id,
                "uid": user_id,
                "pid": payload.plant_instance_id,
                "type": payload.type,
                "comment": payload.comment,
            },
        )

        row = (
            conn.execute(
                text(
                    """
            SELECT id, greenhouse_id, user_id, plant_instance_id, type, created_at, comment
            FROM watering_events WHERE id=:id
        """
                ),
                {"id": ev_id},
            )
            .mappings()
            .first()
        )

    logger.info("Событие %s создано для теплицы %s", payload.type, payload.greenhouse_id)
    return WaterEventOut(**row)


# --- BLE Sensor Data ---
@router.post("/sensors/data", status_code=204)
def receive_sensor_data(payload: SensorDataIn):
    """
    Приём данных от BLE-датчика (температура, влажность).
    Проверяет значения относительно норм, сохраняет предупреждения в alerts и отправляет push-уведомление.
    Доступ: сервисный вызов (без роли, используется системой).
    """
    with engine.begin() as conn:
        sensor = (
            conn.execute(
                text(
                    """
            SELECT s.id, s.ble_identifier, g.id as greenhouse_id, g.name as greenhouse_name,
                   g.target_temp_min, g.target_temp_max,
                   g.target_hum_min, g.target_hum_max
            FROM sensors s
            LEFT JOIN greenhouses g ON s.id = g.sensor_id
            WHERE s.ble_identifier = :ble_id
        """
                ),
                {"ble_id": payload.ble_identifier},
            )
            .mappings()
            .first()
        )

        if not sensor:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor not found")

        conn.execute(
            text(
                """
            UPDATE sensors
            SET last_temperature = :temp,
                last_humidity = :hum,
                last_update = CURRENT_TIMESTAMP
            WHERE id = :sensor_id
        """
            ),
            {
                "sensor_id": sensor["id"],
                "temp": payload.temperature,
                "hum": payload.humidity,
            },
        )

        if sensor["greenhouse_id"]:
            alerts_created = []

            if sensor["target_temp_min"] is not None and payload.temperature < sensor["target_temp_min"]:
                alert_id = new_id()
                message = (
                    f"Температура ниже нормы: {payload.temperature}°C (минимум: {sensor['target_temp_min']}°C)"
                )
                severity = "critical" if payload.temperature < sensor["target_temp_min"] - 5 else "warning"
                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'temperature', :msg, :sev)
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": sensor["greenhouse_id"],
                        "msg": message,
                        "sev": severity,
                    },
                )
                alerts_created.append((sensor["greenhouse_id"], message))

            elif sensor["target_temp_max"] is not None and payload.temperature > sensor["target_temp_max"]:
                alert_id = new_id()
                message = (
                    f"Температура выше нормы: {payload.temperature}°C (максимум: {sensor['target_temp_max']}°C)"
                )
                severity = "critical" if payload.temperature > sensor["target_temp_max"] + 5 else "warning"
                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'temperature', :msg, :sev)
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": sensor["greenhouse_id"],
                        "msg": message,
                        "sev": severity,
                    },
                )
                alerts_created.append((sensor["greenhouse_id"], message))

            if sensor["target_hum_min"] is not None and payload.humidity < sensor["target_hum_min"]:
                alert_id = new_id()
                message = (
                    f"Влажность ниже нормы: {payload.humidity}% (минимум: {sensor['target_hum_min']}%)"
                )
                severity = "critical" if payload.humidity < sensor["target_hum_min"] - 10 else "warning"
                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'humidity', :msg, :sev)
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": sensor["greenhouse_id"],
                        "msg": message,
                        "sev": severity,
                    },
                )
                alerts_created.append((sensor["greenhouse_id"], message))

            elif sensor["target_hum_max"] is not None and payload.humidity > sensor["target_hum_max"]:
                alert_id = new_id()
                message = (
                    f"Влажность выше нормы: {payload.humidity}% (максимум: {sensor['target_hum_max']}%)"
                )
                severity = "critical" if payload.humidity > sensor["target_hum_max"] + 10 else "warning"
                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'humidity', :msg, :sev)
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": sensor["greenhouse_id"],
                        "msg": message,
                        "sev": severity,
                    },
                )
                alerts_created.append((sensor["greenhouse_id"], message))

            if alerts_created:
                workers = conn.execute(
                    text(
                        """
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """
                    ),
                    {"gh_id": sensor["greenhouse_id"]},
                ).mappings().all()

                for _, alert_msg in alerts_created:
                    for worker in workers:
                        send_push_notification(
                            worker["user_id"],
                            alert_msg,
                            f"Предупреждение: {sensor['greenhouse_name']}",
                        )

    logger.info(
        "Данные от датчика %s: temp=%s, hum=%s",
        payload.ble_identifier,
        payload.temperature,
        payload.humidity,
    )


# --- Alerts ---
@router.get("/alerts", response_model=List[AlertOut])
def list_alerts(
    greenhouse_id: Optional[str] = None,
    is_read: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
):
    """Получение списка предупреждений."""
    clauses: List[str] = []
    params = {}

    if current_user["role"] == "worker":
        clauses.append(
            """
            EXISTS (
                SELECT 1 FROM user_greenhouses ug
                WHERE ug.greenhouse_id = a.greenhouse_id
                AND ug.user_id = :current_user_id
            )
        """
        )
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
        overdue_plants = conn.execute(
            text(
                """
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
        """
            )
        ).mappings().all()

        for plant in overdue_plants:
            today_alerts = conn.execute(
                text(
                    """
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'watering_overdue'
                AND date(created_at) = date('now')
            """
                ),
                {"gh_id": plant["greenhouse_id"]},
            ).scalar()

            if not today_alerts:
                alert_id = new_id()
                days_overdue = 0
                if plant["last_watering"]:
                    try:
                        last_date = plant["last_watering"]
                        if isinstance(last_date, str):
                            last_date = datetime.fromisoformat(last_date.replace("Z", "+00:00"))
                        if isinstance(last_date, datetime):
                            days_passed = (datetime.now() - last_date.replace(tzinfo=None)).days
                            days_overdue = max(0, days_passed - plant["watering_interval_days"])
                    except Exception:
                        days_overdue = 0

                message = f"Требуется полив: {plant['plant_name']}"
                if days_overdue > 0:
                    message += f" (просрочено на {days_overdue} дней)"

                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'watering_overdue', :msg, 'warning')
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": plant["greenhouse_id"],
                        "msg": message,
                    },
                )

                workers = conn.execute(
                    text(
                        """
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """
                    ),
                    {"gh_id": plant["greenhouse_id"]},
                ).mappings().all()

                for worker in workers:
                    send_push_notification(
                        worker["user_id"],
                        message,
                        f"Требуется полив: {plant['greenhouse_name']}",
                    )

        overdue_fertilizing = conn.execute(
            text(
                """
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
        """
            )
        ).mappings().all()

        for plant in overdue_fertilizing:
            today_alerts = conn.execute(
                text(
                    """
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'fertilizing_overdue'
                AND date(created_at) = date('now')
            """
                ),
                {"gh_id": plant["greenhouse_id"]},
            ).scalar()

            if not today_alerts:
                alert_id = new_id()
                days_overdue = 0
                if plant["last_fertilizing"]:
                    try:
                        last_date = plant["last_fertilizing"]
                        if isinstance(last_date, str):
                            last_date = datetime.fromisoformat(last_date.replace("Z", "+00:00"))
                        if isinstance(last_date, datetime):
                            days_passed = (datetime.now() - last_date.replace(tzinfo=None)).days
                            days_overdue = max(0, days_passed - plant["fertilizing_interval_days"])
                    except Exception:
                        days_overdue = 0

                message = f"Требуется удобрение: {plant['plant_name']}"
                if days_overdue > 0:
                    message += f" (просрочено на {days_overdue} дней)"

                conn.execute(
                    text(
                        """
                    INSERT INTO alerts (id, greenhouse_id, type, message, severity)
                    VALUES (:id, :gh_id, 'fertilizing_overdue', :msg, 'warning')
                """
                    ),
                    {
                        "id": alert_id,
                        "gh_id": plant["greenhouse_id"],
                        "msg": message,
                    },
                )

                workers = conn.execute(
                    text(
                        """
                    SELECT DISTINCT user_id FROM user_greenhouses
                    WHERE greenhouse_id = :gh_id
                """
                    ),
                    {"gh_id": plant["greenhouse_id"]},
                ).mappings().all()

                for worker in workers:
                    send_push_notification(
                        worker["user_id"],
                        message,
                        f"Требуется удобрение: {plant['greenhouse_name']}",
                    )


@router.post("/check-watering", status_code=200)
def trigger_watering_check(admin: dict = Depends(require_admin)):
    """Ручной запуск проверки времени полива. Доступ: admin."""
    check_watering_schedules()
    return {"message": "Watering check completed"}

