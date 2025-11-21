        # Используем локальные пути на сервере

import os
import random
import shutil
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import text

from .config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    PLANT_TYPES_DIR,
    engine,
    get_full_static_url,
    logger,
)
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
    AvatarOut,
    AvatarUpdate,
    BindSensorIn,
    BindWorkerIn,
    GreenhouseCreate,
    GreenhouseImageOut,
    GreenhouseOut,
    NextWateringOut,
    PlantInstanceCreate,
    PlantInstanceOut,
    PlantTypeCreate,
    PlantTypeOut,
    ReportOut,
    SensorDataIn,
    SensorReadingOut,
    Token,
    UserOut,
    UserRegister,
    UserRoleUpdate,
    WaterEventCreate,
    WaterEventOut,
)

router = APIRouter()


def enrich_user_with_avatar_url(user_data: dict, conn) -> dict:
    """Добавляет avatar_url в данные пользователя на основе avatar_id."""
    user_dict = dict(user_data)
    if user_dict.get("avatar_id"):
        avatar = conn.execute(
            text("SELECT image_url FROM avatars WHERE id=:id"),
            {"id": user_dict["avatar_id"]},
        ).mappings().first()
        if avatar and avatar["image_url"]:
            user_dict["avatar_url"] = get_full_static_url(avatar["image_url"])
        else:
            user_dict["avatar_url"] = None
    else:
        user_dict["avatar_url"] = None
    return user_dict


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

        # Получаем случайную аватарку
        avatars = conn.execute(
            text("SELECT id FROM avatars")
        ).fetchall()
        
        if not avatars:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Нет доступных аватарок",
            )
        
        random_avatar = random.choice(avatars)
        avatar_id = random_avatar[0]

        password_hash = get_password_hash(payload.password)

        conn.execute(
            text(
                """
            INSERT INTO users (id, email, password_hash, name, role, avatar_id, is_active)
            VALUES (:id, :email, :pwd, :name, :role, :avatar_id, 1)
        """
            ),
            {
                "id": user_id,
                "email": payload.email,
                "pwd": password_hash,
                "name": payload.name,
                "role": payload.role,
                "avatar_id": avatar_id,
            },
        )

        row = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, avatar_id, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": user_id},
            )
            .mappings()
            .first()
        )
        
        # Добавляем avatar_url
        user_data = enrich_user_with_avatar_url(row, conn)

    logger.info("Зарегистрирован новый пользователь: %s (ID: %s)", payload.email, user_id)
    return UserOut(**user_data)


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
    with engine.connect() as conn:
        user_data = enrich_user_with_avatar_url(current_user, conn)
    return UserOut(**user_data)


@router.patch("/me/avatar", response_model=UserOut)
def update_avatar(payload: AvatarUpdate, current_user: dict = Depends(get_current_user)):
    """Смена аватарки текущего пользователя."""
    with engine.begin() as conn:
        # Проверяем, что аватарка существует
        avatar_exists = conn.execute(
            text("SELECT 1 FROM avatars WHERE id=:id"),
            {"id": payload.avatar_id},
        ).scalar()
        
        if not avatar_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Аватарка не найдена",
            )
        
        # Обновляем аватарку пользователя
        conn.execute(
            text("UPDATE users SET avatar_id=:avatar_id WHERE id=:user_id"),
            {"avatar_id": payload.avatar_id, "user_id": current_user["id"]},
        )
        
        # Получаем обновленного пользователя
        row = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, avatar_id, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": current_user["id"]},
            )
            .mappings()
            .first()
        )
        
        # Добавляем avatar_url
        user_data = enrich_user_with_avatar_url(row, conn)
    
    logger.info("Пользователь %s сменил аватарку на %s", current_user["id"], payload.avatar_id)
    return UserOut(**user_data)


@router.get("/avatars", response_model=List[AvatarOut])
def list_avatars():
    """Получение списка доступных аватарок."""
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, image_url, name FROM avatars ORDER BY name ASC")
        ).mappings().all()
        result = []
        for r in rows:
            avatar_data = dict(r)
            # Формируем полный URL
            avatar_data["image_url"] = get_full_static_url(avatar_data["image_url"])
            result.append(AvatarOut(**avatar_data))
        return result


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
            SELECT id, email, name, role, is_active, avatar_id, created_at
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
            SELECT id, email, name, role, is_active, avatar_id, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": user_id},
            )
            .mappings()
            .first()
        )
        
        # Добавляем avatar_url
        user_data = enrich_user_with_avatar_url(updated_user, conn)

    logger.info(
        "Роль пользователя %s изменена на %s администратором %s",
        user_id,
        payload.role,
        admin["id"],
    )
    return UserOut(**user_data)


# --- Greenhouses ---
@router.get("/greenhouse-images", response_model=List[GreenhouseImageOut])
def list_greenhouse_images():
    """Получение списка доступных изображений для теплиц."""
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, image_url, name FROM greenhouse_images ORDER BY name ASC")
        ).mappings().all()
        return [GreenhouseImageOut(**r) for r in rows]


@router.get("/greenhouses", response_model=List[GreenhouseOut])
def list_greenhouses(current_user: dict = Depends(get_current_user)):
    """Получение списка теплиц. Админ видит все, рабочий - только привязанные."""
    with engine.connect() as conn:
        if current_user["role"] == "admin":
            sql = """
                SELECT id, name, description, image_url, sensor_id,
                       target_temp_min, target_temp_max,
                       target_hum_min, target_hum_max, created_at
                FROM greenhouses
                ORDER BY created_at ASC
            """
            rows = conn.execute(text(sql)).mappings().all()
        else:
            sql = """
                SELECT g.id, g.name, g.description, g.image_url, g.sensor_id,
                       g.target_temp_min, g.target_temp_max,
                       g.target_hum_min, g.target_hum_max, g.created_at
                FROM greenhouses g
                INNER JOIN user_greenhouses ug ON g.id = ug.greenhouse_id
                WHERE ug.user_id = :user_id
                ORDER BY g.created_at ASC
            """
            rows = conn.execute(text(sql), {"user_id": current_user["id"]}).mappings().all()

        result = []
        for r in rows:
            gh_data = dict(r)
            # Формируем полный URL для изображения
            gh_data["image_url"] = get_full_static_url(gh_data["image_url"])
            result.append(GreenhouseOut(**gh_data))
        return result


@router.post("/greenhouses", response_model=GreenhouseOut, status_code=201)
def create_greenhouse(payload: GreenhouseCreate, admin: dict = Depends(require_admin)):
    """Создание теплицы с привязкой растений и рабочих. Доступ: admin."""
    gh_id = new_id()
    
    with engine.begin() as conn:
        # Проверяем, что выбранное изображение существует (если указано)
        if payload.image_url:
            image_exists = conn.execute(
                text("SELECT 1 FROM greenhouse_images WHERE image_url=:url"),
                {"url": payload.image_url},
            ).scalar()
            if not image_exists:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Выбранное изображение не найдено в списке доступных",
                )
        
        # Валидация: если растения не выбраны, температуры не должны быть указаны
        if not payload.plants or len(payload.plants) == 0:
            if payload.target_temp_min is not None or payload.target_temp_max is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Если растения не выбраны, температуры не должны быть указаны",
                )
            target_temp_min = None
            target_temp_max = None
            target_hum_min = None
            target_hum_max = None
        else:
            # Если растения выбраны, вычисляем средние значения температур
            plant_type_ids = [p.plant_type_id for p in payload.plants]
            placeholders = ",".join([f":id{i}" for i in range(len(plant_type_ids))])
            params = {f"id{i}": pid for i, pid in enumerate(plant_type_ids)}
            
            plants_data = conn.execute(
                text(
                    f"""
                    SELECT temp_min, temp_max, humidity_min, humidity_max
                    FROM plant_types
                    WHERE id IN ({placeholders})
                    """
                ),
                params,
            ).mappings().all()
            
            if len(plants_data) != len(plant_type_ids):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Один или несколько типов растений не найдены",
                )
            
            # Вычисляем средние значения
            temp_mins = [p["temp_min"] for p in plants_data if p["temp_min"] is not None]
            temp_maxs = [p["temp_max"] for p in plants_data if p["temp_max"] is not None]
            hum_mins = [p["humidity_min"] for p in plants_data if p["humidity_min"] is not None]
            hum_maxs = [p["humidity_max"] for p in plants_data if p["humidity_max"] is not None]
            
            target_temp_min = sum(temp_mins) / len(temp_mins) if temp_mins else None
            target_temp_max = sum(temp_maxs) / len(temp_maxs) if temp_maxs else None
            target_hum_min = sum(hum_mins) / len(hum_mins) if hum_mins else None
            target_hum_max = sum(hum_maxs) / len(hum_maxs) if hum_maxs else None
        
        # Создаем теплицу
        sql = """
        INSERT INTO greenhouses
          (id, name, description, image_url,
           target_temp_min, target_temp_max,
           target_hum_min, target_hum_max)
        VALUES
          (:id, :name, :description, :img_url,
           :tmin, :tmax, :hmin, :hmax)
        """
        conn.execute(
            text(sql),
            {
                "id": gh_id,
                "name": payload.name,
                "description": payload.description,
                "img_url": payload.image_url,
                "tmin": target_temp_min,
                "tmax": target_temp_max,
                "hmin": target_hum_min,
                "hmax": target_hum_max,
            },
        )
        
        # Привязываем растения, если они указаны
        if payload.plants:
            for plant in payload.plants:
                # Проверяем, что тип растения существует и получаем интервалы
                pt_data = conn.execute(
                    text("SELECT watering_interval_days, fertilizing_interval_days FROM plant_types WHERE id=:id"),
                    {"id": plant.plant_type_id},
                ).mappings().first()
                if not pt_data:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Тип растения {plant.plant_type_id} не найден",
                    )
                
                pi_id = new_id()
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
                        "pt": plant.plant_type_id,
                        "q": plant.quantity,
                        "note": plant.note,
                    },
                )
                
                # Если у растения есть интервал полива, создаем событие полива на сегодня
                if pt_data["watering_interval_days"] is not None:
                    watering_event_id = new_id()
                    conn.execute(
                        text(
                            """
                            INSERT INTO watering_events
                              (id, greenhouse_id, user_id, plant_instance_id, type, comment)
                            VALUES
                              (:id, :gh, :uid, :pid, 'watering', :comment)
                        """
                        ),
                        {
                            "id": watering_event_id,
                            "gh": gh_id,
                            "uid": admin["id"],
                            "pid": pi_id,
                            "comment": "Автоматически при создании теплицы",
                        },
                    )
                
                # Если у растения есть интервал удобрения, создаем событие удобрения на сегодня
                if pt_data["fertilizing_interval_days"] is not None:
                    fertilizing_event_id = new_id()
                    conn.execute(
                        text(
                            """
                            INSERT INTO watering_events
                              (id, greenhouse_id, user_id, plant_instance_id, type, comment)
                            VALUES
                              (:id, :gh, :uid, :pid, 'fertilizing', :comment)
                        """
                        ),
                        {
                            "id": fertilizing_event_id,
                            "gh": gh_id,
                            "uid": admin["id"],
                            "pid": pi_id,
                            "comment": "Автоматически при создании теплицы",
                        },
                    )
        
        # Привязываем рабочих, если они указаны
        if payload.worker_ids:
            for worker_id in payload.worker_ids:
                # Проверяем, что пользователь существует и является рабочим
                user = conn.execute(
                    text("SELECT role FROM users WHERE id=:id"),
                    {"id": worker_id},
                ).mappings().first()
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Пользователь {worker_id} не найден",
                    )
                if user["role"] != "worker":
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Пользователь {worker_id} должен быть рабочим",
                    )
                
                # Привязываем рабочего (игнорируем ошибку, если уже привязан)
                try:
                    conn.execute(
                        text(
                            """
                            INSERT INTO user_greenhouses (user_id, greenhouse_id)
                            VALUES (:user_id, :gh_id)
                            """
                        ),
                        {"user_id": worker_id, "gh_id": gh_id},
                    )
                except Exception:
                    pass  # Уже привязан
        
        # Привязываем датчик, если он указан
        if payload.sensor_ble_identifier:
            sensor_id = conn.execute(
                text("SELECT id FROM sensors WHERE ble_identifier=:b"),
                {"b": payload.sensor_ble_identifier},
            ).scalar()
            if sensor_id is None:
                # Создаем новый датчик, если его нет
                sensor_id = new_id()
                conn.execute(
                    text("INSERT INTO sensors (id, ble_identifier) VALUES (:id, :b)"),
                    {"id": sensor_id, "b": payload.sensor_ble_identifier},
                )
            else:
                # Проверяем, не привязан ли датчик к другой теплице
                existing_greenhouse = conn.execute(
                    text("SELECT id, name FROM greenhouses WHERE sensor_id=:sid"),
                    {"sid": sensor_id},
                ).mappings().first()
                if existing_greenhouse:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Датчик уже привязан к теплице '{existing_greenhouse['name']}' (ID: {existing_greenhouse['id']})",
                    )
            
            # Привязываем датчик к новой теплице
            conn.execute(
                text("UPDATE greenhouses SET sensor_id=:sid WHERE id=:gh"),
                {"sid": sensor_id, "gh": gh_id},
            )
        
        # Получаем созданную теплицу
        row = (
            conn.execute(
                text(
                    """
            SELECT id, name, description, image_url, sensor_id,
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
        
        # Формируем полный URL для изображения
        gh_data = dict(row)
        gh_data["image_url"] = get_full_static_url(gh_data["image_url"])
    
    logger.info("Теплица %s создана с %d растениями, %d рабочими%s", 
                gh_id, 
                len(payload.plants) if payload.plants else 0,
                len(payload.worker_ids) if payload.worker_ids else 0,
                f" и датчиком {payload.sensor_ble_identifier}" if payload.sensor_ble_identifier else "")
    return GreenhouseOut(**gh_data)


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
            SELECT id, name, description, image_url, sensor_id,
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
        
        # Формируем полный URL для изображения
        gh_data = dict(row)
        gh_data["image_url"] = get_full_static_url(gh_data["image_url"])
        
        return GreenhouseOut(**gh_data)


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
        # Проверяем существование теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
        
        sensor_id = conn.execute(
            text("SELECT id FROM sensors WHERE ble_identifier=:b"),
            {"b": payload.ble_identifier},
        ).scalar()
        if sensor_id is None:
            # Создаем новый датчик, если его нет
            sensor_id = new_id()
            conn.execute(
                text("INSERT INTO sensors (id, ble_identifier) VALUES (:id, :b)"),
                {"id": sensor_id, "b": payload.ble_identifier},
            )
        else:
            # Проверяем, не привязан ли датчик к другой теплице
            existing_greenhouse = conn.execute(
                text("SELECT id, name FROM greenhouses WHERE sensor_id=:sid AND id != :gh_id"),
                {"sid": sensor_id, "gh_id": gh_id},
            ).mappings().first()
            if existing_greenhouse:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Датчик уже привязан к теплице '{existing_greenhouse['name']}' (ID: {existing_greenhouse['id']})",
                )
        
        # Привязываем датчик к теплице
        conn.execute(
            text("UPDATE greenhouses SET sensor_id=:sid WHERE id=:gh"),
            {"sid": sensor_id, "gh": gh_id},
        )
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
            SELECT id, name, description, image_url, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types ORDER BY name ASC
        """
            )
        ).mappings().all()
        result = []
        for r in rows:
            plant_data = dict(r)
            # Формируем полный URL для изображения
            plant_data["image_url"] = get_full_static_url(plant_data["image_url"])
            result.append(PlantTypeOut(**plant_data))
        return result


@router.post("/plant-types/upload-image", status_code=200)
async def upload_plant_image(
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin),
):
    """Загрузка изображения для растения. Доступ: admin."""
    # Проверяем расширение файла
    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp"}
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Недопустимый формат файла. Разрешены: {', '.join(allowed_extensions)}",
        )
    
    # Генерируем уникальное имя файла
    file_id = new_id()
    filename = f"{file_id}{file_ext}"
    file_path = os.path.join(PLANT_TYPES_DIR, filename)
    
    # Сохраняем файл
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        logger.error(f"Ошибка при сохранении файла: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка при сохранении файла",
        )
    
    # Возвращаем полный URL для использования
    relative_url = f"/static/plant-types/{filename}"
    image_url = get_full_static_url(relative_url)
    logger.info("Загружено изображение растения: %s", filename)
    return {"image_url": image_url, "filename": filename}


@router.post("/plant-types", response_model=PlantTypeOut, status_code=201)
def create_plant_type(payload: PlantTypeCreate, admin: dict = Depends(require_admin)):
    """Добавление растения в справочник. Доступ: admin."""
    pt_id = new_id()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
            INSERT INTO plant_types
              (id, name, description, image_url, temp_min, temp_max,
               humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days)
            VALUES
              (:id, :name, :description, :img_url, :tmin, :tmax, :hmin, :hmax, :wi, :fi)
        """
            ),
            {
                "id": pt_id,
                "name": payload.name,
                "description": payload.description,
                "img_url": payload.image_url,
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
            SELECT id, name, description, image_url, temp_min, temp_max,
                   humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days
            FROM plant_types WHERE id=:id
        """
                ),
                {"id": pt_id},
            )
            .mappings()
            .first()
        )
        
        # Формируем полный URL для изображения
        plant_data = dict(row)
        plant_data["image_url"] = get_full_static_url(plant_data["image_url"])
    
    logger.info("Тип растения %s добавлен в справочник", payload.name)
    return PlantTypeOut(**plant_data)


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
        pt_data = conn.execute(
            text("SELECT watering_interval_days, fertilizing_interval_days FROM plant_types WHERE id=:id"), {"id": payload.plant_type_id}
        ).mappings().first()
        if not pt_data:
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
        
        # Если у растения есть интервал полива, создаем событие полива на сегодня
        if pt_data["watering_interval_days"] is not None:
            watering_event_id = new_id()
            conn.execute(
                text(
                    """
                    INSERT INTO watering_events
                      (id, greenhouse_id, user_id, plant_instance_id, type, comment)
                    VALUES
                      (:id, :gh, :uid, :pid, 'watering', :comment)
                """
                ),
                {
                    "id": watering_event_id,
                    "gh": gh_id,
                    "uid": admin["id"],
                    "pid": pi_id,
                    "comment": "Автоматически при добавлении растения",
                },
            )
        
        # Если у растения есть интервал удобрения, создаем событие удобрения на сегодня
        if pt_data["fertilizing_interval_days"] is not None:
            fertilizing_event_id = new_id()
            conn.execute(
                text(
                    """
                    INSERT INTO watering_events
                      (id, greenhouse_id, user_id, plant_instance_id, type, comment)
                    VALUES
                      (:id, :gh, :uid, :pid, 'fertilizing', :comment)
                """
                ),
                {
                    "id": fertilizing_event_id,
                    "gh": gh_id,
                    "uid": admin["id"],
                    "pid": pi_id,
                    "comment": "Автоматически при добавлении растения",
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


@router.get("/greenhouses/{gh_id}/plants", response_model=List[PlantInstanceOut])
def list_plant_instances(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение списка растений в теплице."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found"
            )
        
        rows = conn.execute(
            text(
                """
            SELECT id, greenhouse_id, plant_type_id, quantity, note
            FROM plant_instances
            WHERE greenhouse_id = :gh_id
            ORDER BY id ASC
        """
            ),
            {"gh_id": gh_id},
        ).mappings().all()
        
        return [PlantInstanceOut(**r) for r in rows]


@router.get("/greenhouses/{gh_id}/next-watering", response_model=NextWateringOut)
def get_next_watering_greenhouse(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение ближайшего полива по всей теплице (среди всех поливов теплицы)."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found"
            )
        
        # Находим ближайший следующий полив по всей теплице
        # Сначала находим последний полив по всей теплице (где plant_instance_id IS NULL)
        last_greenhouse_watering = conn.execute(
            text(
                """
            SELECT 
                we.id,
                we.greenhouse_id,
                we.plant_instance_id,
                we.created_at
            FROM watering_events we
            WHERE we.greenhouse_id = :gh_id
                AND we.type = 'watering'
                AND we.plant_instance_id IS NULL
            ORDER BY we.created_at DESC
            LIMIT 1
        """
            ),
            {"gh_id": gh_id},
        ).mappings().first()
        
        # Находим все поливы по растениям с вычислением следующего полива
        plant_waterings = conn.execute(
            text(
                """
            SELECT 
                we.id,
                we.greenhouse_id,
                we.plant_instance_id,
                we.created_at,
                pt.watering_interval_days,
                datetime(we.created_at, '+' || pt.watering_interval_days || ' days') as next_watering_date
            FROM watering_events we
            INNER JOIN plant_instances pi ON we.plant_instance_id = pi.id
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            WHERE we.greenhouse_id = :gh_id
                AND we.type = 'watering'
                AND pt.watering_interval_days IS NOT NULL
            ORDER BY we.created_at DESC
        """
            ),
            {"gh_id": gh_id},
        ).mappings().all()
        
        now = datetime.now()
        closest_watering = None
        closest_days = None
        
        # Обрабатываем полив по всей теплице (без интервала, просто последний)
        if last_greenhouse_watering:
            closest_watering = last_greenhouse_watering
            closest_days = None  # Нет интервала для полива теплицы
        
        # Обрабатываем поливы по растениям, находим ближайший следующий
        for pw in plant_waterings:
            next_date = pw["next_watering_date"]
            if next_date:
                if isinstance(next_date, str):
                    next_date = datetime.fromisoformat(next_date.replace("Z", "+00:00"))
                if isinstance(next_date, datetime):
                    next_date = next_date.replace(tzinfo=None)
                    days_until = (next_date - now).days
                    
                    # Если это первый найденный или ближе чем предыдущий
                    if closest_days is None or days_until < closest_days:
                        closest_watering = pw
                        closest_days = days_until
        
        if not closest_watering:
            return NextWateringOut(
                greenhouse_id=gh_id,
                plant_instance_id=None,
                plant_name=None,
                next_watering_date=None,
                days_until=None,
                is_overdue=False,
            )
        
        is_overdue = closest_days is not None and closest_days < 0
        
        return NextWateringOut(
            greenhouse_id=gh_id,
            plant_instance_id=closest_watering["plant_instance_id"],
            plant_name=None,
            next_watering_date=closest_watering["created_at"],
            days_until=closest_days,
            is_overdue=is_overdue,
        )


@router.get("/greenhouses/{gh_id}/plants/next-watering", response_model=List[NextWateringOut])
def get_next_watering_plants(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение ближайшего полива по каждому растению в теплице."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found"
            )
        
        # Получаем все растения в теплице с информацией о последнем поливе
        rows = conn.execute(
            text(
                """
            SELECT 
                pi.id as plant_instance_id,
                pi.greenhouse_id,
                pt.name as plant_name,
                pt.watering_interval_days,
                MAX(we.created_at) as last_watering,
                datetime(MAX(we.created_at), '+' || pt.watering_interval_days || ' days') as next_watering_date
            FROM plant_instances pi
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            LEFT JOIN watering_events we ON we.plant_instance_id = pi.id 
                AND we.type = 'watering'
            WHERE pi.greenhouse_id = :gh_id
                AND pt.watering_interval_days IS NOT NULL
            GROUP BY pi.id, pi.greenhouse_id, pt.name, pt.watering_interval_days
            ORDER BY next_watering_date ASC NULLS LAST
        """
            ),
            {"gh_id": gh_id},
        ).mappings().all()
        
        result = []
        now = datetime.now()
        
        for row in rows:
            next_date = row["next_watering_date"]
            days_until = None
            is_overdue = False
            
            # Если полива не было, следующий полив - через интервал от текущей даты
            if not row["last_watering"]:
                if row["watering_interval_days"]:
                    days_until = row["watering_interval_days"]
                    is_overdue = False
            elif next_date:
                # Вычисляем дни до следующего полива
                if isinstance(next_date, str):
                    next_date = datetime.fromisoformat(next_date.replace("Z", "+00:00"))
                if isinstance(next_date, datetime):
                    next_date = next_date.replace(tzinfo=None)
                    days_until = (next_date - now).days
                    is_overdue = days_until < 0
            
            result.append(
                NextWateringOut(
                    greenhouse_id=gh_id,
                    plant_instance_id=row["plant_instance_id"],
                    plant_name=row["plant_name"],
                    next_watering_date=row["last_watering"],
                    days_until=days_until,
                    is_overdue=is_overdue,
                )
            )
        
        return result


@router.get("/greenhouses/{gh_id}/next-fertilizing", response_model=NextWateringOut)
def get_next_fertilizing_greenhouse(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение ближайшего удобрения по всей теплице (среди всех удобрений теплицы)."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found"
            )
        
        # Находим ближайшее следующее удобрение по всей теплице
        # Сначала находим последнее удобрение по всей теплице (где plant_instance_id IS NULL)
        last_greenhouse_fertilizing = conn.execute(
            text(
                """
            SELECT 
                we.id,
                we.greenhouse_id,
                we.plant_instance_id,
                we.created_at
            FROM watering_events we
            WHERE we.greenhouse_id = :gh_id
                AND we.type = 'fertilizing'
                AND we.plant_instance_id IS NULL
            ORDER BY we.created_at DESC
            LIMIT 1
        """
            ),
            {"gh_id": gh_id},
        ).mappings().first()
        
        # Находим все удобрения по растениям с вычислением следующего удобрения
        plant_fertilizings = conn.execute(
            text(
                """
            SELECT 
                we.id,
                we.greenhouse_id,
                we.plant_instance_id,
                we.created_at,
                pt.fertilizing_interval_days,
                datetime(we.created_at, '+' || pt.fertilizing_interval_days || ' days') as next_fertilizing_date
            FROM watering_events we
            INNER JOIN plant_instances pi ON we.plant_instance_id = pi.id
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            WHERE we.greenhouse_id = :gh_id
                AND we.type = 'fertilizing'
                AND pt.fertilizing_interval_days IS NOT NULL
            ORDER BY we.created_at DESC
        """
            ),
            {"gh_id": gh_id},
        ).mappings().all()
        
        now = datetime.now()
        closest_fertilizing = None
        closest_days = None
        
        # Обрабатываем удобрение по всей теплице (без интервала, просто последнее)
        if last_greenhouse_fertilizing:
            closest_fertilizing = last_greenhouse_fertilizing
            closest_days = None  # Нет интервала для удобрения теплицы
        
        # Обрабатываем удобрения по растениям, находим ближайшее следующее
        for pf in plant_fertilizings:
            next_date = pf["next_fertilizing_date"]
            if next_date:
                if isinstance(next_date, str):
                    next_date = datetime.fromisoformat(next_date.replace("Z", "+00:00"))
                if isinstance(next_date, datetime):
                    next_date = next_date.replace(tzinfo=None)
                    days_until = (next_date - now).days
                    
                    # Если это первый найденный или ближе чем предыдущий
                    if closest_days is None or days_until < closest_days:
                        closest_fertilizing = pf
                        closest_days = days_until
        
        if not closest_fertilizing:
            return NextWateringOut(
                greenhouse_id=gh_id,
                plant_instance_id=None,
                plant_name=None,
                next_watering_date=None,
                days_until=None,
                is_overdue=False,
            )
        
        is_overdue = closest_days is not None and closest_days < 0
        
        return NextWateringOut(
            greenhouse_id=gh_id,
            plant_instance_id=closest_fertilizing["plant_instance_id"],
            plant_name=None,
            next_watering_date=closest_fertilizing["created_at"],
            days_until=closest_days,
            is_overdue=is_overdue,
        )


@router.get("/greenhouses/{gh_id}/plants/next-fertilizing", response_model=List[NextWateringOut])
def get_next_fertilizing_plants(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение ближайшего удобрения по каждому растению в теплице."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found"
            )
        
        # Получаем все растения в теплице с информацией о последнем удобрении
        rows = conn.execute(
            text(
                """
            SELECT 
                pi.id as plant_instance_id,
                pi.greenhouse_id,
                pt.name as plant_name,
                pt.fertilizing_interval_days,
                MAX(we.created_at) as last_fertilizing,
                datetime(MAX(we.created_at), '+' || pt.fertilizing_interval_days || ' days') as next_fertilizing_date
            FROM plant_instances pi
            INNER JOIN plant_types pt ON pi.plant_type_id = pt.id
            LEFT JOIN watering_events we ON we.plant_instance_id = pi.id 
                AND we.type = 'fertilizing'
            WHERE pi.greenhouse_id = :gh_id
                AND pt.fertilizing_interval_days IS NOT NULL
            GROUP BY pi.id, pi.greenhouse_id, pt.name, pt.fertilizing_interval_days
            ORDER BY next_fertilizing_date ASC NULLS LAST
        """
            ),
            {"gh_id": gh_id},
        ).mappings().all()
        
        result = []
        now = datetime.now()
        
        for row in rows:
            next_date = row["next_fertilizing_date"]
            days_until = None
            is_overdue = False
            
            # Если удобрения не было, следующее удобрение - через интервал от текущей даты
            if not row["last_fertilizing"]:
                if row["fertilizing_interval_days"]:
                    days_until = row["fertilizing_interval_days"]
                    is_overdue = False
            elif next_date:
                # Вычисляем дни до следующего удобрения
                if isinstance(next_date, str):
                    next_date = datetime.fromisoformat(next_date.replace("Z", "+00:00"))
                if isinstance(next_date, datetime):
                    next_date = next_date.replace(tzinfo=None)
                    days_until = (next_date - now).days
                    is_overdue = days_until < 0
            
            result.append(
                NextWateringOut(
                    greenhouse_id=gh_id,
                    plant_instance_id=row["plant_instance_id"],
                    plant_name=row["plant_name"],
                    next_watering_date=row["last_fertilizing"],
                    days_until=days_until,
                    is_overdue=is_overdue,
                )
            )
        
        return result


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
    Сохраняет данные в историю и обновляет последние значения.
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

        # Обновляем последние значения датчика
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

        # Сохраняем данные в историю
        reading_id = new_id()
        conn.execute(
            text(
                """
            INSERT INTO sensor_readings (id, sensor_id, greenhouse_id, temperature, humidity)
            VALUES (:id, :sensor_id, :greenhouse_id, :temp, :hum)
        """
            ),
            {
                "id": reading_id,
                "sensor_id": sensor["id"],
                "greenhouse_id": sensor["greenhouse_id"],
                "temp": payload.temperature,
                "hum": payload.humidity,
            },
        )

        if sensor["greenhouse_id"]:
            alerts_created = []

            if sensor["target_temp_min"] is not None and payload.temperature < sensor["target_temp_min"]:
                # Проверяем, есть ли уже непрочитанный alert такого же типа
                existing_alert = conn.execute(
                    text(
                        """
                    SELECT 1 FROM alerts
                    WHERE greenhouse_id = :gh_id
                    AND type = 'temperature'
                    AND is_read = 0
                    LIMIT 1
                """
                    ),
                    {"gh_id": sensor["greenhouse_id"]},
                ).scalar()
                
                if not existing_alert:
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
                # Проверяем, есть ли уже непрочитанный alert такого же типа
                existing_alert = conn.execute(
                    text(
                        """
                    SELECT 1 FROM alerts
                    WHERE greenhouse_id = :gh_id
                    AND type = 'temperature'
                    AND is_read = 0
                    LIMIT 1
                """
                    ),
                    {"gh_id": sensor["greenhouse_id"]},
                ).scalar()
                
                if not existing_alert:
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
                # Проверяем, есть ли уже непрочитанный alert такого же типа
                existing_alert = conn.execute(
                    text(
                        """
                    SELECT 1 FROM alerts
                    WHERE greenhouse_id = :gh_id
                    AND type = 'humidity'
                    AND is_read = 0
                    LIMIT 1
                """
                    ),
                    {"gh_id": sensor["greenhouse_id"]},
                ).scalar()
                
                if not existing_alert:
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
                # Проверяем, есть ли уже непрочитанный alert такого же типа
                existing_alert = conn.execute(
                    text(
                        """
                    SELECT 1 FROM alerts
                    WHERE greenhouse_id = :gh_id
                    AND type = 'humidity'
                    AND is_read = 0
                    LIMIT 1
                """
                    ),
                    {"gh_id": sensor["greenhouse_id"]},
                ).scalar()
                
                if not existing_alert:
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


@router.get("/greenhouses/{gh_id}/sensor-data/current", response_model=SensorReadingOut)
def get_current_sensor_data(gh_id: str, current_user: dict = Depends(get_current_user)):
    """Получение текущих данных датчика для теплицы."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh = conn.execute(
            text("SELECT id, sensor_id FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).mappings().first()
        
        if not gh:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
        
        if not gh["sensor_id"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No sensor attached to this greenhouse"
            )
        
        # Получаем последние данные датчика из истории
        reading = conn.execute(
            text(
                """
            SELECT id, sensor_id, greenhouse_id, temperature, humidity, created_at
            FROM sensor_readings
            WHERE greenhouse_id = :gh_id
            ORDER BY created_at DESC
            LIMIT 1
        """
            ),
            {"gh_id": gh_id},
        ).mappings().first()
        
        if not reading:
            # Если нет истории, берем из таблицы sensors
            sensor = conn.execute(
                text(
                    """
                SELECT id, last_temperature as temperature, last_humidity as humidity, last_update as created_at
                FROM sensors
                WHERE id = :sensor_id
            """
                ),
                {"sensor_id": gh["sensor_id"]},
            ).mappings().first()
            
            if not sensor or sensor["temperature"] is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="No sensor data available"
                )
            
            return SensorReadingOut(
                id="",
                sensor_id=sensor["id"],
                greenhouse_id=gh_id,
                temperature=sensor["temperature"],
                humidity=sensor["humidity"],
                created_at=sensor["created_at"] or datetime.now(),
            )
        
        return SensorReadingOut(**reading)


@router.get("/greenhouses/{gh_id}/sensor-data", response_model=List[SensorReadingOut])
def get_sensor_data_history(
    gh_id: str,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user),
):
    """Получение истории данных датчика для теплицы."""
    with engine.connect() as conn:
        # Проверка доступа для рабочих
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        
        if not gh_exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
        
        # Получаем историю данных
        readings = conn.execute(
            text(
                """
            SELECT id, sensor_id, greenhouse_id, temperature, humidity, created_at
            FROM sensor_readings
            WHERE greenhouse_id = :gh_id
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """
            ),
            {"gh_id": gh_id, "limit": limit, "offset": offset},
        ).mappings().all()
        
        return [SensorReadingOut(**r) for r in readings]


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


@router.patch("/alerts/{alert_id}/read", status_code=204)
def mark_alert_as_read(alert_id: str, current_user: dict = Depends(get_current_user)):
    """Отметить alert как прочитанный."""
    with engine.begin() as conn:
        # Проверяем существование alert и доступ
        alert = conn.execute(
            text(
                """
            SELECT a.id, a.greenhouse_id
            FROM alerts a
            WHERE a.id = :alert_id
        """
            ),
            {"alert_id": alert_id},
        ).mappings().first()
        
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        
        # Проверка доступа для рабочих
        if current_user["role"] == "worker":
            if alert["greenhouse_id"]:
                has_access = conn.execute(
                    text(
                        """
                    SELECT 1 FROM user_greenhouses
                    WHERE user_id=:user_id AND greenhouse_id=:gh_id
                """
                    ),
                    {"user_id": current_user["id"], "gh_id": alert["greenhouse_id"]},
                ).scalar()
                if not has_access:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access denied to this alert",
                    )
        
        # Отмечаем как прочитанный
        updated = conn.execute(
            text(
                """
            UPDATE alerts
            SET is_read = 1
            WHERE id = :alert_id
        """
            ),
            {"alert_id": alert_id},
        ).rowcount
        
        if updated == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    
    logger.info("Alert %s отмечен как прочитанный пользователем %s", alert_id, current_user["id"])


@router.patch("/greenhouses/{gh_id}/alerts/read", status_code=204)
def mark_greenhouse_alerts_as_read(
    gh_id: str,
    alert_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """Отметить все alerts для теплицы (или определенного типа) как прочитанные."""
    with engine.begin() as conn:
        # Проверка доступа
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
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied to this greenhouse",
                )
        
        # Проверка существования теплицы
        gh_exists = conn.execute(
            text("SELECT 1 FROM greenhouses WHERE id=:id"), {"id": gh_id}
        ).scalar()
        if not gh_exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Greenhouse not found")
        
        # Обновляем alerts
        if alert_type:
            # Отмечаем только alerts определенного типа
            conn.execute(
                text(
                    """
                UPDATE alerts
                SET is_read = 1
                WHERE greenhouse_id = :gh_id
                AND type = :alert_type
                AND is_read = 0
            """
                ),
                {"gh_id": gh_id, "alert_type": alert_type},
            )
        else:
            # Отмечаем все alerts для теплицы
            conn.execute(
                text(
                    """
                UPDATE alerts
                SET is_read = 1
                WHERE greenhouse_id = :gh_id
                AND is_read = 0
            """
                ),
                {"gh_id": gh_id},
            )
    
    logger.info(
        "Alerts для теплицы %s (type: %s) отмечены как прочитанные пользователем %s",
        gh_id,
        alert_type or "all",
        current_user["id"],
    )


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
            # Проверяем, есть ли уже непрочитанный alert такого же типа
            existing_alert = conn.execute(
                text(
                    """
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'watering_overdue'
                AND is_read = 0
                LIMIT 1
            """
                ),
                {"gh_id": plant["greenhouse_id"]},
            ).scalar()

            if not existing_alert:
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
            # Проверяем, есть ли уже непрочитанный alert такого же типа
            existing_alert = conn.execute(
                text(
                    """
                SELECT 1 FROM alerts
                WHERE greenhouse_id = :gh_id
                AND type = 'fertilizing_overdue'
                AND is_read = 0
                LIMIT 1
            """
                ),
                {"gh_id": plant["greenhouse_id"]},
            ).scalar()

            if not existing_alert:
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

