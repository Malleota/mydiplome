"""Инициализация схемы базы данных."""
import logging
from sqlalchemy import Engine, text
from sqlalchemy.exc import OperationalError

logger = logging.getLogger("flowers-api")


def get_default_avatars(): 
    """Возвращает список базовых аватарок для вставки."""
    # Используем локальные пути на сервере
    return [
        ("avatar_1", "/static/avatars/avatar_1.png", "avatar 1"),
        ("avatar_2", "/static/avatars/avatar_2.png", "avatar 2"),
        ("avatar_3", "/static/avatars/avatar_3.png", "avatar 3"),
        ("avatar_4", "/static/avatars/avatar_4.png", "avatar 4"),  # ← исправлено: avatar_4 вместо avatar_3
    ]


def get_default_greenhouse_images():
    """Возвращает список базовых изображений для теплиц."""
    # Используем локальные пути на сервере
    return [
        ("greenhouse_1", "/static/greenhouses/greenhouse_1.png", "Greenhouse 1"),
        ("greenhouse_2", "/static/greenhouses/greenhouse_2.png", "Greenhouse 2"),
        ("greenhouse_3", "/static/greenhouses/greenhouse_3.png", "Greenhouse 3"),
    ]


def get_schema_statements():
    """Возвращает список SQL-запросов для создания таблиц."""
    return [
        # Сначала создаём таблицы без внешних ключей
        """
        CREATE TABLE IF NOT EXISTS avatars (
            id            TEXT NOT NULL PRIMARY KEY,
            image_url     TEXT NOT NULL,
            name          TEXT,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS greenhouse_images (
            id            TEXT NOT NULL PRIMARY KEY,
            image_url     TEXT NOT NULL,
            name          TEXT,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT NOT NULL PRIMARY KEY,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name          TEXT,
            role          TEXT NOT NULL CHECK(role IN ('admin', 'worker')),
            is_active     INTEGER NOT NULL DEFAULT 1,
            avatar_id     TEXT,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS sensors (
            id               TEXT NOT NULL PRIMARY KEY,
            ble_identifier   TEXT NOT NULL UNIQUE,
            last_temperature REAL,
            last_humidity    REAL,
            last_update      DATETIME
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS greenhouses (
            id               TEXT NOT NULL PRIMARY KEY,
            name             TEXT NOT NULL,
            description      TEXT,
            image_url        TEXT,
            sensor_id        TEXT UNIQUE,
            target_temp_min  REAL,
            target_temp_max  REAL,
            target_hum_min   REAL,
            target_hum_max   REAL,
            created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_greenhouse_sensor
                FOREIGN KEY (sensor_id) REFERENCES sensors(id)
                ON DELETE SET NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS plant_types (
            id                         TEXT NOT NULL PRIMARY KEY,
            name                       TEXT NOT NULL,
            description                TEXT,
            image_url                  TEXT,
            temp_min                   REAL,
            temp_max                   REAL,
            humidity_min               REAL,
            humidity_max               REAL,
            watering_interval_days     INTEGER,
            fertilizing_interval_days  INTEGER
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS plant_instances (
            id             TEXT NOT NULL PRIMARY KEY,
            greenhouse_id  TEXT NOT NULL,
            plant_type_id  TEXT NOT NULL,
            quantity       INTEGER NOT NULL DEFAULT 1,
            note           TEXT,
            next_watering_date DATETIME,
            days_until     INTEGER,
            CONSTRAINT fk_pi_greenhouse
                FOREIGN KEY (greenhouse_id) REFERENCES greenhouses(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_pi_plant_type
                FOREIGN KEY (plant_type_id) REFERENCES plant_types(id)
                ON DELETE RESTRICT
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS watering_events (
            id                TEXT NOT NULL PRIMARY KEY,
            greenhouse_id     TEXT NOT NULL,
            user_id           TEXT,
            plant_instance_id TEXT,
            type              TEXT NOT NULL CHECK(type IN ('watering', 'fertilizing')),
            created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            comment           TEXT,
            CONSTRAINT fk_we_greenhouse
                FOREIGN KEY (greenhouse_id) REFERENCES greenhouses(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_we_user
                FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE SET NULL,
            CONSTRAINT fk_we_plant_instance
                FOREIGN KEY (plant_instance_id) REFERENCES plant_instances(id)
                ON DELETE SET NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS user_greenhouses (
            user_id       TEXT NOT NULL,
            greenhouse_id TEXT NOT NULL,
            PRIMARY KEY (user_id, greenhouse_id),
            CONSTRAINT fk_ug_user
                FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_ug_greenhouse
                FOREIGN KEY (greenhouse_id) REFERENCES greenhouses(id)
                ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id            TEXT NOT NULL PRIMARY KEY,
            greenhouse_id TEXT,
            user_id       TEXT,
            type          TEXT NOT NULL CHECK(type IN ('temperature', 'humidity', 'watering_overdue', 'fertilizing_overdue')),
            message       TEXT NOT NULL,
            severity      TEXT NOT NULL CHECK(severity IN ('warning', 'critical')) DEFAULT 'warning',
            is_read       INTEGER NOT NULL DEFAULT 0,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_alerts_greenhouse
                FOREIGN KEY (greenhouse_id) REFERENCES greenhouses(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_alerts_user
                FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE SET NULL
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS sensor_readings (
            id            TEXT NOT NULL PRIMARY KEY,
            sensor_id     TEXT NOT NULL,
            greenhouse_id TEXT,
            temperature   REAL NOT NULL,
            humidity      REAL NOT NULL,
            created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_sr_sensor
                FOREIGN KEY (sensor_id) REFERENCES sensors(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_sr_greenhouse
                FOREIGN KEY (greenhouse_id) REFERENCES greenhouses(id)
                ON DELETE SET NULL
        );
        """,
        # Индексы для улучшения производительности
        """
        CREATE INDEX IF NOT EXISTS idx_watering_events_created_at
            ON watering_events(created_at DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_watering_events_greenhouse_id
            ON watering_events(greenhouse_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at
            ON alerts(created_at DESC);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_greenhouse_id
            ON alerts(greenhouse_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_user_id
            ON alerts(user_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_plant_instances_greenhouse_id
            ON plant_instances(greenhouse_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_sensor_readings_sensor_id
            ON sensor_readings(sensor_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_sensor_readings_greenhouse_id
            ON sensor_readings(greenhouse_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_sensor_readings_created_at
            ON sensor_readings(created_at DESC);
        """,
    ]


def ensure_schema(engine: Engine, db_path: str = None):
    """
    Создаём таблицы, если они ещё не существуют.
    
    Args:
        engine: SQLAlchemy engine для подключения к БД
        db_path: Путь к файлу БД (для логирования ошибок)
    """
    try:
        # Проверяем подключение к БД
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as e:
        logger.error(f"Не удалось подключиться к базе данных: {e}")
        if db_path:
            logger.error(f"Проверьте путь к файлу БД: {db_path}")
        raise
    
    # Создаём все таблицы (если их нет)
    statements = get_schema_statements()
    with engine.begin() as conn:
        for stmt in statements:
            conn.execute(text(stmt))
    
    # Заполняем аватарки, если таблица пустая
    with engine.begin() as conn:
        existing_count = conn.execute(text("SELECT COUNT(*) FROM avatars")).scalar()
        if existing_count == 0:
            avatars = get_default_avatars()
            for avatar_id, image_url, name in avatars:
                conn.execute(
                    text("INSERT INTO avatars (id, image_url, name) VALUES (:id, :url, :name)"),
                    {"id": avatar_id, "url": image_url, "name": name}
                )
            logger.info(f"Добавлено {len(avatars)} базовых аватарок")
    
    # Заполняем изображения теплиц, если таблица пустая
    with engine.begin() as conn:
        existing_count = conn.execute(text("SELECT COUNT(*) FROM greenhouse_images")).scalar()
        if existing_count == 0:
            images = get_default_greenhouse_images()
            for image_id, image_url, name in images:
                conn.execute(
                    text("INSERT INTO greenhouse_images (id, image_url, name) VALUES (:id, :url, :name)"),
                    {"id": image_id, "url": image_url, "name": name}
                )
            logger.info(f"Добавлено {len(images)} базовых изображений теплиц")
    
    # Миграция: добавляем поля next_watering_date и days_until в plant_instances, если их нет
    with engine.begin() as conn:
        # Проверяем существование колонок через PRAGMA table_info
        table_info = conn.execute(text("PRAGMA table_info(plant_instances)")).fetchall()
        column_names = [row[1] for row in table_info]  # Второй элемент - имя колонки
        
        if "next_watering_date" not in column_names:
            try:
                conn.execute(text("ALTER TABLE plant_instances ADD COLUMN next_watering_date DATETIME"))
                logger.info("Добавлена колонка next_watering_date в таблицу plant_instances")
            except OperationalError as e:
                logger.warning(f"Не удалось добавить колонку next_watering_date: {e}")
        
        if "days_until" not in column_names:
            try:
                conn.execute(text("ALTER TABLE plant_instances ADD COLUMN days_until INTEGER"))
                logger.info("Добавлена колонка days_until в таблицу plant_instances")
            except OperationalError as e:
                logger.warning(f"Не удалось добавить колонку days_until: {e}")
    
    logger.info("Схема базы данных успешно инициализирована")

