"""Скрипт для заполнения базы данных тестовыми данными."""
from datetime import datetime, timedelta
from sqlalchemy import text

from app.config import engine
from app.dependencies import new_id, get_password_hash


def populate_database():
    """Заполняет базу данных тестовыми данными."""
    print("Начинаю заполнение базы данных тестовыми данными...")
    
    with engine.begin() as conn:
        # 1. Пользователи
        print("Создаю пользователей...")
        users = [
            {
                "id": new_id(),
                "email": "admin@example.com",
                "password_hash": get_password_hash("admin123"),
                "name": "Администратор",
                "role": "admin",
                "avatar_id": "avatar_1"
            },
            {
                "id": new_id(),
                "email": "worker1@example.com",
                "password_hash": get_password_hash("worker123"),
                "name": "Работник 1",
                "role": "worker",
                "avatar_id": "avatar_2"
            },
            {
                "id": new_id(),
                "email": "worker2@example.com",
                "password_hash": get_password_hash("worker123"),
                "name": "Работник 2",
                "role": "worker",
                "avatar_id": "avatar_3"
            }
        ]
        
        user_ids = []
        for user in users:
            try:
                conn.execute(
                    text("""
                        INSERT INTO users (id, email, password_hash, name, role, avatar_id, is_active)
                        VALUES (:id, :email, :password_hash, :name, :role, :avatar_id, 1)
                    """),
                    user
                )
                user_ids.append(user["id"])
                print(f"  ✓ Создан пользователь: {user['email']}")
            except Exception as e:
                existing = conn.execute(
                    text("SELECT id FROM users WHERE email=:email"),
                    {"email": user["email"]}
                ).scalar()
                if existing:
                    user_ids.append(existing)
                    print(f"  - Пользователь {user['email']} уже существует")
        
        # 2. Сенсоры
        print("Создаю сенсоры...")
        sensors = [
            {"id": new_id(), "ble_identifier": "SENSOR_001", "last_temperature": 22.5, "last_humidity": 65.0},
            {"id": new_id(), "ble_identifier": "SENSOR_002", "last_temperature": 24.0, "last_humidity": 70.0},
            {"id": new_id(), "ble_identifier": "SENSOR_003", "last_temperature": 23.0, "last_humidity": 68.0},
        ]
        
        sensor_ids = []
        for sensor in sensors:
            try:
                conn.execute(
                    text("""
                        INSERT INTO sensors (id, ble_identifier, last_temperature, last_humidity, last_update)
                        VALUES (:id, :ble_identifier, :last_temperature, :last_humidity, datetime('now'))
                    """),
                    sensor
                )
                sensor_ids.append(sensor["id"])
                print(f"  ✓ Создан сенсор: {sensor['ble_identifier']}")
            except Exception as e:
                existing = conn.execute(
                    text("SELECT id FROM sensors WHERE ble_identifier=:ble"),
                    {"ble": sensor["ble_identifier"]}
                ).scalar()
                if existing:
                    sensor_ids.append(existing)
                    print(f"  - Сенсор {sensor['ble_identifier']} уже существует")
        
        # 3. Типы растений
        print("Создаю типы растений...")
        plant_types = [
            {
                "id": new_id(),
                "name": "Томаты",
                "description": "Помидоры черри",
                "temp_min": 18.0,
                "temp_max": 25.0,
                "humidity_min": 60.0,
                "humidity_max": 80.0,
                "watering_interval_days": 3,
                "fertilizing_interval_days": 14
            },
            {
                "id": new_id(),
                "name": "Огурцы",
                "description": "Огурцы для теплицы",
                "temp_min": 20.0,
                "temp_max": 28.0,
                "humidity_min": 70.0,
                "humidity_max": 90.0,
                "watering_interval_days": 2,
                "fertilizing_interval_days": 10
            },
            {
                "id": new_id(),
                "name": "Перец",
                "description": "Болгарский перец",
                "temp_min": 22.0,
                "temp_max": 26.0,
                "humidity_min": 65.0,
                "humidity_max": 85.0,
                "watering_interval_days": 4,
                "fertilizing_interval_days": 21
            }
        ]
        
        plant_type_ids = []
        for pt in plant_types:
            try:
                conn.execute(
                    text("""
                        INSERT INTO plant_types (id, name, description, temp_min, temp_max, 
                                                 humidity_min, humidity_max, watering_interval_days, fertilizing_interval_days)
                        VALUES (:id, :name, :description, :temp_min, :temp_max, 
                                :humidity_min, :humidity_max, :watering_interval_days, :fertilizing_interval_days)
                    """),
                    pt
                )
                plant_type_ids.append(pt["id"])
                print(f"  ✓ Создан тип растения: {pt['name']}")
            except Exception as e:
                print(f"  ✗ Ошибка при создании типа растения {pt['name']}: {e}")
        
        # 4. Теплицы
        print("Создаю теплицы...")
        greenhouses = [
            {
                "id": new_id(),
                "name": "Теплица №1",
                "description": "Основная теплица для томатов",
                "image_url": "/static/greenhouses/greenhouse_1.png",
                "sensor_id": sensor_ids[0] if sensor_ids else None,
                "target_temp_min": 20.0,
                "target_temp_max": 24.0,
                "target_hum_min": 65.0,
                "target_hum_max": 75.0
            },
            {
                "id": new_id(),
                "name": "Теплица №2",
                "description": "Теплица для огурцов",
                "image_url": "/static/greenhouses/greenhouse_2.png",
                "sensor_id": sensor_ids[1] if len(sensor_ids) > 1 else None,
                "target_temp_min": 22.0,
                "target_temp_max": 26.0,
                "target_hum_min": 70.0,
                "target_hum_max": 85.0
            },
            {
                "id": new_id(),
                "name": "Теплица №3",
                "description": "Теплица для перца",
                "image_url": "/static/greenhouses/greenhouse_3.png",
                "sensor_id": sensor_ids[2] if len(sensor_ids) > 2 else None,
                "target_temp_min": 23.0,
                "target_temp_max": 25.0,
                "target_hum_min": 70.0,
                "target_hum_max": 80.0
            }
        ]
        
        greenhouse_ids = []
        for gh in greenhouses:
            try:
                conn.execute(
                    text("""
                        INSERT INTO greenhouses (id, name, description, image_url, sensor_id,
                                                target_temp_min, target_temp_max, target_hum_min, target_hum_max)
                        VALUES (:id, :name, :description, :image_url, :sensor_id,
                                :target_temp_min, :target_temp_max, :target_hum_min, :target_hum_max)
                    """),
                    gh
                )
                greenhouse_ids.append(gh["id"])
                print(f"  ✓ Создана теплица: {gh['name']}")
            except Exception as e:
                print(f"  ✗ Ошибка при создании теплицы {gh['name']}: {e}")
        
        # 5. Связь пользователей с теплицами
        print("Связываю пользователей с теплицами...")
        for i, gh_id in enumerate(greenhouse_ids):
            if len(user_ids) > 1:
                worker_id = user_ids[1]
            else:
                worker_id = user_ids[0] if user_ids else None
            if worker_id:
                try:
                    conn.execute(
                        text("""
                            INSERT INTO user_greenhouses (user_id, greenhouse_id)
                            VALUES (:user_id, :greenhouse_id)
                        """),
                        {"user_id": worker_id, "greenhouse_id": gh_id}
                    )
                    print(f"  ✓ Связан пользователь с теплицей {i+1}")
                except Exception:
                    pass
        
        # 6. Экземпляры растений
        print("Создаю экземпляры растений...")
        plant_instances = []
        if greenhouse_ids and plant_type_ids:
            plant_instances = [
                {
                    "id": new_id(),
                    "greenhouse_id": greenhouse_ids[0],
                    "plant_type_id": plant_type_ids[0],
                    "quantity": 50,
                    "note": "Томаты черри"
                },
                {
                    "id": new_id(),
                    "greenhouse_id": greenhouse_ids[1] if len(greenhouse_ids) > 1 else greenhouse_ids[0],
                    "plant_type_id": plant_type_ids[1] if len(plant_type_ids) > 1 else plant_type_ids[0],
                    "quantity": 30,
                    "note": "Огурцы ранние"
                },
                {
                    "id": new_id(),
                    "greenhouse_id": greenhouse_ids[2] if len(greenhouse_ids) > 2 else greenhouse_ids[0],
                    "plant_type_id": plant_type_ids[2] if len(plant_type_ids) > 2 else plant_type_ids[0],
                    "quantity": 25,
                    "note": "Перец сладкий"
                }
            ]
        
        plant_instance_ids = []
        for pi in plant_instances:
            try:
                conn.execute(
                    text("""
                        INSERT INTO plant_instances (id, greenhouse_id, plant_type_id, quantity, note)
                        VALUES (:id, :greenhouse_id, :plant_type_id, :quantity, :note)
                    """),
                    pi
                )
                plant_instance_ids.append(pi["id"])
                print(f"  ✓ Создан экземпляр растения")
            except Exception as e:
                print(f"  ✗ Ошибка при создании экземпляра: {e}")
        
        # 7. События полива (старые данные)
        print("Создаю события полива...")
        base_date = datetime.now() - timedelta(days=30)
        event_count = 0
        for i in range(20):
            event_date = base_date + timedelta(days=i*1.5)
            if greenhouse_ids and user_ids:
                try:
                    conn.execute(
                        text("""
                            INSERT INTO watering_events (id, greenhouse_id, user_id, plant_instance_id, type, created_at, comment)
                            VALUES (:id, :greenhouse_id, :user_id, :plant_instance_id, :type, :created_at, :comment)
                        """),
                        {
                            "id": new_id(),
                            "greenhouse_id": greenhouse_ids[i % len(greenhouse_ids)],
                            "user_id": user_ids[1] if len(user_ids) > 1 else user_ids[0],
                            "plant_instance_id": plant_instance_ids[i % len(plant_instance_ids)] if plant_instance_ids else None,
                            "type": "watering" if i % 2 == 0 else "fertilizing",
                            "created_at": event_date.strftime("%Y-%m-%d %H:%M:%S"),
                            "comment": f"Полив #{i+1}"
                        }
                    )
                    event_count += 1
                except Exception:
                    pass
        print(f"  ✓ Создано {event_count} событий полива")
        
        # 8. Показания сенсоров (старые данные)
        print("Создаю показания сенсоров...")
        reading_count = 0
        for i in range(50):
            reading_date = base_date + timedelta(hours=i*14)
            if sensor_ids:
                sensor_idx = i % len(sensor_ids)
                try:
                    conn.execute(
                        text("""
                            INSERT INTO sensor_readings (id, sensor_id, greenhouse_id, temperature, humidity, created_at)
                            VALUES (:id, :sensor_id, :greenhouse_id, :temperature, :humidity, :created_at)
                        """),
                        {
                            "id": new_id(),
                            "sensor_id": sensor_ids[sensor_idx],
                            "greenhouse_id": greenhouse_ids[sensor_idx] if sensor_idx < len(greenhouse_ids) else None,
                            "temperature": 20.0 + (i % 10) * 0.5,
                            "humidity": 60.0 + (i % 20) * 1.0,
                            "created_at": reading_date.strftime("%Y-%m-%d %H:%M:%S")
                        }
                    )
                    reading_count += 1
                except Exception:
                    pass
        print(f"  ✓ Создано {reading_count} показаний сенсоров")
        
        # 9. Уведомления
        print("Создаю уведомления...")
        alert_count = 0
        for i in range(10):
            alert_date = base_date + timedelta(days=i*3)
            if greenhouse_ids and user_ids:
                try:
                    conn.execute(
                        text("""
                            INSERT INTO alerts (id, greenhouse_id, user_id, type, message, severity, is_read, created_at)
                            VALUES (:id, :greenhouse_id, :user_id, :type, :message, :severity, :is_read, :created_at)
                        """),
                        {
                            "id": new_id(),
                            "greenhouse_id": greenhouse_ids[i % len(greenhouse_ids)],
                            "user_id": user_ids[1] if len(user_ids) > 1 else user_ids[0],
                            "type": "temperature" if i % 2 == 0 else "humidity",
                            "message": f"Уведомление #{i+1}",
                            "severity": "warning" if i % 3 == 0 else "critical",
                            "is_read": 0 if i % 2 == 0 else 1,
                            "created_at": alert_date.strftime("%Y-%m-%d %H:%M:%S")
                        }
                    )
                    alert_count += 1
                except Exception:
                    pass
        print(f"  ✓ Создано {alert_count} уведомлений")
    
    print("\n✅ Заполнение базы данных завершено!")


if __name__ == "__main__":
    populate_database()
