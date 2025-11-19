from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field


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
    avatar_id: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime


class TokenData(BaseModel):
    user_id: Optional[str] = None


class GreenhousePlantCreate(BaseModel):
    """Растение для добавления в теплицу при создании."""
    plant_type_id: str
    quantity: int = Field(1, ge=1)
    note: Optional[str] = None


class GreenhouseCreate(BaseModel):
    name: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    target_temp_min: Optional[float] = None
    target_temp_max: Optional[float] = None
    target_hum_min: Optional[float] = None
    target_hum_max: Optional[float] = None
    plants: Optional[List[GreenhousePlantCreate]] = None
    worker_ids: Optional[List[str]] = None
    sensor_ble_identifier: Optional[str] = None


class GreenhouseOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    sensor_id: Optional[str] = None
    target_temp_min: Optional[float] = None
    target_temp_max: Optional[float] = None
    target_hum_min: Optional[float] = None
    target_hum_max: Optional[float] = None
    created_at: datetime


class PlantTypeCreate(BaseModel):
    name: str
    description: Optional[str] = None
    image_url: Optional[str] = None
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
    image_url: Optional[str] = None
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


class AvatarUpdate(BaseModel):
    avatar_id: str


class AvatarOut(BaseModel):
    id: str
    image_url: str
    name: Optional[str] = None


class GreenhouseImageOut(BaseModel):
    id: str
    image_url: str
    name: Optional[str] = None


class NextWateringOut(BaseModel):
    """Информация о ближайшем поливе."""
    greenhouse_id: str
    plant_instance_id: Optional[str] = None
    plant_name: Optional[str] = None
    next_watering_date: Optional[datetime] = None
    days_until: Optional[int] = None
    is_overdue: bool = False

