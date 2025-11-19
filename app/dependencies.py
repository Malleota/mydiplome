import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import text

from .config import (
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    engine,
    logger,
    oauth2_scheme,
    pwd_context,
)
from .schemas import TokenData


def new_id() -> str:
    return str(uuid.uuid4())


def one_or_404(row, msg: str = "Not found"):
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password using configured context."""
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, str]:
    """Retrieve current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось подтвердить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception

    with engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    """
            SELECT id, email, name, role, is_active, avatar_id, created_at
            FROM users WHERE id=:id
        """
                ),
                {"id": token_data.user_id},
            )
            .mappings()
            .first()
        )

        if not row:
            raise credentials_exception

        if not row["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Пользователь неактивен",
            )

        return dict(row)


def require_admin(current_user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
    """Ensure that the current user has admin role."""
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуются права администратора",
        )
    return current_user


def send_push_notification(user_id: Optional[str], message: str, title: str = "Уведомление"):
    """Placeholder for push notification integration."""
    logger.info("Push notification to user %s: %s - %s", user_id, title, message)
    # TODO: integrate with Firebase Cloud Messaging or other provider

