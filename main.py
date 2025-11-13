import os

from app import create_app
from app.config import logger

app = create_app()


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    logger.info("Запуск FastAPI сервера на %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)

