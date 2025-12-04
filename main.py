import os

from app import create_app
from app.config import logger

app = create_app()


if __name__ == "__main__":
    import logging
    import uvicorn

    # Подавляем предупреждения uvicorn о невалидных HTTP запросах к WebSocket endpoints
    uvicorn_logger = logging.getLogger("uvicorn.error")
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    
    # Фильтруем предупреждения о невалидных HTTP запросах (это нормально для WebSocket endpoints)
    class FilterInvalidHTTP(logging.Filter):
        def filter(self, record):
            # Подавляем предупреждения о невалидных HTTP запросах
            if "Invalid HTTP request received" in str(record.getMessage()):
                return False
            return True
    
    invalid_http_filter = FilterInvalidHTTP()
    uvicorn_logger.addFilter(invalid_http_filter)
    uvicorn_access_logger.addFilter(invalid_http_filter)

    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000"))
    logger.info("Запуск FastAPI сервера на %s:%s", host, port)
    uvicorn.run(app, host=host, port=port)

