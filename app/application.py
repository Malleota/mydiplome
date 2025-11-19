from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api import router
from .config import lifespan, STATIC_DIR


def create_app() -> FastAPI:
    app = FastAPI(title="zharko_vkr simple API", version="0.1.0", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Подключаем статические файлы (аватарки)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    app.include_router(router)

    return app

