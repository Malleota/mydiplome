from typing import Dict, Set, Optional
from fastapi import WebSocket
from .config import logger


class ConnectionManager:
    """Менеджер для управления WebSocket подключениями."""
    
    def __init__(self):
        # Словарь: greenhouse_id -> Set[WebSocket]
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Подключения для всех теплиц (админы)
        self.all_greenhouses_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket, greenhouse_id: Optional[str] = None):
        """Подключение клиента к WebSocket."""
        try:
            await websocket.accept()
        except Exception as e:
            # Если это не WebSocket запрос, пробрасываем исключение дальше
            logger.debug("Ошибка при принятии WebSocket подключения: %s", e)
            raise
        
        if greenhouse_id:
            if greenhouse_id not in self.active_connections:
                self.active_connections[greenhouse_id] = set()
            self.active_connections[greenhouse_id].add(websocket)
            logger.info("WebSocket подключен для теплицы %s", greenhouse_id)
        else:
            # Подписка на все теплицы
            self.all_greenhouses_connections.add(websocket)
            logger.info("WebSocket подключен (все теплицы)")
    
    def disconnect(self, websocket: WebSocket, greenhouse_id: Optional[str] = None):
        """Отключение клиента от WebSocket."""
        if greenhouse_id and greenhouse_id in self.active_connections:
            self.active_connections[greenhouse_id].discard(websocket)
            if not self.active_connections[greenhouse_id]:
                del self.active_connections[greenhouse_id]
            logger.info("WebSocket отключен для теплицы %s", greenhouse_id)
        else:
            # Удаляем из всех теплиц
            self.all_greenhouses_connections.discard(websocket)
            # Также удаляем из всех конкретных теплиц на случай, если был подключен
            for gh_id in list(self.active_connections.keys()):
                self.active_connections[gh_id].discard(websocket)
                if not self.active_connections[gh_id]:
                    del self.active_connections[gh_id]
            logger.info("WebSocket отключен")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Отправка сообщения конкретному клиенту."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error("Ошибка отправки сообщения через WebSocket: %s", e)
    
    async def broadcast_to_greenhouse(self, message: dict, greenhouse_id: str):
        """Отправка сообщения всем клиентам, подписанным на конкретную теплицу."""
        if greenhouse_id in self.active_connections:
            disconnected = set()
            for connection in self.active_connections[greenhouse_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error("Ошибка отправки сообщения через WebSocket: %s", e)
                    disconnected.add(connection)
            
            # Удаляем отключенные соединения
            for conn in disconnected:
                self.disconnect(conn, greenhouse_id)
    
    async def broadcast_to_all(self, message: dict):
        """Отправка сообщения всем клиентам, подписанным на все теплицы (админы)."""
        disconnected = set()
        for connection in self.all_greenhouses_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error("Ошибка отправки сообщения через WebSocket: %s", e)
                disconnected.add(connection)
        
        # Удаляем отключенные соединения
        for conn in disconnected:
            self.disconnect(conn, None)


# Глобальный экземпляр менеджера
manager = ConnectionManager()

