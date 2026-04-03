import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()
_connections: list[WebSocket] = []


@router.websocket("")
async def websocket_stream(ws: WebSocket):
    await ws.accept()
    _connections.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        _connections.remove(ws)


async def broadcast(data: dict):
    dead = []
    for ws in _connections:
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _connections.remove(ws)
