from flask_socketio import SocketIO

_socketio: SocketIO = None

def init_socketio(sio: SocketIO):
    global _socketio
    _socketio = sio

def get_socketio() -> SocketIO:
    return _socketio

def emit(event: str, data: dict, namespace: str = None):
    if _socketio:
        _socketio.emit(event, data, namespace=namespace)
        print(f"[SOCKET.IO] Emitted '{event}': {data}")
    else:
        print("[SOCKET.IO] Warning: socketio not initialized")