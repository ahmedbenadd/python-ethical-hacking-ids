from flask_socketio import SocketIO

socketio = SocketIO(async_mode='eventlet', cors_allowed_origins="*",
                    ping_timeout=60, ping_interval=25)
