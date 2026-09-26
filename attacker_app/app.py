"""
Attacker App — Flask + SocketIO (Full-stack with Jinja2 templates)
Serves HTML pages + API endpoints. Attacks run in threads with stats pushed via SocketIO.
"""
import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify
from flask_cors import CORS
import os
import sys

# Add parent dir so we can import modules if needed (state.py uses it)
sys.path.insert(0, os.path.dirname(__file__))

from extensions import socketio
from state import active_attacks

# Import blueprints
from routes.pages import pages_bp
from routes.network import network_bp
from routes.bruteforce import bruteforce_bp
from routes.arp import arp_bp
from routes.scanner import scanner_bp
from routes.status import status_bp

app = Flask(__name__)
# Local lab only — override in .env for anything beyond a personal machine.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-not-a-real-secret')
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SocketIO
socketio.init_app(app)

# Register Blueprints
app.register_blueprint(pages_bp)
app.register_blueprint(network_bp)
app.register_blueprint(bruteforce_bp)
app.register_blueprint(arp_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(status_bp)

# Context processor for templates
@app.context_processor
def inject_state():
    return dict(active_attacks=active_attacks)

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("\n╔══════════════════════════════════════════╗")
    print("║   🔴 RED TEAM — API Server               ║")
    print("║   Port: 5000 | SocketIO: enabled         ║")
    print("╚══════════════════════════════════════════╝\n")
    socketio.run(app, host='0.0.0.0', debug=False, port=5000,
                 allow_unsafe_werkzeug=True)
