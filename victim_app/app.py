import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from core.sniffer import TrafficSniffer
from core.analyzer import IDSAnalyzer
from core.monitor import TrafficMonitor
import time
import os

# Initialize Core Components
app = Flask(__name__)
# Local lab only — override in .env for anything beyond a personal machine.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-not-a-real-secret')
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

analyzer = IDSAnalyzer()
monitor = TrafficMonitor()

packet_log = []     # Store recent packets for display
alert_log = []      # Store alerts

# Global Statistics (Persistent-ish)
TOTAL_PACKETS = 0
TOTAL_ALERTS = 0

def packet_callback(packet):
    """Called from the sniffer thread for every packet captured."""
    global TOTAL_PACKETS, TOTAL_ALERTS
    
    # Run analysis (Always run full analysis)
    alerts, info = analyzer.analyze_packet(packet)
    
    # Increment Global Counter for ALL packets captured
    TOTAL_PACKETS += 1
    
    if info:
        # Check if packet should be visualized
        if monitor.should_show(info, has_alerts=bool(alerts)):
            if len(packet_log) > 50:
                packet_log.pop(0)
            packet_log.append(info)
            socketio.emit('new_packet', info)

    # Process High-Level Alerts
    for alert in alerts:
        TOTAL_ALERTS += 1
        alert['timestamp'] = time.strftime('%H:%M:%S')
        alert_log.insert(0, alert)
        if len(alert_log) > 50:
             alert_log.pop()
        
        print(f"[!] ALERT: {alert['message']}")
        socketio.emit('new_alert', alert)

# Start Sniffer
import argparse

parser = argparse.ArgumentParser(description='Guardian IDS')
parser.add_argument('-i', '--interface', help='Network interface to monitor', default=None)
args = parser.parse_args()

interface = args.interface
sniffer = TrafficSniffer(interface=interface, callback=packet_callback)
sniffer.start()

# ─── SocketIO Events ────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.remote_addr}")
    # User requested NO history persistence on refresh.
    # We do NOT send history_packets, history_alerts, or init_stats.
    # The client will start with a fresh blank state.

# ─── Routes ─────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    return jsonify({
        'packet_count': len(packet_log),
        'alert_count': len(alert_log),
        'alerts': alert_log[:10]
    })





if __name__ == '__main__':
    iface_name = args.interface if args.interface else "Default/All"
    print("\n╔══════════════════════════════════════════╗")
    print("║   🛡️  BLUE TEAM — IDS System             ║")
    print(f"║   Monitoring Active on: {iface_name:<16} ║")
    print("╚══════════════════════════════════════════╝\n")
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
