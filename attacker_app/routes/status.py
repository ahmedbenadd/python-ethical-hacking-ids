from flask import Blueprint, jsonify
from extensions import socketio
from state import active_attacks, stats, attack_stats, attack_history

status_bp = Blueprint('status', __name__)

@status_bp.route('/api/status')
def api_status():
    return jsonify({
        'active': active_attacks,
        'stats': stats,
        'attack_stats': attack_stats,
        'history': attack_history[:15],
    })

@socketio.on('connect')
def handle_connect():
    """Send current state when a client connects."""
    # Disable persistence: Reset history and stats on refresh
    attack_history.clear()
    stats['attacks'] = 0
    stats['successes'] = 0

    socketio.emit('status_update', {
        'active': active_attacks,
        'stats': stats,
        'history': attack_history[:15],
    })
    
    if active_attacks['bruteforce']:
        socketio.emit('bf_update', attack_stats['bruteforce'])
    if active_attacks['arp']:
        socketio.emit('arp_stats', attack_stats['arp'])
    if active_attacks['scanner']:
        socketio.emit('scanner_progress', attack_stats['scanner'])
