import time
from extensions import socketio
from modules import network_discovery

# ─── State ──────────────────────────────────────────────────
active_attacks = {'bruteforce': False, 'arp': False, 'scanner': False, 'discovery': False}
attack_stats = {
    'bruteforce': {'attempts': 0, 'progress': 0, 'current_password': '',
                   'found': False, 'cracked_password': None, 'target': '',
                   'total': 0, 'status_code': 0, 'error': '', 'error_type': ''},
    'arp': {'packets_sent': 0, 'elapsed': 0, 'target_ip': '', 'gateway_ip': ''},
    'scanner': {'phase': 'idle', 'target': '', 'scan_type': ''},
    'discovery': {'scanning': False, 'count': 0}
}
attack_history = []
stats = {'attacks': 0, 'successes': 0}


def add_history(attack_type, target, status='launched'):
    entry = {
        'type': attack_type,
        'target': target,
        'time': time.strftime('%H:%M:%S'),
        'status': status,
    }
    attack_history.insert(0, entry)
    if len(attack_history) > 50:
        attack_history.pop()
    socketio.emit('history_update', {'history': attack_history[:15]})


def broadcast_status():
    """Push full status to all connected clients."""
    # Update discovery state locally for broadcast
    try:
        disc_status = network_discovery.discovery_module.get_results()
        active_attacks['discovery'] = disc_status['scanning']
    except Exception:
        # Fallback if discovery module isn't ready or errors
        pass
    
    socketio.emit('status_update', {
        'active': active_attacks,
        'stats': stats,
        'history': attack_history[:15],
    })
