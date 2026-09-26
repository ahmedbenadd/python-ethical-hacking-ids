from flask import Blueprint, request, jsonify
from extensions import socketio
from state import active_attacks, stats, attack_stats, add_history, broadcast_status
from modules import scanner

scanner_bp = Blueprint('scanner', __name__)

@scanner_bp.route('/api/attack/scanner', methods=['POST'])
def scanner_attack():
    action = request.json.get('action')

    if action == 'start':
        if active_attacks['scanner']:
            return jsonify({'status': 'error', 'message': 'Scan already running'})

        target = request.json.get('target', '127.0.0.1')
        scan_type = request.json.get('scan_type', 'quick')
        ports = request.json.get('ports')

        active_attacks['scanner'] = True
        stats['attacks'] += 1
        broadcast_status()

        def scan_callback(data):
            socketio.emit('scanner_results' if data.get('phase') in ('complete', 'error') else 'scanner_progress', data)
            if data.get('phase') in ('complete', 'error', 'cancelled'):
                active_attacks['scanner'] = False
                broadcast_status()

        scanner.scanner_module.start_scan(target, scan_type, ports, callback=scan_callback)
        return jsonify({'status': 'ok', 'message': f'Nmap {scan_type} scan launched against {target}'})
        return jsonify({'status': 'ok', 'message': f'Nmap {scan_type} scan launched against {target}'})

    elif action == 'stop':
        scanner.scanner_module.stop()
        active_attacks['scanner'] = False
        add_history('NMAP_SCAN', attack_stats['scanner'].get('target', ''), 'stopped')
        broadcast_status()
        return jsonify({'status': 'ok', 'message': 'Scan stopped'})


    return jsonify({'status': 'error', 'message': 'Unknown action'})
