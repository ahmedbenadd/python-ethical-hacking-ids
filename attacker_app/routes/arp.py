from flask import Blueprint, request, jsonify
import threading
from extensions import socketio
from state import active_attacks, stats, attack_stats, add_history, broadcast_status
from modules import arp_spoofer

arp_bp = Blueprint('arp', __name__)

@arp_bp.route('/api/attack/arp', methods=['POST'])
def arp_attack():
    action = request.json.get('action')

    if action == 'start':
        if active_attacks['arp']:
            return jsonify({'status': 'error', 'message': 'Already running'})

        target_ip = request.json.get('target_ip')
        gateway_ip = request.json.get('gateway_ip')
        interface = request.json.get('interface', 'eth0')

        # Simplified State Handover
        t = threading.Thread(
            target=arp_spoofer.arp_spoofer_module.spoof,
            args=(target_ip, gateway_ip, interface),
            kwargs={
                'stats_callback': lambda packets_sent, elapsed: socketio.emit('arp_stats', {
                    'packets_sent': packets_sent, 'elapsed': round(elapsed, 1), 'target_ip': target_ip
                }),
                'log_callback': lambda message, **kwargs: socketio.emit('arp_log', {'message': message, 'type': kwargs.get('type', 'info')})
            },
            daemon=True
        )
        t.start()
        
        active_attacks['arp'] = True
        stats['attacks'] += 1
        broadcast_status()
        
        return jsonify({'status': 'ok', 'message': 'ARP Spoofing initiated'})

    elif action == 'stop':
        arp_spoofer.arp_spoofer_module.stop()
        active_attacks['arp'] = False
        add_history('ARP_SPOOF', attack_stats['arp'].get('target_ip', ''), 'stopped')
        broadcast_status()
        return jsonify({'status': 'ok', 'message': 'ARP Spoofing stopped'})

    return jsonify({'status': 'error', 'message': 'Unknown action'})
