from flask import Blueprint, request, jsonify
import threading
from extensions import socketio
from state import active_attacks, stats, attack_stats, add_history, broadcast_status
from modules import brute_forcer

bruteforce_bp = Blueprint('bruteforce', __name__)

@bruteforce_bp.route('/api/attack/bruteforce', methods=['POST'])
def bruteforce_attack():
    action = request.json.get('action')

    if action == 'start':
        if active_attacks['bruteforce']:
            return jsonify({'status': 'error', 'message': 'Already running'})

        # Sanitize Target for SSH
        raw_target = request.json.get('target', '127.0.0.1')
        username = request.json.get('username', 'admin')
        passwords = request.json.get('passwords', [])
        
        # Strip protocol if user pasted a URL
        target = raw_target.replace('http://', '').replace('https://', '').split('/')[0]

        if not passwords:
            passwords = brute_forcer.brute_forcer_module.get_default_passwords()

        total = len(passwords)
        active_attacks['bruteforce'] = True
        stats['attacks'] += 1
        broadcast_status()

        def bf_callback(result):
            # Transform module result to UI event
            socketio.emit('bf_update', {
                'attempts': result['attempt'],
                'total': total,
                'progress': int((result['attempt'] / total) * 100) if total else 0,
                'current_password': result['password'],
                'found': result['success'],
                'cracked_password': result['password'] if result['success'] else None,
                'error': result['error'],
                'completed': result['completed']
            })
            
            if result['success']:
                stats['successes'] += 1
                add_history('BRUTE_FORCE', target, 'cracked')
            
            if result['completed'] or result['success'] or (result['attempt'] >= total):
                if not result.get('completed') and not result['success'] and result['attempt'] >= total:
                     # Finished list without success
                     pass
                
                # State reset is now handled by the thread wrapper (run_attack_safe)
                # to avoid race conditions.

        def run_attack_safe():
            try:
                # Run the attack (blocking call within this thread)
                brute_forcer.brute_forcer_module.start(target, username, passwords, callback=bf_callback)
            except Exception as e:
                print(f"[!] Error in brute force thread: {e}")
            finally:
                # Ensure state is reset regardless of how start() finished
                print("[*] Brute force thread finished. Resetting state.")
                active_attacks['bruteforce'] = False
                broadcast_status()

        t = threading.Thread(
            target=run_attack_safe,
            daemon=True
        )
        t.start()
        
        return jsonify({'status': 'ok', 'message': f'SSH Brute force started on {target}'})

    elif action == 'stop':
        brute_forcer.brute_forcer_module.stop()
        active_attacks['bruteforce'] = False
        broadcast_status()
        return jsonify({'status': 'ok', 'message': 'Brute force stopped'})

    return jsonify({'status': 'error', 'message': 'Unknown action'})
