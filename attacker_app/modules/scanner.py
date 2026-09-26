"""
Nmap Network Scanner Module
Wraps python-nmap to provide multiple scan types with real-time progress.
For educational/ethical hacking purposes only.
"""
import nmap
import time
import threading
import re

class ScannerModule:
    # ─── Scan profiles ──────────────────────────────────────
    SCAN_PROFILES = {
        'quick':      {'name': 'Quick Scan',        'args': '-T4 -F',                   'desc': 'Fast scan of top 100 ports'},
        'full':       {'name': 'Full Port Scan',     'args': '-T4 -p 1-65535',           'desc': 'Scan all 65535 TCP ports'},
        'service':    {'name': 'Service Detection',  'args': '-sV --version-intensity 5','desc': 'Detect service versions'},
        'os':         {'name': 'OS Detection',       'args': '-O --osscan-guess',        'desc': 'Identify operating system'},
        'aggressive': {'name': 'Aggressive Scan',    'args': '-A -T4',                   'desc': 'OS, version, scripts, traceroute'},
    }

    def __init__(self):
        self.running = False
        self.scanner = nmap.PortScanner()
        self.results = None
        self.thread = None
    def _emit(self, callback, phase, message, target, scan_type, profile_name, start_time, extra=None):
        """Helper to standardize callback emissions."""
        if not callback: return
        data = {
            'phase': phase,
            'message': message,
            'target': target,
            'scan_type': scan_type,
            'profile_name': profile_name,
            'elapsed': round(time.time() - start_time, 1)
        }
        if extra: data.update(extra)
        callback(data)


    def start_scan(self, target, scan_type='quick', ports=None, callback=None):
        """
        Launch an nmap scan in background.
        callback(progress_dict) is called with progress updates.
        """
        if self.running:
            return False

        profile = self.SCAN_PROFILES.get(scan_type, self.SCAN_PROFILES['quick'])
        self.running = True
        self.results = None
        self.scanner = nmap.PortScanner()

        def run():
            start_time = time.time()
            try:
                # 1. Build Arguments
                arguments = profile['args']
                if ports and scan_type != 'udp':
                    arguments = arguments.replace('-F', '').strip()
                    arguments = re.sub(r'-p\s*[\d\-,]+', '', arguments).strip()
                    arguments += f' -p {ports}'

                # 2. Notify Start
                self._emit(callback, 'starting', f'Initializing {profile["name"]}...', target, scan_type, profile['name'], start_time)

                print(f"[*] [Scanner] Executing: nmap {arguments} {target}")
                self.scanner.scan(hosts=target, arguments=arguments)

                # 3. Handle Cancellation
                if not self.running:
                    print("[*] [Scanner] Scan cancelled by user.")
                    self._emit(callback, 'cancelled', 'Scan cancelled by user.', target, scan_type, profile['name'], start_time)
                    return

                # 4. Parse & Success
                elapsed = round(time.time() - start_time, 1)
                parsed = self._parse_results(target)
                self.results = parsed
                
                print(f"[+] [Scanner] Scan complete in {elapsed}s. Found {parsed['summary']['total_ports']} open ports.")
                self._emit(callback, 'complete', 
                          f'Scan complete in {elapsed}s — {parsed["summary"]["total_ports"]} ports found.', 
                          target, scan_type, profile['name'], start_time, {'results': parsed, 'elapsed': elapsed})

            except (nmap.PortScannerError, Exception) as e:
                print(f"[-] [Scanner] Error: {e}")
                self._emit(callback, 'error', f'Scanner error: {str(e)}', target, scan_type, profile['name'], start_time, {'progress': 0})
            finally:
                self.running = False

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        return True

    def _parse_results(self, target):
        """Parse nmap results into a structured dict (Simplified)."""
        hosts = []
        hosts_up = 0
        total_ports = 0

        for host in self.scanner.all_hosts():
            data = self.scanner[host]
            if data.state() == 'up': hosts_up += 1
            
            # Simple port list comprehension
            ports = []
            for proto in data.all_protocols():
                for port, info in data[proto].items():
                    ports.append({
                        'port': port,
                        'protocol': proto,
                        'state': info.get('state', 'unknown'),
                        'service': info.get('name', 'unknown'),
                        'version': info.get('version', ''),
                        'product': info.get('product', '')
                    })
                    total_ports += 1

            hosts.append({
                'ip': host,
                'hostname': data.hostnames()[0]['name'] if data.hostnames() else '',
                'state': data.state(),
                'os_matches': [{'name': m['name'], 'accuracy': m['accuracy']} for m in data.get('osmatch', [])[:1]],
                'ports': ports
            })

        if not hosts:
            hosts.append({'ip': target, 'state': 'down', 'ports': []})

        return {
            'hosts': hosts,
            'summary': {
                'total_hosts': len(hosts),
                'hosts_up': hosts_up,
                'total_ports': total_ports
            }
        }

    def stop(self):
        """Cancel a running scan."""
        self.running = False
        try:
            if self.scanner and hasattr(self.scanner, '_process'):
                # python-nmap internal process handle
                if self.scanner._process:
                    self.scanner._process.kill()
        except Exception:
            pass

    def get_results(self):
        """Return the last scan results."""
        return self.results

# Instance globale
scanner_module = ScannerModule()
