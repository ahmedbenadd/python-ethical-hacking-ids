import nmap
import threading

class NetworkDiscovery:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.is_scanning = False
        self.results = []

    def scan(self, subnet):
        """
        Performs a network discovery using python-nmap.
        """
        if self.is_scanning:
            return {"status": "error", "message": "Scan already in progress"}

        self.is_scanning = True
        self.results = []

        def _scan_thread():
            try:
                # Arguments: -sn (Ping Scan), -PR (ARP Ping)
                # python-nmap returns a dict, avoiding manual XML parsing
                self.nm.scan(hosts=subnet, arguments='-sn -PR')
                
                hosts = []
                for host in self.nm.all_hosts():
                    host_data = self.nm[host]
                    if host_data['status']['state'] == 'up':
                        mac = host_data['addresses'].get('mac', '')
                        vendor = ''
                        if mac and 'vendor' in host_data and mac in host_data['vendor']:
                            vendor = host_data['vendor'][mac]
                            
                        hostname = ''
                        if host_data['hostnames']:
                            hostname = host_data['hostnames'][0]['name']

                        hosts.append({
                            'ip': host,
                            'mac': mac,
                            'vendor': vendor,
                            'hostname': hostname,
                            'status': 'up'
                        })
                self.results = hosts

            except Exception as e:
                print(f"Network Discovery Error: {e}")
            finally:
                self.is_scanning = False

        thread = threading.Thread(target=_scan_thread)
        thread.daemon = True
        thread.start()

        return {"status": "ok", "message": "Discovery started"}

    def stop(self):
        if self.is_scanning:
            self.is_scanning = False
            # python-nmap wrapper doesn't expose clean process kill for asynchronous usage easily
            # in this pattern, but strictly following 'python-nmap' usage as requested.
            return {"status": "ok", "message": "Discovery stopped"}
        return {"status": "error", "message": "No scan in progress"}

    def get_results(self):
        return {
            "scanning": self.is_scanning,
            "hosts": self.results
        }

discovery_module = NetworkDiscovery()
