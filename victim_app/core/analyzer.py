import time
from scapy.all import ARP, IP, TCP, ICMP, Ether
from collections import defaultdict, deque

class IDSAnalyzer:
    def __init__(self):
        # State for detection
        self.arp_table = {}  # IP -> MAC mapping
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'start_time': 0}) 
        self.auth_attempts = defaultdict(deque) # IP -> deque of timestamps
        
        # Configuration
        self.SCAN_THRESHOLD = 15
        self.BRUTE_FORCE_THRESHOLD = 5  # Reduced to 5 (User Request)
        self.BRUTE_FORCE_WINDOW = 20.0  # Reduced to 20s (User Request)

    def analyze_packet(self, packet):
        alerts = []
        packet_info = self._extract_info(packet)
        
        if not packet_info:
            return alerts, None

        curr_time = time.time()
        src_ip = packet[IP].src if packet.haslayer(IP) else None

        # 1. ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # is-at (reply)
            arp_src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            if arp_src_ip in self.arp_table:
                # If MAC changes for an existing IP
                if self.arp_table[arp_src_ip] != src_mac:
                    old_mac = self.arp_table[arp_src_ip]

                    alerts.append({
                        'type': 'ARP Poisoning',
                        'severity': 'HIGH',
                        'source': src_mac,
                        'message': f"ARP Conflict: {arp_src_ip} is at {src_mac} (was {old_mac})",
                        'analysis': f"MITM ATTEMPT: MAC Address Flapping detected. The host {arp_src_ip} is being claimed by multiple MAC addresses ({old_mac} vs {src_mac}). This indicates an active ARP Spoofing attack."
                    })
            
            self.arp_table[arp_src_ip] = src_mac

        # 2. TCP Analysis
        if packet.haslayer(TCP) and src_ip:
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            
            # --- SSH Brute Force Detection (Port 22) ---
            if dst_port == 22 and 'S' in str(flags):
                tracker = self.auth_attempts[src_ip] # deque
                tracker.append(curr_time)
                
                while tracker and curr_time - tracker[0] > self.BRUTE_FORCE_WINDOW:
                    tracker.popleft()
                
                # Check Threshold
                if len(tracker) >= self.BRUTE_FORCE_THRESHOLD:
                     # Alert every X attempts to avoid spam
                    if len(tracker) == self.BRUTE_FORCE_THRESHOLD or len(tracker) % 5 == 0: 
                        duration = tracker[-1] - tracker[0]
                        alerts.append({
                            'type': 'SSH Brute Force',
                            'severity': 'HIGH',
                            'source': src_ip,
                            'message': f"SSH Brute Force ({len(tracker)} attempts in {duration:.1f}s)",
                            'analysis': "Action: Dictionary attack on SSH."
                        })

            # --- Port Scan Detection ---
            # Track unique ports targeted by source
            if 'S' in str(flags):
                scan_tracker = self.port_scan_tracker[src_ip]
                # Reset if stale (> 1.0s)
                if curr_time - scan_tracker['start_time'] > 1.0:
                    scan_tracker['ports'].clear()
                    scan_tracker['start_time'] = curr_time
                
                scan_tracker['ports'].add(dst_port)

                if len(scan_tracker['ports']) > self.SCAN_THRESHOLD:
                     alerts.append({
                        'type': 'Nmap Scan',
                        'severity': 'MEDIUM',
                        'source': src_ip,
                        'message': f"Port Scanning Activity",
                        'analysis': "Action: Searching for open ports (likely Nmap)."
                    })
                     scan_tracker['ports'].clear()

        # 3. HTTP Scanner Detection
        if packet.haslayer(TCP) and packet.haslayer(IP) and packet[IP].len > 0:
            try:
                load = bytes(packet[TCP].payload).decode('utf-8', errors='ignore').lower()
                if any(x in load for x in ['nmap', 'sqlmap', 'nikto', 'gobuster']):
                     alerts.append({
                        'type': 'Web Scanner',
                        'severity': 'HIGH',
                        'source': packet[IP].src,
                        'message': "Web Vulnerability Scanner Detected",
                        'analysis': "Action: Tool signature found in HTTP traffic."
                    })
            except:
                pass

        return alerts, packet_info

    def _extract_info(self, packet):
        info = {'time': time.strftime('%H:%M:%S')}
        
        if packet.haslayer(Ether):
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst
            
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['proto'] = packet[IP].proto
            
        if packet.haslayer(TCP):
            info['sport'] = packet[TCP].sport
            info['dport'] = packet[TCP].dport
            info['flags'] = str(packet[TCP].flags)
        
        return info

    def analyze_http_request(self, method, path, remote_addr):
        """Called manually from Flask request hooks"""
        alerts = []
        curr_time = time.time()
        
        # 4. Brute Force Detection
        if method == 'POST' and 'login' in path:
            # Use a separate key prefix for HTTP to avoid collision with SSH if same IP
            key = f"HTTP_{remote_addr}"
            tracker = self.auth_attempts[key]
            
            tracker.append(curr_time)
             # Sliding Window: Remove timestamps older than WINDOW
            while tracker and curr_time - tracker[0] > self.BRUTE_FORCE_WINDOW:
                tracker.popleft()
            
            if len(tracker) >= self.BRUTE_FORCE_THRESHOLD:
                if len(tracker) == self.BRUTE_FORCE_THRESHOLD or len(tracker) % 5 == 0:
                    duration = tracker[-1] - tracker[0]
                    alerts.append({
                        'type': 'Brute Force',
                        'severity': 'HIGH',
                        'source': remote_addr,
                        'message': f"Web Brute Force ({len(tracker)} attempts in {duration:.1f}s)",
                        'analysis': "GUESS: Credential Stuffing against Login Page."
                    })
                
        return alerts
