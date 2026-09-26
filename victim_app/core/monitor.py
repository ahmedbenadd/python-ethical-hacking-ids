import time

class TrafficMonitor:
    def __init__(self):
        # Smart Filter State
        self.known_flows = set() # Stores 'srcIP:srcPort->dstIP:dstPort'
        self.throttle_state = {} # Stores 'key' -> timestamp
        self.NOISY_PORTS = {5000, 5001} 

    def should_show(self, info, has_alerts=False):
        """
        Decides if a packet should be visualized based on noise filters and throttling.
        """
        # 3. Alerts always override (We want to see the packet that caused an alert)
        if has_alerts:
            return True

        curr_time = time.time()
        
        # 1. ARP / Non-IP
        if 'proto' not in info or info.get('proto') == 1: # ARP or ICMP
             # Throttle ARP/ICMP updates from same source to once per 5 seconds
             throttle_key = f"L2_{info.get('src_mac')}_{info.get('proto')}"
             if curr_time - self.throttle_state.get(throttle_key, 0) > 5.0:
                 self.throttle_state[throttle_key] = curr_time
                 return True
             return False

        # 2. IP Traffic
        elif 'src_ip' in info and 'sport' in info:
            sport = info['sport']
            dport = info['dport']
            
            # Absolute Ignore Ports
            if sport in self.NOISY_PORTS or dport in self.NOISY_PORTS:
                return False
            
            flow_id = f"{info['src_ip']}:{sport}->{info['dst_ip']}:{dport}"
            flags = info.get('flags', '')
            
            # TCP: Show only SYN (Start) and FIN/RST (End)
            if info.get('proto') == 6: 
                if 'S' in flags: 
                    self.known_flows.add(flow_id)
                    return True
                elif 'F' in flags or 'R' in flags:
                    self.known_flows.discard(flow_id)
                    return True
                elif flow_id not in self.known_flows:
                     # Show 1 packet for unknown flow then mute
                    self.known_flows.add(flow_id)
                    return True
            
            # UDP/Other: Throttle flow to once every 10s
            else: 
                 if curr_time - self.throttle_state.get(flow_id, 0) > 10.0:
                     self.throttle_state[flow_id] = curr_time
                     return True
        
        return False
