from scapy.all import sniff
import threading
import queue

class TrafficSniffer:
    def __init__(self, interface=None, callback=None):
        self.interface = interface
        self.callback = callback
        self.running = False
        self.packet_queue = queue.Queue()

    def start(self):
        self.running = True
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        threading.Thread(target=self._process_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _sniff_loop(self):
        try:
            # Sniffing on interface if provided, else on default
            # Store 0 means don't keep packets in memory (prevents leak)
            sniff(iface=self.interface, prn=lambda x: self.packet_queue.put(x), store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"Sniffer Error: {e}")

    def _process_loop(self):
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                if self.callback:
                    self.callback(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Processing Error: {e}")
