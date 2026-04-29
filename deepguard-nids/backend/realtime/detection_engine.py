"""
DeepGuard NIDS - Real-Time Traffic Simulation Engine
Generates realistic network traffic events for demonstration and testing.
"""

import random
import time
import threading
import datetime
import os
import csv

# Realistic IP ranges
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 50)]
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.12", "185.220.101.33", "91.243.80.72",
    "45.33.32.156", "104.248.50.87", "157.245.218.11", "64.225.8.195",
    "178.128.83.165", "159.89.173.104", "142.93.115.42", "167.172.164.81",
    "206.189.98.72", "134.209.152.36", "68.183.44.143", "165.22.49.204",
    "10.0.0.5", "10.0.0.12", "172.16.0.8", "172.16.0.15",
    "8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9",
]

ATTACKER_IPS = [
    "185.220.101.33", "91.243.80.72", "45.33.32.156",
    "178.128.83.165", "134.209.152.36", "206.189.98.72"
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]

NORMAL_PORTS = [80, 443, 8080, 53, 993, 995, 587, 25, 110, 143]
ATTACK_PORT_SETS = {
    "DoS": [80, 443, 8080, 53],
    "DDoS": [80, 443, 8080, 53, 22],
    "Brute Force": [22, 23, 3389, 21, 3306, 1433],
    "Port Scan": list(range(20, 1024)),
    "Botnet": [6667, 6668, 4444, 5555, 8888],
    "Web Attack": [80, 443, 8080, 8443],
    "Infiltration": [135, 139, 445, 4444, 5555]
}


class TrafficSimulator:
    """Generates realistic network traffic events."""

    def __init__(self, model_engine, on_event_callback=None):
        self.model_engine = model_engine
        self.on_event = on_event_callback
        self._running = False
        self._thread = None
        self._event_count = 0
        self._attack_count = 0
        self.use_real_data = False
        self.real_data = []
        self.current_data_idx = 0
        self._load_real_data()

    def _load_real_data(self):
        try:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            data_path = os.path.join(base_dir, "backend", "data", "real_traffic_stream.csv")
            if os.path.exists(data_path):
                with open(data_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    self.real_data = list(reader)
                if self.real_data:
                    self.use_real_data = True
                    print(f"[SIM] Loaded {len(self.real_data)} real traffic records for simulation.")
            else:
                print(f"[SIM] Real traffic stream not found at {data_path}. Falling back to random simulation.")
        except Exception as e:
            print(f"[SIM] Error loading real data: {e}. Falling back to random simulation.")

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("[SIM] Traffic simulation started.")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        print("[SIM] Traffic simulation stopped.")

    @property
    def is_running(self):
        return self._running

    def _run_loop(self):
        while self._running:
            try:
                event = self._generate_event()
                if self.on_event:
                    self.on_event(event)
                self._event_count += 1
                if event.get("is_attack"):
                    self._attack_count += 1
            except Exception as e:
                print(f"[SIM] Error: {e}")
            time.sleep(random.uniform(0.5, 1.5))

    def _generate_event(self):
        """Generate a single traffic event."""
        if self.use_real_data and self.real_data:
            row = self.real_data[self.current_data_idx]
            self.current_data_idx = (self.current_data_idx + 1) % len(self.real_data)
            
            label = row.get("label", "Normal")
            is_attack_traffic = label != "Normal"
            
            # Reconstruct basic UI features from real row
            proto_val = float(row.get("protocol", 0))
            if proto_val == 0: protocol = "TCP"
            elif proto_val == 1: protocol = "UDP"
            else: protocol = "ICMP"
            
            packet_size = int(float(row.get("src_bytes", 64)))
            
            if is_attack_traffic:
                src_ip = random.choice(ATTACKER_IPS)
                dst_ip = random.choice(INTERNAL_IPS)
                dst_port = random.choice(ATTACK_PORT_SETS.get(label, ATTACK_PORT_SETS["DoS"]))
            else:
                src_ip = random.choice(INTERNAL_IPS)
                dst_ip = random.choice(EXTERNAL_IPS)
                dst_port = random.choice(NORMAL_PORTS)
                
            src_port = random.randint(1024, 65535)
            
            packet_features = {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_size": packet_size,
                "real_features": {
                    "protocol": proto_val,
                    "src_bytes": float(row.get("src_bytes", 0)),
                    "dst_bytes": float(row.get("dst_bytes", 0)),
                    "duration": float(row.get("duration", 0)),
                    "count": float(row.get("count", 0)),
                    "srv_count": float(row.get("srv_count", 0))
                }
            }
        else:
            is_attack_traffic = random.random() < 0.30  # 30% attack probability

            if is_attack_traffic:
                attack_type = random.choice(list(ATTACK_PORT_SETS.keys()))
                src_ip = random.choice(ATTACKER_IPS)
                dst_ip = random.choice(INTERNAL_IPS)
                dst_port = random.choice(ATTACK_PORT_SETS[attack_type])
                protocol = self._get_attack_protocol(attack_type)
                packet_size = self._get_attack_packet_size(attack_type)
                src_port = random.randint(1024, 65535)
            else:
                src_ip = random.choice(INTERNAL_IPS)
                dst_ip = random.choice(EXTERNAL_IPS)
                dst_port = random.choice(NORMAL_PORTS)
                protocol = random.choice(["TCP", "TCP", "TCP", "UDP"])  # TCP heavy
                packet_size = random.randint(40, 1460)
                src_port = random.randint(1024, 65535)

            packet_features = {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_size": packet_size
            }
        # Run prediction
        result = self.model_engine.predict(packet_features)

        event = {
            **packet_features,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "is_attack": result["is_attack"],
            "severity": result["severity"],
            "model_used": result["model_used"],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        return event

    def _get_attack_protocol(self, attack_type):
        protos = {
            "DoS": "TCP", "DDoS": random.choice(["TCP", "UDP"]),
            "Brute Force": "TCP", "Port Scan": "TCP",
            "Botnet": "TCP", "Web Attack": "TCP",
            "Infiltration": "TCP"
        }
        return protos.get(attack_type, "TCP")

    def _get_attack_packet_size(self, attack_type):
        sizes = {
            "DoS": random.randint(1200, 1500),
            "DDoS": random.randint(1000, 1500),
            "Brute Force": random.randint(100, 500),
            "Port Scan": random.randint(40, 120),
            "Botnet": random.randint(50, 300),
            "Web Attack": random.randint(500, 2000),
            "Infiltration": random.randint(800, 1500)
        }
        return sizes.get(attack_type, random.randint(64, 1460))

    def get_stats(self):
        return {
            "total_events": self._event_count,
            "attack_events": self._attack_count,
            "is_running": self._running
        }
