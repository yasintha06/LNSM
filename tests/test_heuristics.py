import unittest
from unittest.mock import patch
import time
from sensor import run_heuristics, sliding_window, icmp_window, syn_window, udp_window, outbound_window, alerted_ips
from datetime import datetime

class MockDatabase:
    def __init__(self):
        self.alerts = []

    def insert_alert(self, alert):
        self.alerts.append(alert)

class TestHeuristics(unittest.TestCase):
    def setUp(self):
        # Clear shared state before each test
        sliding_window.clear()
        icmp_window.clear()
        syn_window.clear()
        udp_window.clear()
        outbound_window.clear()
        alerted_ips.clear()
        self.db = MockDatabase()

    def create_metadata(self, src, dest, port=None, proto=None, flags=None):
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src,
            "dest_ip": dest,
            "dest_port": port,
            "protocol": proto,
            "tcp_flags": flags
        }

    @patch('sensor.send_alert_email')
    def test_brute_force_detection(self, mock_email):
        attacker_ip = "1.2.3.4"
        # Simulate 200 rapid connections to port 22
        for _ in range(200):
            meta = self.create_metadata(attacker_ip, "192.168.0.50", port=22, proto="TCP")
            run_heuristics(meta, self.db)
            
        self.assertTrue(any(a["rule_name"] == "BRUTE_FORCE" for a in self.db.alerts))
        self.assertTrue(any(a["src_ip"] == attacker_ip for a in self.db.alerts))

    @patch('sensor.send_alert_email')
    def test_port_scan_detection(self, mock_email):
        attacker_ip = "5.6.7.8"
        # Probe 15 unique ports
        for port in range(1, 16):
            meta = self.create_metadata(attacker_ip, "192.168.0.50", port=port, proto="TCP")
            run_heuristics(meta, self.db)
            
        self.assertTrue(any(a["rule_name"] == "PORT_SCAN_DETECTED" for a in self.db.alerts))

    @patch('sensor.send_alert_email')
    def test_data_exfiltration(self, mock_email):
        local_ip = "127.0.0.1" # Whitelisted local IP
        malicious_dest = "9.9.9.9"
        
        for _ in range(200):
            meta = self.create_metadata(local_ip, malicious_dest, port=443, proto="TCP")
            run_heuristics(meta, self.db)
            
        self.assertTrue(any(a["rule_name"] == "DATA_EXFILTRATION" for a in self.db.alerts))
        # Exfiltration flags the destination as the threat
        self.assertTrue(any(a["src_ip"] == malicious_dest for a in self.db.alerts))

if __name__ == '__main__':
    unittest.main()
