import sqlite3
import time
from datetime import datetime

DB_PATH = "lnsm_security.db"

def inject_fake_attack():
    conn = sqlite3.connect(DB_PATH)
    
    # 1. Generate fake traffic from a "malicious" external IP
    malicious_ip = "185.15.59.224"
    print(f"Injecting fake traffic from {malicious_ip}...")
    
    for _ in range(50):
        timestamp = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO traffic_logs (timestamp, src_ip, dest_ip, dest_port, protocol, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, malicious_ip, "192.168.1.100", 22, "TCP", "S"))
        time.sleep(0.01)
        
    # 2. Trigger a fake security alert
    print("Triggering Critical BRUTE_FORCE alert...")
    conn.execute("""
        INSERT INTO security_alerts (timestamp, rule_name, src_ip, severity, detail)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), "BRUTE_FORCE", malicious_ip, "CRITICAL", "Detected 50 rapid connection attempts to Port 22 (SSH)"))

    conn.commit()
    conn.close()
    
    print("Attack simulation complete! Check your dashboard.")

if __name__ == "__main__":
    inject_fake_attack()
