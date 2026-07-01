import sqlite3
import os

def wipe_database():
    try:
        conn = sqlite3.connect('lnsm_security.db')
        
        # 1. Delete all traffic history
        conn.execute("DELETE FROM traffic_logs")
        
        # 2. Delete all security alerts
        conn.execute("DELETE FROM security_alerts")
        
        conn.commit()
        conn.close()
        print("Database successfully wiped clean! (All traffic and alerts deleted)")
    except Exception as e:
        print(f"Error wiping database: {e}")

if __name__ == '__main__':
    wipe_database()
