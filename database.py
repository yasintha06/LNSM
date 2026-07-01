"""
database.py - Persistence Layer
LNSM System - B00971364
"""

import sqlite3
import threading

from config import is_ignored_ip, load_settings

DB_PATH = "lnsm_security.db"


class Database:
    """
    Handles all SQLite persistence for the LNSM application.
    
    Utilizes SQLite in WAL (Write-Ahead Logging) mode to permit highly concurrent
    reads (from the Flask API) and writes (from the Packet Sensor) simultaneously
    without database locking issues.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.create_function("is_ignored", 1, is_ignored_ip)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip    TEXT,
                dest_ip   TEXT,
                dest_port INTEGER,
                protocol  TEXT,
                tcp_flags TEXT
            );
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                rule_name TEXT,
                src_ip TEXT,
                severity TEXT,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS geoip_cache (
                ip TEXT PRIMARY KEY,
                flag TEXT,
                country TEXT
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp
                ON traffic_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
                ON security_alerts(timestamp);
        """)
        conn.commit()
        conn.close()
        print("[Database] Initialised.")

    def insert_telemetry_batch(self, batch):
        """
        Inserts a batch of network packet metadata into the database.
        
        Args:
            batch (list): A list of dictionaries containing packet metadata.
        """
        rows = [
            (m["timestamp"], m["src_ip"], m["dest_ip"],
             m["dest_port"], m["protocol"], m["tcp_flags"])
            for m in batch
        ]
        with self._lock:
            conn = self._get_conn()
            conn.executemany(
                """INSERT INTO traffic_logs
                   (timestamp,src_ip,dest_ip,dest_port,protocol,tcp_flags)
                   VALUES (?,?,?,?,?,?)""", rows)
            conn.commit()
            conn.close()

    def insert_alert(self, alert):
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """INSERT INTO security_alerts
                   (timestamp,rule_name,src_ip,severity,detail)
                   VALUES (?,?,?,?,?)""",
                (alert["timestamp"], alert["rule_name"],
                 alert["src_ip"], alert["severity"], alert["detail"]))
            conn.commit()
            conn.close()

    def _get_geo_info(self, ip, conn):
        from config import is_ignored_ip
        if is_ignored_ip(ip) or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
            return ""
            
        row = conn.execute("SELECT flag, country FROM geoip_cache WHERE ip = ?", (ip,)).fetchone()
        if row:
            return f" {row['flag']}" if row['flag'] else ""
            
        import urllib.request, json
        try:
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=country,countryCode", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success' or data.get('countryCode'):
                    cc = data.get('countryCode', '')
                    flag = "".join(chr(ord(c) + 127397) for c in cc) if cc else ""
                    country = data.get('country', '')
                    conn.execute("INSERT OR IGNORE INTO geoip_cache (ip, flag, country) VALUES (?, ?, ?)", (ip, flag, country))
                    conn.commit()
                    return f" {flag}"
        except Exception:
            pass
            
        conn.execute("INSERT OR IGNORE INTO geoip_cache (ip, flag, country) VALUES (?, ?, ?)", (ip, "", ""))
        conn.commit()
        return ""

    def get_alerts(self, limit=50):
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT timestamp, rule_name, src_ip, severity, detail 
               FROM security_alerts ORDER BY timestamp DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        
        alerts = []
        for r in rows:
            d = dict(r)
            d['geo_flag'] = self._get_geo_info(d['src_ip'], conn).strip()
            d['is_blocked'] = self.is_ip_blocked(d['src_ip'], conn)
            alerts.append(d)
            
        conn.close()
        return alerts

    def get_recent_alerts(self, limit=100):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM security_alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_traffic_last_60s(self):
        from datetime import datetime, timedelta
        conn = self._get_conn()
        bound = (datetime.now() - timedelta(seconds=60)).isoformat()
        settings = load_settings()
        if settings.get("safe_mode", False):
            rows = conn.execute("""
                SELECT strftime('%H:%M:%S', timestamp) as second,
                       COUNT(*) as count
                FROM   traffic_logs
                WHERE  timestamp >= ? AND (NOT is_ignored(src_ip) OR NOT is_ignored(dest_ip))
                GROUP  BY second ORDER BY second ASC
            """, (bound,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT strftime('%H:%M:%S', timestamp) as second,
                       COUNT(*) as count
                FROM   traffic_logs
                WHERE  timestamp >= ?
                GROUP  BY second ORDER BY second ASC
            """, (bound,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_recent_traffic(self, limit=25):
        conn = self._get_conn()
        settings = load_settings()
        if settings.get("safe_mode", False):
            rows = conn.execute(
                """SELECT timestamp,src_ip,dest_ip,dest_port,protocol,tcp_flags
                   FROM traffic_logs 
                   WHERE NOT is_ignored(src_ip) OR NOT is_ignored(dest_ip)
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,)).fetchall()
        else:
            rows = conn.execute(
                """SELECT timestamp,src_ip,dest_ip,dest_port,protocol,tcp_flags
                   FROM traffic_logs ORDER BY timestamp DESC LIMIT ?""",
                (limit,)).fetchall()
                
        traffic = []
        for r in rows:
            d = dict(r)
            if not settings.get("safe_mode", False) or not d['src_ip'].startswith('192.168.'):
                d['geo_flag'] = self._get_geo_info(d['src_ip'], conn).strip()
                d['is_blocked'] = self.is_ip_blocked(d['src_ip'], conn)
            else:
                d['geo_flag'] = ""
                d['is_blocked'] = False
            traffic.append(d)
            
        conn.close()
        return traffic

    def block_ip(self, ip):
        """
        Blocks an IP address at both the software and OS firewall levels.
        
        Attempts to run a PowerShell command to create a Windows Defender Firewall 
        block rule. If the application is not running as Administrator, this will 
        fail gracefully and fall back to purely software-level database blocking.
        
        Args:
            ip (str): The IP address to block.
        """
        import subprocess
        
        # 1. OS-Level Windows Firewall Block (requires Admin)
        try:
            ps_command = (
                f"New-NetFirewallRule -DisplayName 'LNSM Block {ip}' "
                f"-Direction Inbound -Action Block -RemoteAddress {ip}"
            )
            # CREATE_NO_WINDOW (0x08000000) prevents the console flashing
            result = subprocess.run(
                ["powershell.exe", "-Command", ps_command],
                capture_output=True,
                text=True,
                creationflags=0x08000000
            )
            if result.returncode != 0:
                if "Access is denied" in result.stderr:
                    print(f"[Firewall] Warning: Administrator privileges required to block {ip} at OS level.")
                else:
                    print(f"[Firewall] Error blocking {ip}: {result.stderr}")
            else:
                print(f"[Firewall] Successfully blocked {ip} in Windows Defender.")
        except Exception as e:
            print(f"[Firewall] Integration exception: {e}")

        # 2. Software-Level Database Block
        conn = self._get_conn()
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
        conn.commit()
        conn.close()
        
    def is_ip_blocked(self, ip, conn=None):
        should_close = False
        if not conn:
            conn = self._get_conn()
            should_close = True
            
        row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        
        if should_close:
            conn.close()
            
        return bool(row)

    def get_stats(self):
        conn = self._get_conn()
        from config import load_settings, DEFAULT_IGNORED_PREFIXES
        settings = load_settings()
        
        # Performance Optimization: Raw COUNT(*) is O(1) in SQLite. 
        # Using the is_ignored() Python function inside SQL causes O(N) evaluation,
        # which crashes the API when the DB reaches 300,000+ packets.
        visible_packets = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
            
        total_alerts   = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
        critical_count = conn.execute(
            "SELECT COUNT(*) FROM security_alerts WHERE severity='CRITICAL'"
        ).fetchone()[0]
        top_ip_row = conn.execute(
            """SELECT src_ip, COUNT(*) as c FROM security_alerts
               GROUP BY src_ip ORDER BY c DESC LIMIT 1"""
        ).fetchone()
        
        ignored_ips = len(settings.get("ignored_ips", [])) + len(DEFAULT_IGNORED_PREFIXES)
        
        top_threat = None
        if top_ip_row:
            top_ip_str = dict(top_ip_row)["src_ip"]
            geo = self._get_geo_info(top_ip_str, conn).strip()
            top_threat = {
                "ip": top_ip_str,
                "geo_flag": geo
            }
            
        conn.close()
        return {
            "total_packets":  visible_packets,
            "total_alerts":   total_alerts,
            "critical_count": critical_count,
            "top_threat_ip":  top_threat,
            "ignored_ips_count": ignored_ips
        }

    def get_protocol_breakdown(self):
        conn = self._get_conn()
        settings = load_settings()
        if settings.get("safe_mode", False):
            rows = conn.execute(
                """SELECT protocol, COUNT(*) as count FROM traffic_logs
                   WHERE timestamp >= datetime('now', '-5 minutes')
                   AND (NOT is_ignored(src_ip) OR NOT is_ignored(dest_ip))
                   GROUP BY protocol"""
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT protocol, COUNT(*) as count FROM traffic_logs
                   WHERE timestamp >= datetime('now', '-5 minutes')
                   GROUP BY protocol"""
            ).fetchall()
        conn.close()
        return [{"protocol": r["protocol"], "count": r["count"]} for r in rows]

    def export_alerts_csv(self):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM security_alerts ORDER BY timestamp DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
