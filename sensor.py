"""
sensor.py - Packet Capture Engine (Producer-Consumer Architecture)
LNSM System - B00971364
"""

import threading
import queue
import time
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from database import Database
from notifier import send_alert_email
from config import is_ignored_ip

# ── Configuration ─────────────────────────────────────────────────
SCAN_WINDOW_SECONDS   = 60   # Sliding window duration
PORT_SCAN_THRESHOLD   = 50   # Unique ports → port scan alert
BRUTE_FORCE_THRESHOLD = 1000 # Same-port hits → brute force alert (raised to reduce false positives)
SYN_FLOOD_THRESHOLD   = 500  # SYN packets in window → SYN flood alert
ICMP_FLOOD_THRESHOLD  = 200  # ICMP packets in window → ICMP flood alert
UDP_SCAN_THRESHOLD    = 50   # Unique UDP ports → UDP scan alert
BATCH_FLUSH_INTERVAL  = 2    # Seconds between DB batch writes
INTERFACE             = None # None = auto-select

# ── Whitelist ─────────────────────────────────────────────────────
def get_local_ip():
    """
    Attempts to determine the local machine's primary IPv4 address.
    
    This works by creating a dummy UDP socket and connecting to a public DNS 
    server (8.8.8.8) to see which network interface the OS routes the traffic through.
    
    Returns:
        str: The local IPv4 address, or '127.0.0.1' if disconnected.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# IPs and subnets that will NEVER trigger alerts.
# Add your router, trusted cloud services, and your own devices here.
WHITELIST_IPS = {
    "127.0.0.1",        # Localhost
    "192.168.0.1",      # Your router (common default)
    "192.168.1.1",      # Alternative router IP
    get_local_ip(),     # Automatically whitelist the machine running the app
}

# Whitelisted IP prefixes — any IP starting with these is ignored
WHITELIST_PREFIXES = (
    "20.190.",   # Microsoft (OneDrive, Teams, Azure AD)
    "20.189.",   # Microsoft
    "52.96.",    # Microsoft Exchange Online
    "52.97.",    # Microsoft
    "104.208.",  # Microsoft Azure
    "13.107.",   # Microsoft 365
    "40.96.",    # Microsoft
    "34.149.",   # Google Cloud
    "34.160.",   # Google Cloud
    "142.250.",  # Google services
    "172.217.",  # Google services
    "216.58.",   # Google services
    "151.101.",  # Fastly CDN
    "199.232.",  # Fastly CDN
)

def is_whitelisted(ip):
    """
    Checks whether a given IP address should be excluded from threat analysis.
    
    Args:
        ip (str): The IP address to check.
        
    Returns:
        bool: True if the IP is dynamically ignored via config or statically 
              whitelisted, otherwise False.
    """
    return is_ignored_ip(ip) or ip in WHITELIST_IPS

# ── Shared structures ─────────────────────────────────────────────
packet_queue        = queue.Queue()
sliding_window      = defaultdict(list)
icmp_window         = defaultdict(list)
syn_window          = defaultdict(list)
udp_window          = defaultdict(list)
outbound_window     = defaultdict(list)
sliding_window_lock = threading.Lock()
alerted_ips         = {}  # Cooldown tracker: { ip: last_alert_time }
ALERT_COOLDOWN      = 30  # Seconds before same IP can alert again
EXFILTRATION_THRESHOLD = 5000 # Packets per 10 seconds


_last_cleanup = 0
def _cooldown_ok(src_ip, rule):
    """
    Implements a cooldown mechanism to prevent alert flooding.
    
    Args:
        src_ip (str): The source IP address triggering the alert.
        rule (str): The name of the heuristic rule being triggered.
        
    Returns:
        bool: True if the alert is permitted to fire, False if it is 
              currently suppressed by the cooldown timer.
    """
    global _last_cleanup
    now = time.time()

    # Prevent memory leaks by cleaning up stale keys every 5 minutes
    if now - _last_cleanup > 300:
        stale_keys = [k for k, v in alerted_ips.items() if now - v > ALERT_COOLDOWN]
        for k in stale_keys:
            del alerted_ips[k]
        _last_cleanup = now

    key = f"{src_ip}:{rule}"
    if now - alerted_ips.get(key, 0) > ALERT_COOLDOWN:
        alerted_ips[key] = now
        return True
    return False


# ─────────────────────────────────────────────────────────────────
# PRODUCER
# ─────────────────────────────────────────────────────────────────
def packet_callback(packet):
    """
    The main callback invoked by scapy for each intercepted packet.
    
    Extracts the IP layer and L4 protocol headers (TCP/UDP/ICMP), formats the
    telemetry metadata, and pushes it onto the processing queue.
    
    Args:
        packet (scapy.packet.Packet): The intercepted raw network packet.
    """
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dest_ip = packet[IP].dst

    metadata = {
        "timestamp": datetime.now().isoformat(),
        "src_ip":    src_ip,
        "dest_ip":   dest_ip,
        "dest_port": None,
        "protocol":  None,
        "tcp_flags": None,
    }
    if packet.haslayer(TCP):
        metadata["dest_port"] = packet[TCP].dport
        metadata["protocol"]  = "TCP"
        metadata["tcp_flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        metadata["dest_port"] = packet[UDP].dport
        metadata["protocol"]  = "UDP"
    elif packet.haslayer(ICMP):
        metadata["protocol"]  = "ICMP"
    packet_queue.put(metadata)


def start_producer():
    """
    Initiates the scapy packet sniffer on the network interface.
    This function runs continuously and blocks the thread it operates on.
    """
    print("[Producer] Packet capture started.")
    sniff(
        filter="tcp or udp or icmp",
        prn=packet_callback,
        store=0,
        iface=INTERFACE
    )


# ─────────────────────────────────────────────────────────────────
# HEURISTICS ENGINE
# ─────────────────────────────────────────────────────────────────
def run_heuristics(metadata, db):
    """
    Analyzes packet metadata against defined security heuristics to detect anomalies.
    
    Evaluates:
      - Data Exfiltration (Massive outbound traffic)
      - Port Scans (Many unique ports queried)
      - Brute Force (High frequency of identical port hits)
      - SYN Floods (TCP SYN without ACK)
      - ICMP Floods (Ping of Death/DoS)
      - UDP Scans (High number of unique UDP port probes)
      
    Args:
        metadata (dict): The formatted packet telemetry.
        db (Database): The active database connection for logging alerts.
    """
    src_ip    = metadata["src_ip"]
    dest_port = metadata["dest_port"]
    protocol  = metadata["protocol"]
    tcp_flags = metadata["tcp_flags"]
    now       = time.time()
    ts        = metadata["timestamp"]

    # Skip whitelisted IPs — known-safe services never trigger alerts
    if is_whitelisted(src_ip):
        # Check for Data Exfiltration (if we are the source sending to an unknown destination)
        if src_ip in WHITELIST_IPS and not is_whitelisted(metadata["dest_ip"]):
            dest_ip = metadata["dest_ip"]
            with sliding_window_lock:
                outbound_window[dest_ip].append(now)
                outbound_window[dest_ip] = [ts2 for ts2 in outbound_window[dest_ip] if now - ts2 <= 10]
                if len(outbound_window[dest_ip]) >= EXFILTRATION_THRESHOLD:
                    if _cooldown_ok(dest_ip, "DATA_EXFILTRATION"):
                        alert = {
                            "timestamp": ts,
                            "rule_name": "DATA_EXFILTRATION",
                            "src_ip": dest_ip,  # Log the receiver as the threat IP
                            "severity": "CRITICAL",
                            "detail": f"Outbound data flood to {dest_ip} ({len(outbound_window[dest_ip])} pkts in 10s)"
                        }
                        db.insert_alert(alert)
                        print(f"[ALERT] DATA_EXFILTRATION to {dest_ip}")
                    outbound_window[dest_ip] = []
        return

    def fire_alert(rule, severity, detail):
        if not _cooldown_ok(src_ip, rule):
            return
        alert = {
            "timestamp": ts,
            "rule_name": rule,
            "src_ip":    src_ip,
            "severity":  severity,
            "detail":    detail,
        }
        db.insert_alert(alert)
        send_alert_email(rule, src_ip, detail)
        print(f"[ALERT] {rule} from {src_ip} — {detail}")

    with sliding_window_lock:

        # ── TCP rules ────────────────────────────────────────────
        if protocol == "TCP":
            sliding_window[src_ip].append((now, dest_port))
            sliding_window[src_ip] = [
                (ts2, p) for ts2, p in sliding_window[src_ip]
                if now - ts2 <= SCAN_WINDOW_SECONDS
            ]
            unique_ports = set(p for _, p in sliding_window[src_ip])
            same_port    = [p for _, p in sliding_window[src_ip] if p == dest_port]

            # Rule 1 — Port Scan
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                fire_alert(
                    "PORT_SCAN_DETECTED", "HIGH",
                    f"Contacted {len(unique_ports)} unique ports in {SCAN_WINDOW_SECONDS}s"
                )
                sliding_window[src_ip] = []

            # Rule 2 — Brute Force
            elif len(same_port) >= BRUTE_FORCE_THRESHOLD:
                fire_alert(
                    "BRUTE_FORCE", "HIGH",
                    f"{len(same_port)} rapid connections to port {dest_port}"
                )
                sliding_window[src_ip] = []

            # Rule 3 — SYN Flood
            if tcp_flags and "S" in tcp_flags and "A" not in tcp_flags:
                syn_window[src_ip].append(now)
                syn_window[src_ip] = [
                    t for t in syn_window[src_ip]
                    if now - t <= SCAN_WINDOW_SECONDS
                ]
                if len(syn_window[src_ip]) >= SYN_FLOOD_THRESHOLD:
                    fire_alert(
                        "SYN_FLOOD", "CRITICAL",
                        f"{len(syn_window[src_ip])} SYN packets in {SCAN_WINDOW_SECONDS}s"
                    )
                    syn_window[src_ip] = []

        # ── ICMP Flood ────────────────────────────────────────────
        elif protocol == "ICMP":
            icmp_window[src_ip].append(now)
            icmp_window[src_ip] = [
                t for t in icmp_window[src_ip]
                if now - t <= SCAN_WINDOW_SECONDS
            ]
            if len(icmp_window[src_ip]) >= ICMP_FLOOD_THRESHOLD:
                fire_alert(
                    "ICMP_FLOOD", "MEDIUM",
                    f"{len(icmp_window[src_ip])} ICMP packets in {SCAN_WINDOW_SECONDS}s"
                )
                icmp_window[src_ip] = []

        # ── UDP Scan ──────────────────────────────────────────────
        elif protocol == "UDP":
            udp_window[src_ip].append((now, dest_port))
            udp_window[src_ip] = [
                (ts2, p) for ts2, p in udp_window[src_ip]
                if now - ts2 <= SCAN_WINDOW_SECONDS
            ]
            unique_udp = set(p for _, p in udp_window[src_ip])
            if len(unique_udp) >= UDP_SCAN_THRESHOLD:
                fire_alert(
                    "UDP_SCAN_DETECTED", "MEDIUM",
                    f"Probed {len(unique_udp)} unique UDP ports in {SCAN_WINDOW_SECONDS}s"
                )
                udp_window[src_ip] = []


# ─────────────────────────────────────────────────────────────────
# CONSUMER
# ─────────────────────────────────────────────────────────────────
def start_consumer(db):
    """
    The background worker thread that drains the packet queue.
    
    This function retrieves packet metadata from the producer queue, runs
    heuristic analysis on each packet, and asynchronously batches database writes
    to maximize throughput and prevent disk I/O bottlenecks.
    
    Args:
        db (Database): The active database connection.
    """
    print("[Consumer] Analysis engine started.")
    telemetry_batch = []
    last_flush = time.time()
    while True:
        try:
            # Short timeout to allow frequent flush checks
            metadata = packet_queue.get(timeout=0.2)
            telemetry_batch.append(metadata)
            run_heuristics(metadata, db)
        except queue.Empty:
            pass

        now = time.time()
        if telemetry_batch and (now - last_flush >= BATCH_FLUSH_INTERVAL or len(telemetry_batch) >= 500):
            db.insert_telemetry_batch(telemetry_batch)
            print(f"[Consumer] Flushed {len(telemetry_batch)} packets to DB.")
            telemetry_batch = []
            last_flush = now


def start_sensor(db=None):
    if db is None:
        db = Database()
    consumer_thread = threading.Thread(target=start_consumer, args=(db,), daemon=True)
    consumer_thread.start()
    start_producer()


if __name__ == "__main__":
    start_sensor()