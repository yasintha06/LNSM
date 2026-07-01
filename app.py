"""
app.py - Flask Dashboard (Presentation Tier)
LNSM System - B00971364
"""

import csv
import io
import os
import socket
import threading
from datetime import datetime
from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS
from database import Database
from config import add_ignored_entry, load_settings, remove_ignored_entry, set_safe_mode
from sensor import start_sensor

app = Flask(__name__)
CORS(app)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

db  = Database()


def start_background_monitoring():
    """
    Initializes the network sensor thread securely.
    
    Ensures that the packet sniffing daemon is only spun up once per Flask 
    application context, preventing multiple socket bindings or database lockups.
    """
    if getattr(app, "_monitoring_started", False):
        return
    app._monitoring_started = True
    print("[App] Starting monitoring engine...")
    threading.Thread(target=start_sensor, args=(db,), daemon=True).start()


start_background_monitoring()

ALERT_TRANSLATIONS = {
    "PORT_SCAN_DETECTED": "A device (<b>{src_ip}</b>) is systematically probing ports on your network.",
    "BRUTE_FORCE":        "Repeated connection attempts from <b>{src_ip}</b> — possible brute-force attack.",
    "SYN_FLOOD":          "High-volume SYN packet flood from <b>{src_ip}</b> — possible DoS attack.",
    "ICMP_FLOOD":         "Excessive ping traffic from <b>{src_ip}</b> — possible ICMP flood.",
    "UDP_SCAN_DETECTED":  "UDP port probe detected from <b>{src_ip}</b>.",
}

SEVERITY_COLOURS = {
    "CRITICAL": "danger",
    "HIGH":     "warning",
    "MEDIUM":   "info",
    "LOW":      "secondary",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}




@app.route("/")
def dashboard():
    """
    Serves the main single-page application dashboard.
    Enforces strict cache-control headers so the dashboard always retrieves
    fresh telemetry from the backend.
    """
    response = Response(render_template('dashboard.html'))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/api/alerts")
def api_alerts():
    raw = db.get_recent_alerts()
    result = []
    for a in raw:
        tmpl = ALERT_TRANSLATIONS.get(a["rule_name"], "Security event from <b>{src_ip}</b>.")
        result.append({
            "timestamp":       a["timestamp"],
            "src_ip":          a["src_ip"],
            "rule_name":       a["rule_name"],
            "severity":        a["severity"],
            "severity_colour": SEVERITY_COLOURS.get(a["severity"], "secondary"),
            "severity_icon":   SEVERITY_ICONS.get(a["severity"], "⚠️"),
            "detail":          a["detail"],
            "message":         tmpl.format(src_ip=a["src_ip"]),
        })
    return jsonify(result)


@app.route("/api/traffic")
def api_traffic():
    return jsonify(db.get_traffic_last_60s())


@app.route("/api/recent_traffic")
def api_recent_traffic():
    return jsonify(db.get_recent_traffic())


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/protocol_breakdown")
def api_protocol_breakdown():
    return jsonify(db.get_protocol_breakdown())


@app.route('/api/demo_alert', methods=['POST'])
def demo_alert():
    db.insert_alert({
        "timestamp": datetime.now().isoformat(),
        "rule_name": "DEMO_TEST",
        "src_ip": "1.1.1.1",
        "severity": "CRITICAL",
        "detail": "This is a manually triggered demo alert."
    })
    return jsonify({"status": "success"})

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    """
    Blocks a specific IP address by calling the persistence layer's firewall 
    integration routine.
    
    Accepts:
        JSON Payload: {"ip": "1.2.3.4"}
    """
    data = request.json
    ip_to_block = data.get('ip')
    if ip_to_block:
        db.block_ip(ip_to_block)
        return jsonify({"status": "success", "message": f"{ip_to_block} blocked."})
    return jsonify({"status": "error", "message": "No IP provided."}), 400


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        value = payload.get("value")
        if action == "add":
            add_ignored_entry(value)
        elif action == "remove":
            remove_ignored_entry(value)
        elif action == "safe_mode":
            set_safe_mode(value)
        return jsonify(load_settings())
    return jsonify(load_settings())


@app.route("/api/export_csv")
def api_export_csv():
    rows = db.export_alerts_csv()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","timestamp","rule_name","src_ip","severity","detail"])
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=lnsm_alerts.csv"}
    )


def get_available_port(start_port=5000, max_port=5010):
    host = os.environ.get("HOST", "127.0.0.1")
    for port in range(start_port, max_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    return int(os.environ.get("PORT", str(start_port)))


if __name__ == "__main__":
    start_background_monitoring()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", str(get_available_port())))
    app.run(host=host, port=port, debug=False, threaded=True)
