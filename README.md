# LNSM - Lightweight Network Security Monitor

## Abstract
The Lightweight Network Security Monitor (LNSM) is a lightweight, real-time Intrusion Detection System (IDS) and Network Traffic Analyzer designed specifically for local and edge environments. It captures, analyzes, and visualizes network telemetry to detect anomalous behavior, brute force attempts, UDP port scans, and potential data exfiltration events in real-time.

## System Architecture
The application is built on a modular architecture to ensure separation of concerns and high performance during heavy network traffic analysis:
1. **Packet Sniffer (`sensor.py`)**: Utilizes raw OS sockets to capture incoming and outgoing TCP/UDP/ICMP packets at the network layer. This runs as a highly optimized background producer-consumer queue to prevent packet dropping.
2. **Persistence Layer (`database.py`)**: An SQLite3 database operating in WAL (Write-Ahead Logging) mode, enabling high-throughput concurrent reads and writes. Traffic telemetry is batched and flushed asynchronously to prevent disk I/O bottlenecks.
3. **Backend API (`app.py`)**: A Flask-based REST API that serves live telemetry, security alerts, and threat geolocation data to the frontend.
4. **Frontend Dashboard (`dashboard.html`)**: A Cyberpunk-themed, responsive, real-time dashboard built with vanilla JavaScript, HTML5, and Chart.js.

## Security Heuristics Implemented
LNSM employs deterministic heuristic algorithms to identify specific threat signatures:
* **Brute Force Detection**: Triggers when a single external IP address establishes excessive rapid connections (e.g., >50 packets within a 60-second sliding window) to a specific destination port (e.g., Port 22/SSH, Port 3389/RDP).
* **UDP Port Scanning**: Triggers when an external IP address probes a high number of unique UDP ports across the local machine within a sliding window, indicating reconnaissance.
* **ICMP Flooding**: Detects Ping-of-Death or standard ICMP flood DoS (Denial of Service) attacks by monitoring the volume of ICMP packets from a single origin.
* **Data Exfiltration Detection**: Triggers when the local machine begins uploading a massive, sustained volume of packets to a non-whitelisted external IP address, potentially indicating unauthorized data transfer or a compromised background process.

## Key Features
- **Live Threat Geolocation**: Automatically queries IP-API to determine the country of origin for active threats, displaying the corresponding national flag on the dashboard.
- **Active OS Firewall Integration**: Includes an actionable "Block" button on the dashboard that interfaces directly with Windows Defender Firewall via Powershell to establish a hard block against the IP at the OS level.
- **Dynamic Noise Filtering**: Safely ignores benign background traffic (such as Google services, Microsoft telemetry, and local subnets) to prevent dashboard flooding. This can be toggled via "Safe Mode".

## Installation & Usage
1. Ensure Python 3.8+ is installed on a Windows environment.
2. Install the required dependencies: `pip install -r requirements.txt`
3. Launch your command prompt as **Administrator** (Required for raw sockets and firewall modification).
4. Launch the application: `python app.py` (The packet sniffer will start automatically in the background).
5. Navigate to `http://localhost:5001` in your web browser.

## Disclaimer
This project is for educational and academic purposes. Never deploy raw socket sniffers in an enterprise environment without explicit authorization.
