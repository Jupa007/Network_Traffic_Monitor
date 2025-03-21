# Network Traffic Monitor - Developed by Ahmed Adel Mohamed Abdelbar
# This tool monitors network traffic, detects suspicious activity, and logs data every 24 hours.
# Created with ❤️ by Ahmed Adel Mohamed Abdelbar

import os
import sys
import time
import json
import asyncio
import platform
import logging
import socket

# Help function
def show_help():
    help_text = """
    Network Traffic Monitor - Developed by Ahmed Adel Mohamed Abdelbar
    ---------------------------------------------------------------
    This tool monitors network traffic, detects suspicious activity, and logs data every 24 hours.
    
    Usage:
        python network_monitor.py [options]
    
    Options:
        -h, --help       Show this help message and exit
    
    Features:
        - Real-time traffic monitoring
        - Suspicious activity detection
        - Logs stored every 24 hours
        - Customizable log directory
    """
    print(help_text)
    sys.exit(0)

# Check if help flag is provided
if "-h" in sys.argv or "--help" in sys.argv:
    show_help()

# Allow user to specify log directory
LOG_DIR = input("Enter the log directory path: ").strip()
if not LOG_DIR:
    LOG_DIR = os.path.join(os.getenv('APPDATA'), 'NetworkMonitorLogs') if platform.system() == "Windows" else "/var/log/network_monitor"
os.makedirs(LOG_DIR, exist_ok=True)
print(f"Logging directory: {LOG_DIR}")

# Configure logging to write to both file and console
LOG_FILE = os.path.join(LOG_DIR, "network_monitor.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

# Alert system webhook (change as needed)
ALERT_WEBHOOK = "http://your-alert-system.com/webhook"
traffic_data = []
lock = asyncio.Lock()
packet_queue = asyncio.Queue(maxsize=1000)  # Prevent queue overflow

# Get local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logging.error(f"Failed to get local IP: {e}")
        return "Unknown"

# Analyze packets and detect anomalies
async def analyze_packet():
    while True:
        packet = await packet_queue.get()
        traffic_info = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": get_local_ip(),
            "dst_ip": "Unknown",
            "protocol": "Unknown",
            "length": len(str(packet)),
            "status": "Normal"
        }

        log_message = f"[LOG] {json.dumps(traffic_info, indent=2)}"
        logging.info(log_message)

        # Mark suspicious traffic with improved threshold
        if traffic_info["length"] > 500:
            traffic_info["status"] = "Suspicious"
            await send_alert(traffic_info)

        async with lock:
            traffic_data.append(traffic_info)
        packet_queue.task_done()

# Save logs periodically without stopping the program
async def save_logs():
    while True:
        await asyncio.sleep(86400)  # Every 24 hours
        async with lock:
            if traffic_data:
                filename = os.path.join(LOG_DIR, f"network_log_{time.strftime('%Y-%m-%d_%H-%M-%S')}.json")
                with open(filename, "w") as log_file:
                    json.dump(traffic_data, log_file, indent=4)
                logging.info(f"[INFO] Log file saved: {filename}")
                traffic_data.clear()

# Send alerts for suspicious activity
async def send_alert(traffic_info):
    try:
        alert_data = {"message": "Suspicious Traffic Detected", "data": traffic_info}
        logging.warning("[ALERT] Suspicious traffic detected and reported!")
    except Exception as e:
        logging.error(f"[ERROR] Failed to send alert: {e}")

# Simulate packet sniffing
async def simulate_packet_sniffing():
    count = 0
    while True:
        packet = f"Simulated Packet Data {count}"
        await packet_queue.put(packet)
        count += 1
        await asyncio.sleep(0.1)

# Main event loop
async def main():
    asyncio.create_task(save_logs())
    for _ in range(3):  # Run multiple packet analyzers in parallel
        asyncio.create_task(analyze_packet())
    asyncio.create_task(simulate_packet_sniffing())
    while True:
        await asyncio.sleep(1)  # Keep the event loop running

if __name__ == "__main__":
    asyncio.run(main())