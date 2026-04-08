import time
import json
import os
from collections import defaultdict

HONEYPOT_LOG = "C:/xampp/htdocs/honeypot_tes.log"
IDS_LOG = "C:/xampp/htdocs/ids_log.log"

# Threshold
DDOS_THRESHOLD = 20    # requests per IP / 5 detik
BRUTE_FORCE_THRESHOLD = 5  # gagal login per IP / 30 detik

# Pola serangan
XSS_PATTERNS = ["<script>", "alert(", "onerror=", "onload="]
SQLI_PATTERNS = ["' or '1'='1", "union select", "drop table", "--", "';--"]

# Whitelist IP (misal IP lokal admin)
WHITELIST_IPS = ["127.0.0.1", "::1"]

# Penyimpanan sementara
traffic_counter = defaultdict(list)
login_fail_counter = defaultdict(list)
last_alert_time = defaultdict(float)  # mencegah spam alert

ALERT_COOLDOWN = 10  # detik

def log_ids(event):
    """Simpan hasil deteksi ke IDS log"""
    with open(IDS_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")

def detect_ddos(ip):
    now = time.time()
    traffic_counter[ip] = [t for t in traffic_counter[ip] if now - t < 5]
    traffic_counter[ip].append(now)
    return len(traffic_counter[ip]) > DDOS_THRESHOLD

def detect_bruteforce(ip, status):
    now = time.time()
    if status == "failed":
        login_fail_counter[ip] = [t for t in login_fail_counter[ip] if now - t < 30]
        login_fail_counter[ip].append(now)
        return len(login_fail_counter[ip]) > BRUTE_FORCE_THRESHOLD
    return False

def detect_xss(payload):
    return any(pat.lower() in payload.lower() for pat in XSS_PATTERNS)

def detect_sqli(payload):
    return any(pat.lower() in payload.lower() for pat in SQLI_PATTERNS)

def alert(event_type, ip, payload=None):
    now = time.time()
    key = f"{event_type}_{ip}"

    if now - last_alert_time[key] < ALERT_COOLDOWN:
        return  # mencegah spam alert berulang

    last_alert_time[key] = now
    event = {
        "severity": "high" if event_type in ["DDoS", "SQL Injection"] else "medium",
        "type": event_type,
        "ip": ip,
        "payload": payload,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    log_ids(event)
    print(f"[ALERT] {event_type} from {ip} | Payload: {payload}")

def run_ids():
    if not os.path.exists(HONEYPOT_LOG):
        open(HONEYPOT_LOG, "w").close()

    print("[IDS] Monitoring honeypot.log...")
    with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                log_data = json.loads(line.strip())
                ip = log_data.get("ip", "unknown")
                status = log_data.get("status", "")
                payload = log_data.get("payload", "")

                if ip in WHITELIST_IPS:
                    continue  # skip whitelist

                if detect_ddos(ip):
                    alert("DDoS", ip)

                if detect_bruteforce(ip, status):
                    alert("Brute Force", ip)

                if payload:
                    if detect_xss(payload):
                        alert("XSS", ip, payload)
                    if detect_sqli(payload):
                        alert("SQL Injection", ip, payload)

            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    run_ids()
