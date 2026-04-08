from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from datetime import datetime, timedelta
import json
from collections import defaultdict
import time

LOG_FILE = "C:/xampp/htdocs/honeypot.log"
TARGET_URL = "https://ci-cd-phi.vercel.app"
RATE_LIMIT = 20  # Maks 20 request
TIME_WINDOW = 60  # dalam detik
BLOCK_DURATION = 300  # IP diblok selama 5 menit

request_counts = defaultdict(list)
blocked_ips = {}

class ProxyLoggerHandler(BaseHTTPRequestHandler):
    def log_request_data(self, status):
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "method": self.command,
            "path": self.path,
            "status": status
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def is_rate_limited(self, ip):
        now = time.time()

        # Unblock if time passed
        if ip in blocked_ips:
            if now > blocked_ips[ip]:
                del blocked_ips[ip]
            else:
                return True

        # Clean old requests
        request_counts[ip] = [t for t in request_counts[ip] if now - t <= TIME_WINDOW]
        request_counts[ip].append(now)

        if len(request_counts[ip]) > RATE_LIMIT:
            blocked_ips[ip] = now + BLOCK_DURATION
            return True

        return False

    def do_GET(self):
        client_ip = self.client_address[0]

        if self.is_rate_limited(client_ip):
            self.send_response(429)  # Too Many Requests
            self.end_headers()
            self.wfile.write(b"Too Many Requests - Anda diblokir sementara.")
            self.log_request_data(429)
            return

        try:
            target = TARGET_URL + self.path
            headers = dict(self.headers)
            r = requests.get(target, headers=headers, timeout=10)

            self.send_response(r.status_code)
            for key, value in r.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(r.content)

            self.log_request_data(r.status_code)

        except Exception:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Proxy error")
            self.log_request_data(502)

    def log_message(self, format, *args):
        return  # Suppress console logs

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8888), ProxyLoggerHandler)
    print("[*] Reverse Proxy Logger with Rate Limiting on port 8888...")
    server.serve_forever()
