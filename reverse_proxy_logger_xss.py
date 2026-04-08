from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from datetime import datetime, timedelta
import json
import time

LOG_FILE = "C:/xampp/htdocs/honeypot_xss.log"
TARGET_BASE_URL = "https://ci-cd-phi.vercel.app"

# Rate limit configuration
RATE_LIMIT_WINDOW = 2  # seconds
request_timestamps = {}  # Format: {ip: last_request_time}

class ProxyLoggerHandler(BaseHTTPRequestHandler):
    def is_rate_limited(self, ip):
        now = time.time()
        last_time = request_timestamps.get(ip, 0)
        if now - last_time < RATE_LIMIT_WINDOW:
            return True
        request_timestamps[ip] = now
        return False

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

    def do_GET(self):
        ip = self.client_address[0]
        if self.is_rate_limited(ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Rate limit exceeded")
            self.log_request_data(429)
            return

        try:
            target = TARGET_BASE_URL + self.path
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

    def do_POST(self):
        ip = self.client_address[0]
        if self.is_rate_limited(ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Rate limit exceeded")
            self.log_request_data(429)
            return

        try:
            target = TARGET_BASE_URL + self.path
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)

            headers = dict(self.headers)
            r = requests.post(target, headers=headers, data=post_data, timeout=10)

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
        return  # Supress console logs

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8888), ProxyLoggerHandler)
    print("[*] Reverse Proxy Logger running on port 8888 with Rate Limiting...")
    server.serve_forever()
