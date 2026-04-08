from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import requests
from datetime import datetime
import json
import time
import os
import threading

LOG_FILE = "C:/xampp/htdocs/honeypot_brute.log"
TARGET_BASE_URL = "https://ci-cd-phi.vercel.app"

RATE_WINDOW = 2  # Rate limit per IP (detik)
ip_request_times = {}
lock = threading.Lock()

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class ProxyLoggerHandler(BaseHTTPRequestHandler):
    def log_request_data(self, status):
        forwarded_ip = self.headers.get("X-Forwarded-For", self.client_address[0])
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": forwarded_ip,
            "user_agent": self.headers.get("User-Agent", ""),
            "method": self.command,
            "path": self.path,
            "status": status
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def is_rate_limited(self):
        # Ambil IP dari X-Forwarded-For atau IP asli
        ip = self.headers.get("X-Forwarded-For", self.client_address[0])
        now = time.time()

        with lock:
            last_time = ip_request_times.get(ip, 0)
            elapsed = now - last_time

            if elapsed < RATE_WINDOW:
                print(f"[!] RATE LIMITED {ip} - hanya {elapsed:.2f}s sejak request terakhir")
                return True

            ip_request_times[ip] = now
            return False

    def forward_request(self, method):
        if self.is_rate_limited():
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Too Many Requests - Rate Limited")
            self.log_request_data(429)
            return

        try:
            target_url = TARGET_BASE_URL + self.path
            headers = dict(self.headers)
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length) if content_length > 0 else None

            r = requests.request(method, target_url, headers=headers, data=data, timeout=10)

            self.send_response(r.status_code)
            for key, value in r.headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(r.content)
            self.log_request_data(r.status_code)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"Proxy error")
            self.log_request_data(502)
            print(f"[!] Proxy error from {self.client_address[0]}: {e}")

    def do_GET(self):
        print(f"[*] GET {self.client_address[0]} -> {self.path}")
        self.forward_request("GET")

    def do_POST(self):
        print(f"[*] POST {self.client_address[0]} -> {self.path}")
        self.forward_request("POST")

    def log_message(self, format, *args):
        return  # Nonaktifkan log default

if __name__ == "__main__":
    try:
        if not os.path.exists(LOG_FILE):
            open(LOG_FILE, "w").close()

        port = 8888
        server = ThreadingHTTPServer(("0.0.0.0", port), ProxyLoggerHandler)
        print(f"[*] Honeypot reverse proxy running on port {port}...")
        server.serve_forever()
    except Exception as e:
        print(f"[!] Gagal menjalankan honeypot: {e}")
