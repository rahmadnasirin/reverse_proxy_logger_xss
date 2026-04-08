# save as simulate_ddos.py
import os
import json
import random
import time
from datetime import datetime, timedelta
import psutil

# Paths (sesuaikan)
OUT_DIR = r"C:\test-cicd\log_ids"
METRICS_FILE = os.path.join(OUT_DIR, "ddos_metrics.json")
LOG_FILE = os.path.join(OUT_DIR, "ddos_log.json")

os.makedirs(OUT_DIR, exist_ok=True)

# Simulation parameters
duration_seconds = 30              # total simulated duration
sample_interval = 1                # seconds per timeline sample
max_ips = 120                      # jumlah unique IP selama simulasi
peak_rps = 300                     # puncak rps yang disimulasikan
normal_rps = 5                     # baseline rps di luar serangan
attack_start = 5                   # detik mulai serangan
attack_peak_at = 15                # detik ketika mencapai puncak
attack_end = 25                    # detik selesai serangan

# CPU/RAM sampling
cpu_before = psutil.cpu_percent(interval=1)
ram_before = psutil.virtual_memory().percent

timeline = []
logs = []

start_ts = datetime.now()
unique_ips_pool = [f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(max_ips)]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.79.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 (Linux; Android 11)"
]

for t in range(duration_seconds):
    current_time = start_ts + timedelta(seconds=t)
    # Determine RPS (shape: ramp up, peak, ramp down)
    if t < attack_start or t > attack_end:
        rps = normal_rps
    elif t <= attack_peak_at:
        # linear ramp up
        progress = (t - attack_start) / max(1, (attack_peak_at - attack_start))
        rps = int(normal_rps + progress * (peak_rps - normal_rps))
    else:
        # ramp down
        progress = (attack_end - t) / max(1, (attack_end - attack_peak_at))
        rps = int(normal_rps + max(0, progress) * (peak_rps - normal_rps))

    # Simulate one sample per second: store timeline entry
    timeline.append({
        "time": current_time.strftime("%H:%M:%S"),
        "rps": rps
    })

    # Simulate logs for this second (capped to avoid huge files)
    requests_this_second = min(rps, 200)  # cap per-second logs to 200 for safety
    for i in range(requests_this_second):
        ip = random.choice(unique_ips_pool) if random.random() < 0.9 else f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        ua = random.choice(user_agents)
        # Simulate response time influenced by rps (higher rps -> higher RT)
        base_rt = random.uniform(0.01, 0.05)
        extra_rt = (rps / (peak_rps + 1)) * random.uniform(0, 0.5)
        response_time = round(base_rt + extra_rt, 3)
        status = "attack" if rps > (normal_rps + 10) else "normal"

        logs.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "user_agent": ua,
            "status": status,
            "response_time": response_time
        })

    # sample CPU/RAM during this second (light sampling, not generating load)
    cpu_now = psutil.cpu_percent(interval=0.1)
    ram_now = psutil.virtual_memory().percent

    # small sleep to simulate real-time generation (can be reduced or removed)
    time.sleep(max(0, sample_interval - 0.1))

# After simulation sampling
cpu_after = psutil.cpu_percent(interval=1)
ram_after = psutil.virtual_memory().percent

# Aggregate metrics
total_requests = sum(item["rps"] for item in timeline)
unique_ips = len({log["ip"] for log in logs})
peak_rps_observed = max(item["rps"] for item in timeline) if timeline else 0
attack_duration = f"{(attack_end - attack_start)}s"

metrics = {
    "total_requests": total_requests,
    "unique_ips": unique_ips,
    "peak_rps": peak_rps_observed,
    "attack_duration": attack_duration,
    "timeline": timeline,
    "cpu_before": cpu_before,
    "ram_before": ram_before,
    "cpu_after": cpu_after,
    "ram_after": ram_after,
    "avg_cpu_during": round(sum(psutil.cpu_percent(interval=0.01) for _ in range(3)) / 3, 2),
    "avg_ram_during": round(sum([r["response_time"] for r in logs]) / len(logs), 3)  # note: just an example placeholder
}

# Save files
with open(METRICS_FILE, "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)

with open(LOG_FILE, "w", encoding="utf-8") as f:
    json.dump(logs, f, indent=2, ensure_ascii=False)

print("[✓] Simulated ddos metrics written to:", METRICS_FILE)
print("[✓] Simulated ddos log written to:", LOG_FILE)
print(f"Total simulated requests (sum RPS): {total_requests}, unique IPs: {unique_ips}")
