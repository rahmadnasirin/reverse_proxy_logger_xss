import requests
from html import escape
from datetime import datetime
import json
import time
import psutil

XSS_LOG = r"C:\test-cicd\log_ids\xss_test_log.json"
XSS_METRICS = r"C:\test-cicd\log_ids\evaluation_metrics_xss.json"

url = "http://localhost/web_attack/login.php"

xss_payloads = [
    "<script>alert('XSS1')</script>",
    "\"><script>alert('XSS2')</script>",
    "<img src=x onerror=alert('XSS3')>",
    "<svg onload=alert('XSS4')>",
    "<body onload=alert('XSS5')>",
    "'><svg/onload=alert(1337)>",
    "<iframe src=javascript:alert('xss')>",
    "<svg><script>alert(1)</script>"
]

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

results = []
cpu_list = []
ram_list = []

# === CPU & RAM Sebelum Serangan ===
cpu_before = psutil.cpu_percent(interval=1)
ram_before = psutil.virtual_memory().percent

# === Jalankan Serangan XSS ===
for payload in xss_payloads:
    # Hitung CPU & RAM saat serangan
    cpu_during = psutil.cpu_percent(interval=0.5)
    ram_during = psutil.virtual_memory().percent
    cpu_list.append(cpu_during)
    ram_list.append(ram_during)

    # Test di field email
    data_email = {"email": payload, "password": "dummy"}
    start_time = time.time()
    res_email = requests.post(url, data=data_email, headers=headers)
    elapsed_email = time.time() - start_time

    status_email = "AMAN"
    if res_email.status_code != 200:
        status_email = f"ERROR HTTP {res_email.status_code}"
    else:
        if payload in res_email.text:
            status_email = "TEREKSPOS"
        elif escape(payload) in res_email.text:
            status_email = "TEREKSPOS (encoded)"

    # Test di field password
    data_pass = {"email": "dummy@xss.com", "password": payload}
    start_time = time.time()
    res_pass = requests.post(url, data=data_pass, headers=headers)
    elapsed_pass = time.time() - start_time

    status_pass = "AMAN"
    if res_pass.status_code != 200:
        status_pass = f"ERROR HTTP {res_pass.status_code}"
    else:
        if payload in res_pass.text:
            status_pass = "TEREKSPOS"
        elif escape(payload) in res_pass.text:
            status_pass = "TEREKSPOS (encoded)"

    results.append({
        "waktu_uji": str(datetime.now()),
        "payload": payload,
        "status_email": status_email,
        "status_http_email": res_email.status_code,
        "waktu_respon_email_detik": round(elapsed_email, 3),
        "status_password": status_pass,
        "status_http_password": res_pass.status_code,
        "waktu_respon_password_detik": round(elapsed_pass, 3),
        "cpu_saat_ujian_%": cpu_during,
        "ram_saat_ujian_%": ram_during,
        "tipe": "Uji XSS"
    })

# === CPU & RAM Setelah Serangan ===
cpu_after = psutil.cpu_percent(interval=1)
ram_after = psutil.virtual_memory().percent

# Simpan log JSON lengkap
with open(XSS_LOG, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

# Buat evaluasi metrik
total = len(results)
email_vuln = sum(1 for r in results if "TEREKSPOS" in r["status_email"])
pass_vuln = sum(1 for r in results if "TEREKSPOS" in r["status_password"])
email_errors = sum(1 for r in results if "ERROR" in r["status_email"])
pass_errors = sum(1 for r in results if "ERROR" in r["status_password"])
avg_email_resp_time = round(sum(r["waktu_respon_email_detik"] for r in results)/total, 3) if total else 0
avg_pass_resp_time = round(sum(r["waktu_respon_password_detik"] for r in results)/total, 3) if total else 0
avg_cpu_during = round(sum(cpu_list) / len(cpu_list), 2) if cpu_list else 0
avg_ram_during = round(sum(ram_list) / len(ram_list), 2) if ram_list else 0

metrics = {
    "Tipe_Ujian": "XSS",
    "Total_Payload_Diuji": total,
    "Total_Email_Rentan_XSS": email_vuln,
    "Total_Password_Rentan_XSS": pass_vuln,
    "Persentase_Email_Rentan_%": round(email_vuln / total * 100, 1) if total else 0,
    "Persentase_Password_Rentan_%": round(pass_vuln / total * 100, 1) if total else 0,
    "Jumlah_Error_HTTP_Email": email_errors,
    "Jumlah_Error_HTTP_Password": pass_errors,
    "Rata2_Waktu_Respon_Email_Detik": avg_email_resp_time,
    "Rata2_Waktu_Respon_Password_Detik": avg_pass_resp_time,
    "CPU_Sebelum_%": cpu_before,
    "RAM_Sebelum_%": ram_before,
    "Rata2_CPU_Saat_Serangan_%": avg_cpu_during,
    "Rata2_RAM_Saat_Serangan_%": avg_ram_during,
    "CPU_Sesudah_%": cpu_after,
    "RAM_Sesudah_%": ram_after,
    "Waktu_Ujian_Selesai": str(datetime.now())
}

with open(XSS_METRICS, "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=2, ensure_ascii=False)

# Cetak hasil
print(f"[✓] Log hasil uji XSS tersimpan di: {XSS_LOG}")
print(f"[✓] Metrik evaluasi XSS tersimpan di: {XSS_METRICS}")
print(f"Rata-rata CPU saat serangan : {metrics['Rata2_CPU_Saat_Serangan_%']}%")
print(f"Rata-rata RAM saat serangan : {metrics['Rata2_RAM_Saat_Serangan_%']}%")
