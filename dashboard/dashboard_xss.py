import json

XSS_LOG = r"C:\test-cicd\log_ids\xss_test_log.json"
XSS_METRICS = r"C:\test-cicd\log_ids\evaluation_metrics_xss.json"
OUTPUT_HTML = r"C:\test-cicd\dashboard\xss_dashboard.html"
MAX_LENGTH = 100
ROWS_PER_PAGE = 10

with open(XSS_LOG, "r", encoding="utf-8") as f:
    logs = json.load(f)

logs = logs[:MAX_LENGTH]

with open(XSS_METRICS, "r", encoding="utf-8") as f:
    metrics = json.load(f)

logs_json = json.dumps(logs)

def metrics_to_html(metrics):
    items = ""
    for key, value in metrics.items():
        # Ubah _ jadi spasi dan huruf kapital tiap kata
        title = key.replace('_', ' ').title()
        items += f"<li><strong>{title}:</strong> {value}</li>\n"
    return items

html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>XSS Test Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-blue-50 min-h-screen p-6">
    <div class="max-w-6xl mx-auto bg-white rounded-lg shadow-lg p-8">
        <h1 class="text-4xl font-extrabold mb-8 text-center text-blue-700">🛡️ XSS Test Dashboard</h1>

        <section class="mb-10">
            <h2 class="text-2xl font-semibold mb-4 text-blue-600">📋 Recent XSS Test Logs (max {MAX_LENGTH})</h2>
            <div class="overflow-x-auto border border-blue-300 rounded-lg shadow-sm">
                <table class="min-w-full table-auto border-collapse text-sm text-blue-900">
                    <thead class="bg-blue-200">
                        <tr>
                            <th class="border px-4 py-3">Timestamp</th>
                            <th class="border px-4 py-3">Payload</th>
                            <th class="border px-4 py-3">Email Status</th>
                            <th class="border px-4 py-3">HTTP Status (Email)</th>
                            <th class="border px-4 py-3">Response Time (Email)</th>
                            <th class="border px-4 py-3">Password Status</th>
                            <th class="border px-4 py-3">HTTP Status (Password)</th>
                            <th class="border px-4 py-3">Response Time (Password)</th>
                        </tr>
                    </thead>
                    <tbody id="logTableBody">
                        <!-- Data dimuat lewat JS -->
                    </tbody>
                </table>
            </div>

            <div class="flex justify-between items-center mt-4">
                <button id="prevBtn" class="px-5 py-2 bg-blue-300 rounded hover:bg-blue-400 disabled:opacity-50" disabled>Previous</button>
                <span class="text-sm text-blue-700 font-semibold" id="pageInfo"></span>
                <button id="nextBtn" class="px-5 py-2 bg-blue-300 rounded hover:bg-blue-400 disabled:opacity-50">Next</button>
            </div>
        </section>

        <section>
            <h2 class="text-2xl font-semibold mb-4 text-blue-600">📊 Evaluation Metrics</h2>
            <ul class="list-disc list-inside text-blue-900 text-sm">
                {metrics_to_html(metrics)}
            </ul>
        </section>
    </div>

<script>
    const logs = {logs_json};
    const rowsPerPage = {ROWS_PER_PAGE};
    let currentPage = 1;
    const totalPages = Math.ceil(logs.length / rowsPerPage);

    function renderTablePage(page) {{
        const tbody = document.getElementById("logTableBody");
        tbody.innerHTML = "";

        const start = (page - 1) * rowsPerPage;
        const end = Math.min(start + rowsPerPage, logs.length);

        for(let i = start; i < end; i++) {{
            const log = logs[i];
            const row = `
                <tr class="hover:bg-blue-100">
                    <td class="border px-3 py-1 text-xs break-words">${{log.timestamp}}</td>
                    <td class="border px-3 py-1 text-xs break-words font-mono">${{log.payload}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.email_status}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.email_http_status}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.email_response_time_sec}}s</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.password_status}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.password_http_status}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.password_response_time_sec}}s</td>
                </tr>
            `;
            tbody.insertAdjacentHTML("beforeend", row);
        }}

        document.getElementById("pageInfo").textContent = `Page ${{page}} of ${{totalPages}}`;
        document.getElementById("prevBtn").disabled = page === 1;
        document.getElementById("nextBtn").disabled = page === totalPages;
    }}

    document.getElementById("prevBtn").addEventListener("click", () => {{
        if(currentPage > 1) {{
            currentPage--;
            renderTablePage(currentPage);
        }}
    }});

    document.getElementById("nextBtn").addEventListener("click", () => {{
        if(currentPage < totalPages) {{
            currentPage++;
            renderTablePage(currentPage);
        }}
    }});

    // Load halaman pertama
    renderTablePage(currentPage);
</script>

</body>
</html>
"""

with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
    f.write(html_content)

print(f"[✓] Dashboard XSS berhasil dibuat di: {OUTPUT_HTML}")
