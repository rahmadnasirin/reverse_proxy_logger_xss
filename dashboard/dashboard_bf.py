import json

HONEYPOT_LOG = r"C:\test-cicd\log_ids\bf_metrics.json"
METRICS_RESULT = r"C:\test-cicd\log_ids\evaluation_metrics_bf.json"
OUTPUT_HTML = r"C:\test-cicd\dashboard\bf_dashboard.html"
MAX_LENGTH = 100
ROWS_PER_PAGE = 10

with open(HONEYPOT_LOG, "r", encoding="utf-8") as f:
    logs = json.load(f)

logs = logs[:MAX_LENGTH]

with open(METRICS_RESULT, "r", encoding="utf-8") as f:
    metrics = json.load(f)

logs_json = json.dumps(logs)

def metrics_to_html(metrics):
    items = ""
    for key, value in metrics.items():
        items += f"<li><strong>{key.replace('_', ' ')}:</strong> {value}</li>\n"
    return items

html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <title>Brute Force Honeypot Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen p-6">
    <div class="max-w-5xl mx-auto bg-white rounded shadow p-6">
        <h1 class="text-3xl font-bold mb-6 text-center">🛡️ Brute Force Honeypot Dashboard</h1>

        <section class="mb-8">
            <h2 class="text-xl font-semibold mb-4">📋 Recent Brute Force Logs (max {MAX_LENGTH})</h2>
            <div class="overflow-x-auto border rounded">
                <table class="min-w-full table-auto border-collapse text-sm">
                    <thead class="bg-gray-200">
                        <tr>
                            <th class="border px-3 py-2">Timestamp</th>
                            <th class="border px-3 py-2">IP</th>
                            <th class="border px-3 py-2">Email</th>
                            <th class="border px-3 py-2">Password</th>
                            <th class="border px-3 py-2">Status</th>
                            <th class="border px-3 py-2">Type</th>
                            <th class="border px-3 py-2">Attack Start</th>
                        </tr>
                    </thead>
                    <tbody id="logTableBody">
                        <!-- Data akan dimuat lewat JS -->
                    </tbody>
                </table>
            </div>

            <div class="flex justify-between items-center mt-4">
                <button id="prevBtn" class="px-4 py-1 bg-gray-300 rounded hover:bg-gray-400 disabled:opacity-50" disabled>Previous</button>
                <span class="text-sm text-gray-700" id="pageInfo"></span>
                <button id="nextBtn" class="px-4 py-1 bg-gray-300 rounded hover:bg-gray-400">Next</button>
            </div>
        </section>

        <section>
            <h2 class="text-xl font-semibold mb-4">📊 Evaluation Metrics</h2>
            <ul class="list-disc list-inside text-gray-700 text-sm">
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
                <tr class="hover:bg-gray-100">
                    <td class="border px-3 py-1 text-xs break-words">${{log.timestamp ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.ip ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.email ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.password ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.status ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.type ?? "-"}}</td>
                    <td class="border px-3 py-1 text-xs break-words">${{log.attack_start ?? "-"}}</td>
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

print(f"[✓] Dashboard berhasil dibuat di: {OUTPUT_HTML}")
