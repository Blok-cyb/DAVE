/* ==========================================
   REAL REPORTS PAGE
   Uses current Flask session data only.
========================================== */

if (localStorage.getItem("loggedIn") !== "true") {
    window.location.href = "login.html";
}

const API = "http://127.0.0.1:5000";
const $ = id => document.getElementById(id);

function updateClock() {
    const now = new Date();
    if ($("clock")) $("clock").textContent = now.toLocaleTimeString();
    if ($("todayDate")) $("todayDate").textContent = now.toDateString();
}
setInterval(updateClock, 1000);
updateClock();

$("logoutBtn")?.addEventListener("click", () => {
    localStorage.removeItem("loggedIn");
    window.location.href = "login.html";
});

let latestReport = null;
let latestScanId = null;

function setText(id, value) {
    if ($(id)) $(id).textContent = value;
}

function renderHistory(history) {
    const tbody = $("scanHistory");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!history.length) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;opacity:.7;">No scans have been performed in this session.</td></tr>`;
        return;
    }

    history.forEach(scan => {
        const row = document.createElement("tr");
        const threatClass = scan.threats > 0 ? "danger-text" : "safe-text";
        row.innerHTML = `
            <td>SCAN-${String(scan.id).padStart(3, "0")}</td>
            <td>${scan.date || "—"}</td>
            <td>1</td>
            <td class="${threatClass}">${scan.threats}</td>
            <td class="${threatClass}">${scan.status}</td>
        `;
        row.addEventListener("click", () => {
            latestScanId = scan.id;
            localStorage.setItem("lastScanId", String(scan.id));
            if ($("reportStatus")) {
                $("reportStatus").textContent = `${scan.file} — ${scan.status} — ${scan.confidence ?? 0}% confidence`;
            }
        });
        tbody.appendChild(row);
    });
}

function renderStats(data) {
    latestReport = data;
    setText("totalScans", data.total_scans);
    setText("filesChecked", data.files_checked);
    setText("malwareDetected", data.malware_detected);
    setText("threatRate", `${data.threat_rate}%`);
    setText("lastScanTime", data.last_scan ? new Date(data.last_scan).toLocaleString() : "No scan yet");
    setText("reportDate", new Date().toDateString());

    setText("exeThreats", data.chart.malware);
    setText("encryptedFiles", data.chart.warning);
    setText("modifiedFiles", data.files_checked);
    setText("deletedFiles", data.malware_detected);

    const safePercentage = data.files_checked ? Math.round((data.chart.safe / data.files_checked) * 100) : 0;
    setText("safePercentage", `${safePercentage}%`);

    setText("createdFiles", data.files_checked);
    setText("modifiedCount", data.files_checked);
    setText("deletedCount", data.malware_detected);

    if ($("reportStatus")) {
        $("reportStatus").textContent = data.files_checked
            ? `Live session report: ${data.files_checked} scan(s), ${data.malware_detected} malware detection(s), ${data.warnings} warning(s).`
            : "No scans have been performed in this session.";
    }

    renderHistory(data.history);
}

async function loadReports() {
    try {
        const response = await fetch(`${API}/report/stats?ts=${Date.now()}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        if (!payload.success) throw new Error(payload.message || "Unable to load report data");
        renderStats(payload.stats);
    } catch (error) {
        console.error("Report API error:", error);
        if ($("reportStatus")) $("reportStatus").textContent = "Unable to connect to the report backend.";
    }
}

$("generateReport")?.addEventListener("click", async () => {
    await loadReports();
    const scanId = latestScanId || localStorage.getItem("lastScanId");
    if (!scanId) {
        alert("Run a scan first. There is no report to generate yet.");
        return;
    }
    window.open(`${API}/report/${encodeURIComponent(scanId)}/pdf`, "_blank");
    if ($("reportStatus")) $("reportStatus").textContent = "PDF report generated from the selected real scan.";
});

$("exportCSV")?.addEventListener("click", () => {
    window.location.href = `${API}/report/export.csv?ts=${Date.now()}`;
});

$("exportPDF")?.addEventListener("click", () => {
    const scanId = latestScanId || localStorage.getItem("lastScanId");
    if (!scanId) {
        alert("Run a scan first so there is a real report to export.");
        return;
    }
    window.open(`${API}/report/${encodeURIComponent(scanId)}/pdf`, "_blank");
});

$("printReport")?.addEventListener("click", () => window.print());

loadReports();
setInterval(loadReports, 2000);
