/* ==========================================
   detection.js - REAL BACKEND RESULTS
   No generated/demo detections.
========================================== */

if (localStorage.getItem("loggedIn") !== "true") {
    window.location.href = "login.html";
}

const API = "http://127.0.0.1:5000";
const $ = id => document.getElementById(id);

const resultTable = $("resultTable");
const totalScanned = $("totalScanned");
const safeFiles = $("safeFiles");
const malwareFiles = $("malwareFiles");
const highRisk = $("highRisk");
const alertBanner = $("alertBanner");
const searchInput = $("searchInput");
const riskFilter = $("riskFilter");
const predictionFilter = $("predictionFilter");
const timeline = $("timeline");

let results = [];
let selected = null;

function updateClock() {
    const now = new Date();
    if ($("clock")) $("clock").textContent = now.toLocaleTimeString();
    if ($("todayDate")) $("todayDate").textContent = now.toDateString();
}
setInterval(updateClock, 1000);
updateClock();

$("logoutBtn")?.addEventListener("click", () => {
    localStorage.removeItem("loggedIn");
    localStorage.removeItem("user");
    localStorage.removeItem("currentUser");
    window.location.href = "login.html";
});

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>'"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]));
}

function predictionClass(prediction) {
    return String(prediction).toLowerCase() === "malware" ? "malware" : "benign";
}

function riskClass(risk) {
    const r = String(risk || "LOW").toLowerCase();
    return ["safe","low","medium","high","critical"].includes(r) ? r : "low";
}

function formatConfidence(value) {
    return Number(value || 0).toFixed(2) + "%";
}

function updateSummary(summary) {
    totalScanned.textContent = summary.total ?? 0;
    safeFiles.textContent = summary.safe ?? 0;
    malwareFiles.textContent = summary.malware ?? 0;
    highRisk.textContent = summary.high_risk ?? 0;

    if ((summary.malware || 0) > 0) {
        alertBanner.className = "danger-banner";
        alertBanner.textContent = "🔴 Malware detected in the current scan session - review the latest result.";
    } else if ((summary.high_risk || 0) > 0) {
        alertBanner.className = "danger-banner";
        alertBanner.textContent = "🟠 High-risk scan result detected - review the latest result.";
    } else if ((summary.total || 0) > 0) {
        alertBanner.className = "safe-banner";
        alertBanner.textContent = "🟢 Current scan session contains no confirmed malware.";
    } else {
        alertBanner.className = "safe-banner";
        alertBanner.textContent = "🟢 No scan results in the current session.";
    }
}

function renderTable() {
    const search = (searchInput?.value || "").toLowerCase().trim();
    const risk = riskFilter?.value || "All";
    const prediction = predictionFilter?.value || "All";

    const filtered = results.filter(r => {
        const file = String(r.file_name || "").toLowerCase();
        const rr = String(r.threat_level || "");
        const pp = String(r.prediction || "");
        return (!search || file.includes(search)) &&
               (risk === "All" || rr.toLowerCase() === risk.toLowerCase()) &&
               (prediction === "All" || pp.toLowerCase() === prediction.toLowerCase());
    });

    if (!filtered.length) {
        resultTable.innerHTML = `<tr><td colspan="6">No real scan results in the current session.</td></tr>`;
        return;
    }

    resultTable.innerHTML = filtered.map(r => `
        <tr data-id="${r.id}" tabindex="0">
            <td>${escapeHtml(r.file_name)}</td>
            <td>${escapeHtml(r.extension)}</td>
            <td class="${predictionClass(r.prediction)}">${escapeHtml(r.prediction)}</td>
            <td>${formatConfidence(r.confidence)}</td>
            <td class="${riskClass(r.threat_level)}">${escapeHtml(r.threat_level)}</td>
            <td>${escapeHtml(new Date(r.scan_time.replace(" ", "T")).toLocaleTimeString())}</td>
        </tr>`).join("");
}

function renderTimeline() {
    if (!timeline) return;
    if (!results.length) {
        timeline.innerHTML = `<div class="timeline-item"><div class="timeline-content"><h3>No scan history yet</h3><p>Run a scan from the Scan page and the real result will appear here.</p></div></div>`;
        return;
    }
    timeline.innerHTML = results.slice(0, 10).map(r => {
        const malware = String(r.prediction).toLowerCase() === "malware";
        const icon = malware ? "bug" : "check";
        const cls = malware ? "danger" : "safe";
        const reason = (r.reasons || []).join("; ") || "No strong static indicators detected.";
        return `<div class="timeline-item">
            <div class="timeline-icon ${cls}"><i class="fa-solid fa-${icon}"></i></div>
            <div class="timeline-content">
                <h3>${escapeHtml(r.file_name)}</h3>
                <p>${escapeHtml(r.prediction)} — ${escapeHtml(reason)}</p>
                <small>${escapeHtml(r.scan_time || "")}</small>
            </div>
        </div>`;
    }).join("");
}

function showDetails(r) {
    selected = r;
    $("detailFilename").textContent = r.file_name || "-";
    $("detailPath").textContent = r.file_path || "-";
    $("detailExtension").textContent = r.extension || "-";
    $("detailPrediction").textContent = r.prediction || "-";
    $("detailConfidence").textContent = formatConfidence(r.confidence);
    $("detailRisk").textContent = r.threat_level || "-";
    $("detailEntropy").textContent = Number(r.write_entropy || 0).toFixed(4);
    $("detailHash").textContent = r.sha256 || "Unavailable (file no longer present)";
    $("detailAction").textContent = String(r.prediction).toLowerCase() === "malware" ? "Review and isolate after verification" : "No action required";

    const fields = {
        detailWriteCount: r.write_count,
        detailDeleteCount: r.delete_count,
        detailCreateCount: r.create_count,
        detailRenameCount: r.rename_count,
        detailExtDiversity: r.ext_diversity,
        detailSensitivePath: r.sensitive_path_access,
        detailReadWrite: Number(r.read_write_ratio || 0).toFixed(3),
        detailScore: Number(r.detection_score || 0).toFixed(2),
        detailReasons: (r.reasons || []).join("; ") || "No strong static indicators detected."
    };
    Object.entries(fields).forEach(([id, value]) => { if ($(id)) $(id).textContent = value; });

    $("analysisExecutable").textContent = Number(r.execution_attempts || 0) > 0 ? "Executable/script characteristic detected" : "No executable characteristic detected";
    $("analysisML").textContent = "Current backend behavioural/static analyzer";
    $("analysisScore").textContent = Number(r.detection_score || 0).toFixed(2) + "/100";
    $("analysisStatus").textContent = String(r.prediction).toLowerCase() === "malware" ? "Threat detected" : "Protected";
    $("lastScan").textContent = r.scan_time || "-";
}

async function loadResults() {
    try {
        const response = await fetch(`${API}/detection/results`, { cache: "no-store" });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.message || "Could not load detection results.");
        results = data.results || [];
        updateSummary(data.summary || {});
        renderTable();
        renderTimeline();
        if (results.length && !selected) showDetails(results[0]);
        if (results.length && selected) {
            const fresh = results.find(x => x.id === selected.id);
            if (fresh) showDetails(fresh);
        }
    } catch (error) {
        console.error(error);
        resultTable.innerHTML = `<tr><td colspan="6">Backend unavailable. Start Flask and refresh.</td></tr>`;
        if (alertBanner) {
            alertBanner.className = "danger-banner";
            alertBanner.textContent = "🔴 Detection results unavailable - backend connection required.";
        }
    }
}

resultTable.addEventListener("click", e => {
    const row = e.target.closest("tr[data-id]");
    if (!row) return;
    const item = results.find(r => String(r.id) === row.dataset.id);
    if (item) showDetails(item);
});

searchInput?.addEventListener("input", renderTable);
riskFilter?.addEventListener("change", renderTable);
predictionFilter?.addEventListener("change", renderTable);

$("rescanBtn")?.addEventListener("click", () => {
    window.location.href = "scan.html";
});

$("quarantineBtn")?.addEventListener("click", () => {
    alert("Quarantine is not executed automatically. Verify the selected file first, then isolate it using your operating system or security tooling.");
});

$("deleteBtn")?.addEventListener("click", () => {
    alert("Automatic deletion is disabled in this demonstration build to prevent accidental removal of files.");
});

$("ignoreBtn")?.addEventListener("click", () => {
    alert("The detection remains in the current scan history. Ignoring it does not delete or execute the file.");
});

$("exportCSV")?.addEventListener("click", () => {
    window.location.href = `${API}/detection/export.csv`;
});

$("exportPDF")?.addEventListener("click", () => {
    if (!selected) {
        alert("Run a scan and select a result first.");
        return;
    }
    window.location.href = `${API}/report/${selected.id}/pdf`;
});

$("printReport")?.addEventListener("click", () => window.print());

loadResults();
setInterval(loadResults, 2000);
