from flask import Flask, jsonify, send_file
from flask_cors import CORS

import database
import sqlite3
import os
import csv
import hashlib
from datetime import datetime

from routes.auth_routes import auth
from routes.scan_routes import scan
from routes.activity_routes import activity


# ==========================================
# CREATE FLASK APPLICATION
# ==========================================

app = Flask(__name__)

# Create/migrate the SQLite schema at startup.
database.create_database()

CORS(app)


# ==========================================
# REGISTER ROUTES
# ==========================================

app.register_blueprint(auth)
app.register_blueprint(scan)
app.register_blueprint(activity)


# ==========================================
# SHOW REGISTERED ROUTES
# ==========================================

print("\n==========================================")
print("REGISTERED FLASK ROUTES")
print("==========================================")

print(app.url_map)

print("==========================================\n")


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return jsonify({

        "message":
        "Malware Detection Backend Running"

    })


# ==========================================
# REAL-TIME DASHBOARD STATISTICS
# ==========================================

# Dashboard session starts when Flask starts. This prevents old/demo database
# records from appearing as if they were live events in the current session.
from datetime import datetime, timezone
DASHBOARD_SESSION_START = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@app.get("/dashboard/stats")
def dashboard_stats():
    """Return only current-session scans plus current live monitor events."""
    import os
    import sqlite3

    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Only scans created after this Flask session started count on the dashboard.
    scans = cur.execute("""
        SELECT file_name, prediction, confidence, threat_level, scan_time
        FROM scan_history
        WHERE scan_time >= ?
        ORDER BY id DESC
    """, (DASHBOARD_SESSION_START,)).fetchall()

    scan_safe = sum(str(r["prediction"] or "").lower() in ("safe", "benign") for r in scans)
    scan_malware = sum(str(r["prediction"] or "").lower() in ("malware", "malicious") for r in scans)
    scan_alerts = sum(
        str(r["prediction"] or "").lower() in ("malware", "malicious", "suspicious", "warning")
        or str(r["threat_level"] or "").lower() in ("high", "medium", "suspicious", "warning")
        for r in scans
    )

    # Current in-memory monitor events are the real-time source.
    try:
        from routes.activity_routes import monitor
        live_monitoring = bool(monitor.running)
        monitor_folder = monitor.folder
        live_events = list(monitor.events)
        live_features = monitor.features()
    except Exception:
        live_monitoring = False
        monitor_folder = None
        live_events = []
        live_features = {
            "status": "Safe", "score": 0, "total_events": 0,
            "write_count": 0, "delete_count": 0, "create_count": 0,
            "rename_count": 0, "write_entropy": 0, "ext_diversity": 0,
            "sensitive_path_access": 0, "read_write_ratio": 0,
            "reasons": []
        }

    live_safe = sum(str(e.get("status", "")).lower() == "safe" for e in live_events)
    live_warning = sum(str(e.get("status", "")).lower() in ("warning", "suspicious") for e in live_events)

    # We never label a behavioural Warning/Suspicious event as confirmed malware.
    # Confirmed malware comes only from an actual file scan prediction.
    malware_detected = scan_malware
    threat_alerts = scan_alerts + live_warning

    total_files = len({str(e.get("path") or e.get("filename")) for e in live_events}) + len(scans)
    safe_files = live_safe + scan_safe

    if malware_detected > 0:
        threat_level = "HIGH RISK"
        notification = "A scanned file was classified as malware. Review the latest scan result."
    elif live_warning > 0 or scan_alerts > 0:
        threat_level = "MEDIUM RISK"
        notification = "Suspicious or warning-level activity is being observed."
    else:
        threat_level = "LOW RISK"
        notification = "No elevated threat activity has been observed in this session."

    # Include events received from authorized remote monitoring agents.
    remote_events = []
    try:
        remote_query = cur.execute("""
            SELECT e.filename, e.activity, e.status, e.event_time, e.process, e.path, d.device_name
            FROM agent_events e
            JOIN agent_devices d ON d.id=e.device_id
            WHERE e.event_time >= ?
            ORDER BY e.id DESC LIMIT 50
        """, (DASHBOARD_SESSION_START,)).fetchall()
        remote_events = [dict(r) for r in remote_query]
    except sqlite3.Error:
        remote_events = []

    remote_warning = sum(str(e.get("status", "")).lower() in ("warning", "suspicious") for e in remote_events)
    remote_safe = sum(str(e.get("status", "")).lower() == "safe" for e in remote_events)
    threat_alerts += remote_warning
    safe_files += remote_safe
    total_files += len(remote_events)

    # Show the newest events from the local monitor and remote agents together.
    combined_events = []
    for e in live_events:
        combined_events.append({
            "file": e.get("filename", "Unknown"),
            "status": e.get("status", "Safe"),
            "time": e.get("time"),
            "activity": e.get("activity"),
            "process": e.get("process", "Unknown")
        })
    for e in remote_events:
        combined_events.append({
            "file": e.get("filename", "Unknown"),
            "status": e.get("status", "Safe"),
            "time": e.get("event_time"),
            "activity": e.get("activity"),
            "process": e.get("process", "Unknown"),
            "device": e.get("device_name", "Remote PC")
        })
    combined_events.sort(key=lambda x: str(x.get("time") or ""), reverse=True)

    if combined_events:
        recent_activity = combined_events[:8]
    else:
        recent_activity = [
            {
                "file": r["file_name"] or "Unknown",
                "status": r["prediction"] or "Pending",
                "time": r["scan_time"]
            }
            for r in scans[:8]
        ]

    chart = {
        "safe": safe_files,
        "warning": live_warning + max(0, scan_alerts - scan_malware),
        "malware": malware_detected
    }

    conn.close()
    return jsonify(success=True, stats={
        "total_files": total_files,
        "safe_files": safe_files,
        "malware_detected": malware_detected,
        "threat_alerts": threat_alerts,
        "threat_level": threat_level,
        "notification": notification,
        "recent_activity": recent_activity,
        "chart": chart,
        "live_monitoring": live_monitoring,
        "monitor_folder": monitor_folder,
        "live_features": live_features,
        "session_started": DASHBOARD_SESSION_START
    })



# ==========================================
# REAL REPORT STATISTICS
# ==========================================

@app.get("/report/stats")
def report_stats():
    """Return current-session report statistics and scan history only."""
    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT id, file_name, prediction, confidence, threat_level, scan_time,
               detection_score, write_count, delete_count, create_count, rename_count
        FROM scan_history
        WHERE scan_time >= ?
        ORDER BY id DESC
    """, (DASHBOARD_SESSION_START,)).fetchall()
    conn.close()

    total = len(rows)
    malware = sum(str(r["prediction"] or "").lower() in ("malware", "malicious") for r in rows)
    safe = sum(str(r["prediction"] or "").lower() in ("safe", "benign") for r in rows)
    warning = max(0, total - malware - safe)
    threat_rate = round(((malware + warning) / total) * 100, 1) if total else 0

    history = []
    for r in rows[:100]:
        prediction = str(r["prediction"] or "Pending")
        status = "Malware Detected" if prediction.lower() in ("malware", "malicious") else ("Warning" if prediction.lower() in ("warning", "suspicious") else "Safe")
        history.append({
            "id": r["id"],
            "file": r["file_name"],
            "date": r["scan_time"],
            "files": 1,
            "threats": 1 if status != "Safe" else 0,
            "status": status,
            "prediction": prediction,
            "confidence": r["confidence"],
            "risk": r["threat_level"],
            "score": r["detection_score"],
            "write_count": r["write_count"],
            "delete_count": r["delete_count"],
            "create_count": r["create_count"],
            "rename_count": r["rename_count"]
        })

    return jsonify(success=True, stats={
        "total_scans": total,
        "files_checked": total,
        "malware_detected": malware,
        "warnings": warning,
        "threat_rate": threat_rate,
        "last_scan": history[0]["date"] if history else None,
        "history": history,
        "chart": {"safe": safe, "warning": warning, "malware": malware},
        "session_started": DASHBOARD_SESSION_START
    })


@app.get("/report/export.csv")
def report_export_csv():
    """Export current-session scan records as CSV."""
    database_path = os.path.join(os.path.dirname(__file__), "database.db")
    conn = sqlite3.connect(database_path)
    rows = conn.execute("""
        SELECT id,file_name,file_path,prediction,confidence,threat_level,scan_time,
               write_count,delete_count,create_count,rename_count,write_entropy,
               ext_diversity,sensitive_path_access,read_write_ratio,detection_score,
               detection_reasons
        FROM scan_history WHERE scan_time >= ? ORDER BY id DESC
    """, (DASHBOARD_SESSION_START,)).fetchall()
    conn.close()

    out=os.path.join(os.path.dirname(__file__),"uploads","security_report.csv")
    os.makedirs(os.path.dirname(out),exist_ok=True)
    with open(out,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f)
        w.writerow(["Scan ID","File Name","Path","Prediction","Confidence","Risk","Time",
                    "Write Count","Delete Count","Create Count","Rename Count","Write Entropy",
                    "Extension Diversity","Sensitive Path Access","Read/Write Ratio","Detection Score","Reasons"])
        w.writerows(rows)
    return send_file(out,as_attachment=True,download_name="security_report.csv",mimetype="text/csv")

# ==========================================
# REAL DETECTION RESULTS
# ==========================================

@app.get("/detection/results")
def detection_results():
    """Return only scans created during the current backend session."""
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT id, file_name, file_path, file_size, prediction, confidence,
               threat_level, scan_time, write_count, delete_count, create_count,
               rename_count, write_entropy, ext_diversity, sensitive_path_access,
               read_write_ratio, hidden_file_activity, execution_attempts,
               detection_score, detection_reasons
        FROM scan_history
        WHERE scan_time >= ?
        ORDER BY id DESC
        LIMIT 500
    """, (DASHBOARD_SESSION_START,)).fetchall()
    conn.close()

    results=[]
    for r in rows:
        item=dict(r)
        path=item.get("file_path") or ""
        item["extension"] = os.path.splitext(item.get("file_name") or "")[1].lower() or "none"
        item["reasons"] = [x.strip() for x in (item.get("detection_reasons") or "").split(";") if x.strip()]
        item["sha256"] = None
        if path and os.path.isfile(path):
            try:
                h=hashlib.sha256()
                with open(path,"rb") as f:
                    for chunk in iter(lambda: f.read(1024*1024), b""):
                        h.update(chunk)
                item["sha256"] = h.hexdigest()
            except OSError:
                pass
        results.append(item)

    summary={
        "total": len(results),
        "safe": sum(str(x.get("prediction","")).lower() in ("safe","benign") for x in results),
        "malware": sum(str(x.get("prediction","")).lower()=="malware" for x in results),
        "high_risk": sum(str(x.get("threat_level","")).upper() in ("HIGH","CRITICAL","HIGH RISK") for x in results),
        "last_scan": results[0]["scan_time"] if results else None,
    }
    return jsonify(success=True, session_started=DASHBOARD_SESSION_START, summary=summary, results=results)


@app.get("/detection/export.csv")
def detection_export_csv():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    rows = conn.execute("""
        SELECT id,file_name,file_path,prediction,confidence,threat_level,scan_time,
               write_count,delete_count,create_count,rename_count,write_entropy,
               ext_diversity,sensitive_path_access,read_write_ratio,detection_score,
               detection_reasons
        FROM scan_history WHERE scan_time >= ? ORDER BY id DESC
    """, (DASHBOARD_SESSION_START,)).fetchall()
    conn.close()
    out=os.path.join(os.path.dirname(__file__),"uploads","detection_results.csv")
    os.makedirs(os.path.dirname(out),exist_ok=True)
    with open(out,"w",newline="",encoding="utf-8-sig") as f:
        w=csv.writer(f)
        w.writerow(["Scan ID","File Name","Path","Prediction","Confidence","Risk","Time",
                    "Write Count","Delete Count","Create Count","Rename Count","Write Entropy",
                    "Extension Diversity","Sensitive Path Access","Read/Write Ratio","Detection Score","Reasons"])
        w.writerows(rows)
    return send_file(out,as_attachment=True,download_name="detection_results.csv",mimetype="text/csv")

# ==========================================
# AGENT DOWNLOAD AND REMOTE EVENT API
# ==========================================

from flask import request, Response
import io
import json
import secrets
import zipfile

AGENT_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "agent_template")


def _agent_db():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "database.db"))
    conn.row_factory = sqlite3.Row
    return conn


@app.post("/api/agent/pair")
def pair_agent():
    """Create a device token for a logged-in dashboard user."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    device_name = str(data.get("device_name", "")).strip() or "Windows-PC"
    if not email:
        return jsonify(success=False, message="User email is required."), 400

    conn = _agent_db()
    user = conn.execute("SELECT id, email FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        conn.close()
        return jsonify(success=False, message="User account not found."), 404

    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO agent_devices(user_id, device_name, token) VALUES(?,?,?)",
        (user["id"], device_name, token)
    )
    conn.commit()
    conn.close()
    return jsonify(success=True, token=token, device_name=device_name)


@app.get("/agent/download")
def download_agent():
    """Return a personalized agent ZIP using the device token supplied by the dashboard."""
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify(success=False, message="Missing device token."), 400

    conn = _agent_db()
    device = conn.execute("SELECT id, token FROM agent_devices WHERE token=?", (token,)).fetchone()
    conn.close()
    if not device:
        return jsonify(success=False, message="Invalid device token."), 403

    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as z:
        for name in ("agent.py", "requirements.txt", "run_agent.bat", "README.md"):
            path = os.path.join(AGENT_TEMPLATE_DIR, name)
            if os.path.isfile(path):
                z.write(path, name)
        config = {
            "server_url": request.host_url.rstrip("/"),
            "device_token": token,
            "watch_folder": ""
        }
        z.writestr("config.json", json.dumps(config, indent=2))
    memory.seek(0)
    return send_file(memory, as_attachment=True, download_name="DAVE-Monitor-Agent.zip", mimetype="application/zip")


@app.post("/api/agent/events")
def receive_agent_event():
    """Receive file-event metadata from an authorized local monitoring agent."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    if not token:
        return jsonify(success=False, message="Agent authorization required."), 401

    data = request.get_json(silent=True) or {}
    conn = _agent_db()
    device = conn.execute(
        "SELECT id, user_id, device_name FROM agent_devices WHERE token=?", (token,)
    ).fetchone()
    if not device:
        conn.close()
        return jsonify(success=False, message="Invalid agent token."), 403

    conn.execute("""
        INSERT INTO agent_events
        (user_id, device_id, device_name, filename, extension, activity, path, process, status, score, event_time)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        device["user_id"], device["id"], data.get("device_name") or device["device_name"],
        data.get("name", "Unknown"), data.get("extension", ""), data.get("event", "unknown"),
        data.get("path", ""), data.get("process", "Unknown"), data.get("status", "Safe"),
        float(data.get("score", 0) or 0), data.get("timestamp") or datetime.utcnow().isoformat()
    ))
    conn.execute("UPDATE agent_devices SET last_seen=CURRENT_TIMESTAMP WHERE id=?", (device["id"],))
    conn.commit()
    conn.close()
    return jsonify(success=True, message="Event received.")


@app.get("/api/agent/status")
def agent_status():
    email = request.args.get("email", "").strip().lower()
    if not email:
        return jsonify(success=False, message="Email is required."), 400
    conn = _agent_db()
    row = conn.execute("""
        SELECT d.device_name, d.last_seen, COUNT(e.id) AS event_count
        FROM agent_devices d
        LEFT JOIN agent_events e ON e.device_id=d.id
        JOIN users u ON u.id=d.user_id
        WHERE u.email=?
        GROUP BY d.id
        ORDER BY d.id DESC LIMIT 1
    """, (email,)).fetchone()
    conn.close()
    if not row:
        return jsonify(success=True, connected=False, device=None)
    return jsonify(success=True, connected=bool(row["last_seen"]), device=dict(row))


# Start server only after ALL routes have been registered.
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
