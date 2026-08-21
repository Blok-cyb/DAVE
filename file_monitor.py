import os
import threading
import math
import sqlite3
from collections import deque, Counter
from datetime import datetime

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from activity_ml import ActivityML


class ActivityMonitor(FileSystemEventHandler):
    """Real-time recursive file-system monitor using Watchdog.

    The monitor keeps a 10-second behavioural window in memory and records
    every real create/modify/delete/rename event it observes.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.observer = None
        self.folder = None
        self.running = False
        self.lock = threading.RLock()
        self.events = deque(maxlen=500)
        self.window = deque(maxlen=1000)
        self.counts = {"Created": 0, "Modified": 0, "Deleted": 0, "Renamed": 0}
        self.session_started = None
        self.ml = ActivityML(os.path.join(os.path.dirname(db_path), "activity_behavior_model.pkl"))
        self._ensure_db()

    def _ensure_db(self):
        """Create/migrate the activity table so real event data is exportable."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                extension TEXT,
                activity TEXT,
                process TEXT,
                path TEXT,
                old_path TEXT,
                status TEXT,
                score REAL DEFAULT 0,
                reasons TEXT,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(activity_logs)")}
        additions = {
            "extension": "TEXT", "process": "TEXT", "path": "TEXT", "old_path": "TEXT",
            "score": "REAL DEFAULT 0", "reasons": "TEXT"
        }
        for name, typ in additions.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE activity_logs ADD COLUMN {name} {typ}")
        conn.commit()
        conn.close()

    def _process_name(self, path):
        """Best-effort process lookup. Windows may deny access to open-file handles."""
        target = os.path.normcase(os.path.abspath(path))
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    for opened in proc.open_files() or []:
                        if os.path.normcase(os.path.abspath(opened.path)) == target:
                            return proc.info.get("name") or f"PID {proc.pid}"
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                    continue
        except Exception:
            pass
        return "Unknown"

    @staticmethod
    def _byte_entropy(path):
        """Calculate Shannon entropy from up to the first 1 MiB of a real file."""
        try:
            if not os.path.isfile(path):
                return 0.0
            with open(path, "rb") as fh:
                data = fh.read(1024 * 1024)
            if not data:
                return 0.0
            counts = Counter(data)
            total = len(data)
            return round(-sum((n / total) * math.log2(n / total) for n in counts.values()), 4)
        except (PermissionError, OSError):
            return 0.0

    @staticmethod
    def _sensitive(path):
        p = os.path.normcase(os.path.abspath(path))
        sensitive_parts = (
            os.sep + "appdata" + os.sep,
            os.sep + "startup" + os.sep,
            os.sep + "system32" + os.sep,
            os.sep + "windows" + os.sep,
            os.sep + "programdata" + os.sep,
        )
        return 1 if any(part in p for part in sensitive_parts) else 0

    def _recent_events(self):
        now = datetime.now()
        with self.lock:
            events = list(self.window)
        recent = []
        for event in events:
            try:
                t = datetime.fromisoformat(event["time"])
                age = (now - t).total_seconds()
                if 0 <= age <= 10:
                    recent.append(event)
            except Exception:
                continue
        return recent

    def _calculate_features(self, recent=None):
        recent = self._recent_events() if recent is None else recent
        writes = sum(e["activity"] == "Modified" for e in recent)
        deletes = sum(e["activity"] == "Deleted" for e in recent)
        creates = sum(e["activity"] == "Created" for e in recent)
        renames = sum(e["activity"] == "Renamed" for e in recent)
        extensions = [e["extension"] for e in recent if e.get("extension") not in (None, "none", "")]
        ext_diversity = len(set(extensions))
        entropy_values = [e.get("file_entropy", 0) for e in recent if e.get("file_entropy", 0) > 0]
        write_entropy = round(max(entropy_values), 4) if entropy_values else 0.0
        sensitive = sum(self._sensitive(e.get("path", "")) for e in recent)

        # Transparent behavioural heuristic; this is NOT an ML probability.
        score = 0
        reasons = []
        if writes >= 15:
            score += 30; reasons.append("high modification rate")
        elif writes >= 8:
            score += 15; reasons.append("elevated modification rate")
        if renames >= 8:
            score += 30; reasons.append("high rename rate")
        elif renames >= 4:
            score += 15; reasons.append("elevated rename rate")
        if deletes >= 8:
            score += 25; reasons.append("high deletion rate")
        elif deletes >= 4:
            score += 12; reasons.append("elevated deletion rate")
        if creates >= 20:
            score += 25; reasons.append("rapid file creation")
        elif creates >= 10:
            score += 12; reasons.append("elevated file creation")
        if sensitive:
            score += min(20, sensitive * 5); reasons.append("sensitive path activity")
        if write_entropy >= 7.0 and writes >= 3:
            score += 15; reasons.append("high file-content entropy")
        score = min(score, 100)
        status = "Suspicious" if score >= 70 else "Warning" if score >= 40 else "Safe"

        # Windows file-system notifications do not expose ordinary read events.
        # Keep this explicit instead of pretending that a zero means no reads.
        ratio_proxy = round(creates / writes, 3) if writes else 0.0
        ml = self.ml.observe({
            "write_count": writes, "delete_count": deletes, "create_count": creates,
            "rename_count": renames, "write_entropy": write_entropy,
            "ext_diversity": ext_diversity, "sensitive_path_access": sensitive,
            "read_write_ratio": ratio_proxy, "score": score
        })
        return {
            "write_count": writes,
            "delete_count": deletes,
            "create_count": creates,
            "rename_count": renames,
            "write_entropy": write_entropy,
            "ext_diversity": ext_diversity,
            "sensitive_path_access": sensitive,
            "read_write_ratio": ratio_proxy,
            "read_write_ratio_note": "Create/Write proxy; normal file reads are not observable through Watchdog events",
            "score": score,
            "status": status,
            "reasons": reasons or ["no elevated file-activity pattern detected"],
            "window_seconds": 10,
            "total_events": len(recent),
            **ml,
        }

    def _record(self, activity, path, old_path=None):
        now = datetime.now().isoformat(timespec="seconds")
        filename = os.path.basename(path) or path
        extension = os.path.splitext(filename)[1].lower() or "none"
        process = self._process_name(path)
        event = {
            "filename": filename,
            "extension": extension,
            "activity": activity,
            "process": process,
            "time": now,
            "path": os.path.abspath(path),
            "old_path": os.path.abspath(old_path) if old_path else "",
            "file_entropy": self._byte_entropy(path) if activity in ("Created", "Modified", "Renamed") else 0.0,
        }
        with self.lock:
            self.counts[activity] = self.counts.get(activity, 0) + 1
            self.window.append(event)
            features = self._calculate_features()
            event.update({
                "status": features["status"],
                "score": features["score"],
                "reasons": list(features["reasons"]),
                "feature_snapshot": {k: features[k] for k in (
                    "write_count", "delete_count", "create_count", "rename_count",
                    "write_entropy", "ext_diversity", "sensitive_path_access", "read_write_ratio"
                )},
            })
            self.events.appendleft(event)
        self._save_db(event)

    def _save_db(self, event):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO activity_logs
                (filename, extension, activity, process, path, old_path, status, score, reasons, event_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event["filename"], event["extension"], event["activity"], event["process"],
                event["path"], event.get("old_path", ""), event["status"], event["score"],
                "; ".join(event["reasons"]), event["time"]
            ))
            conn.commit(); conn.close()
        except Exception:
            pass

    def features(self):
        recent = self._recent_events()
        with self.lock:
            totals = dict(self.counts)
        result = self._calculate_features(recent)
        result["totals"] = totals
        return result

    def on_created(self, event):
        if not event.is_directory: self._record("Created", event.src_path)
    def on_modified(self, event):
        if not event.is_directory: self._record("Modified", event.src_path)
    def on_deleted(self, event):
        if not event.is_directory: self._record("Deleted", event.src_path)
    def on_moved(self, event):
        if not event.is_directory: self._record("Renamed", event.dest_path, event.src_path)

    def start(self, folder):
        folder = os.path.abspath(os.path.expanduser(folder))
        if not os.path.isdir(folder): raise ValueError("Monitoring folder does not exist.")
        if self.running: self.stop()
        self.folder = folder
        with self.lock:
            self.events.clear(); self.window.clear()
            self.counts = {"Created": 0, "Modified": 0, "Deleted": 0, "Renamed": 0}
            self.session_started = datetime.now().isoformat(timespec="seconds")
        self.observer = Observer()
        self.observer.schedule(self, folder, recursive=True)
        self.observer.start()
        self.running = True

    def stop(self):
        if self.observer:
            self.observer.stop(); self.observer.join(timeout=3)
        self.observer = None; self.running = False

    def clear_live(self):
        with self.lock:
            self.events.clear(); self.window.clear()
            self.counts = {"Created": 0, "Modified": 0, "Deleted": 0, "Renamed": 0}

    def snapshot(self):
        with self.lock: events = list(self.events)
        return {
            "running": self.running,
            "folder": self.folder,
            "session_started": self.session_started,
            "events": events,
            "features": self.features(),
            "totals": dict(self.counts)
        }
