import sqlite3


DATABASE = "database.db"


def create_database():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ==========================================
    # USERS TABLE
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            fullname TEXT NOT NULL,

            email TEXT UNIQUE NOT NULL,

            password TEXT NOT NULL,

            failed_attempts INTEGER DEFAULT 0,

            locked INTEGER DEFAULT 0,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)


    # ==========================================
    # LOGIN LOGS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            email TEXT,

            ip_address TEXT,

            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            status TEXT,

            FOREIGN KEY(user_id)
            REFERENCES users(id)

        )
    """)


    # ==========================================
    # SCAN HISTORY
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            file_name TEXT,

            file_path TEXT,

            file_size INTEGER,

            prediction TEXT DEFAULT 'Pending',

            confidence REAL DEFAULT 0,

            threat_level TEXT DEFAULT 'Unknown',

            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(user_id)
            REFERENCES users(id)

        )
    """)


    # ==========================================
    # CHECK EXISTING SCAN_HISTORY COLUMNS
    # ==========================================

    cursor.execute("""
        PRAGMA table_info(scan_history)
    """)

    columns = [
        column[1]
        for column in cursor.fetchall()
    ]


    # ==========================================
    # ADD MISSING COLUMNS
    # ==========================================

    if "file_name" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN file_name TEXT
        """)

        print("Added file_name column.")


    if "file_path" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN file_path TEXT
        """)

        print("Added file_path column.")


    if "file_size" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN file_size INTEGER
        """)

        print("Added file_size column.")


    if "prediction" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN prediction TEXT DEFAULT 'Pending'
        """)

        print("Added prediction column.")


    if "confidence" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN confidence REAL DEFAULT 0
        """)

        print("Added confidence column.")


    if "threat_level" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN threat_level TEXT DEFAULT 'Unknown'
        """)

        print("Added threat_level column.")


    # ==========================================
    # BEHAVIOURAL SCAN FEATURES
    # ==========================================

    feature_columns = {
        "write_count": "INTEGER DEFAULT 0",
        "delete_count": "INTEGER DEFAULT 0",
        "create_count": "INTEGER DEFAULT 0",
        "rename_count": "INTEGER DEFAULT 0",
        "write_entropy": "REAL DEFAULT 0",
        "ext_diversity": "INTEGER DEFAULT 0",
        "sensitive_path_access": "INTEGER DEFAULT 0",
        "read_write_ratio": "REAL DEFAULT 0",
        "hidden_file_activity": "INTEGER DEFAULT 0",
        "execution_attempts": "INTEGER DEFAULT 0",
        "detection_score": "REAL DEFAULT 0",
        "detection_reasons": "TEXT DEFAULT ''"
    }

    for name, definition in feature_columns.items():
        if name not in columns:
            cursor.execute(f"ALTER TABLE scan_history ADD COLUMN {name} {definition}")


    # ==========================================
    # FILE ACTIVITY LOGS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            activity TEXT,
            status TEXT,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            path TEXT,
            process TEXT,
            extension TEXT,
            score REAL DEFAULT 0,
            reasons TEXT DEFAULT ''
        )
    """)

    activity_columns = {row[1] for row in cursor.execute("PRAGMA table_info(activity_logs)").fetchall()}
    for name, definition in {
        "path": "TEXT", "process": "TEXT", "extension": "TEXT",
        "score": "REAL DEFAULT 0", "reasons": "TEXT DEFAULT ''"
    }.items():
        if name not in activity_columns:
            cursor.execute(f"ALTER TABLE activity_logs ADD COLUMN {name} {definition}")


    # ==========================================
    # REMOTE MONITORING AGENTS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_name TEXT,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_id INTEGER,
            device_name TEXT,
            filename TEXT,
            extension TEXT,
            activity TEXT,
            path TEXT,
            process TEXT,
            status TEXT DEFAULT 'Safe',
            score REAL DEFAULT 0,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(device_id) REFERENCES agent_devices(id)
        )
    """)


    # ==========================================
    # REPORTS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            report_name TEXT,

            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY(user_id)
            REFERENCES users(id)

        )
    """)


    # ==========================================
    # SETTINGS
    # ==========================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER UNIQUE,

            dark_mode INTEGER DEFAULT 0,

            notifications INTEGER DEFAULT 1,

            monitoring INTEGER DEFAULT 1,

            scan_type TEXT DEFAULT 'Quick Scan',

            FOREIGN KEY(user_id)
            REFERENCES users(id)

        )
    """)


    conn.commit()
    conn.close()

    print("Database created/migrated successfully.")


# ==========================================
# RUN DATABASE SETUP
# ==========================================

if __name__ == "__main__":

    create_database()