import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "aetherguard.db")

def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and seed baseline telemetry if empty."""
    conn = get_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        role TEXT NOT NULL,
        status TEXT DEFAULT 'Active',
        last_login TEXT,
        avatar TEXT,
        created_at TEXT
    );
    """)

    # 2. Threats Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        requests INTEGER NOT NULL,
        failed_logins INTEGER NOT NULL,
        anomaly_score REAL NOT NULL,
        threat_type TEXT NOT NULL,
        risk TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT DEFAULT 'Active',
        accounts_targeted INTEGER DEFAULT 1,
        country TEXT,
        target_service TEXT
    );
    """)

    # 3. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT DEFAULT 'Open',
        assigned_to TEXT,
        events_count INTEGER,
        source_ip TEXT,
        summary TEXT,
        created_at TEXT
    );
    """)

    # 4. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT,
        user_id TEXT,
        timestamp TEXT NOT NULL
    );
    """)

    # 5. Settings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT
    );
    """)

    conn.commit()

    # Seed initial baseline data if tables are empty
    _seed_initial_data(conn)
    conn.close()

def _seed_initial_data(conn):
    cursor = conn.cursor()

    # Seed default users
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        initial_users = [
            ("USR-01", "Dr. Elena Vance", "analyst@ibm.security", "pbkdf2:sha256:sample", "Lead SOC Analyst", "Active", now, "EV", now),
            ("USR-02", "Marcus Holloway", "marcus.h@ibm.security", "pbkdf2:sha256:sample", "Security Analyst", "Active", now, "MH", now),
            ("USR-03", "Sarah Connor", "s.connor@ibm.security", "pbkdf2:sha256:sample", "Incident Responder", "Active", now, "SC", now),
            ("USR-04", "Devon Miles", "devon.m@ibm.security", "pbkdf2:sha256:sample", "Viewer", "Inactive", now, "DM", now)
        ]
        cursor.executemany("""
        INSERT INTO users (id, name, email, password_hash, role, status, last_login, avatar, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_users)

    # Seed baseline threats
    cursor.execute("SELECT COUNT(*) FROM threats")
    if cursor.fetchone()[0] == 0:
        initial_threats = [
            ("THR-9021", "192.168.1.50", "10.0.4.12", 22, "SSH", 500, 147, 0.94, "Brute Force", "Critical", "2026-09-20 17:14:02", "Active", 18, "US-EAST", "OpenSSH 8.9"),
            ("THR-9022", "10.0.12.88", "10.0.2.1", 443, "HTTPS", 14200, 2, 0.88, "DoS-like Pattern", "Critical", "2026-09-20 17:12:45", "Investigating", 1, "INTERNAL", "Nginx Gateway"),
            ("THR-9023", "172.16.42.11", "10.0.10.15", 3389, "RDP", 840, 89, 0.81, "Abnormal Login", "High", "2026-09-20 17:08:19", "Active", 4, "EU-WEST", "WinRDP"),
            ("THR-9024", "192.168.1.105", "10.0.1.0/24", 80, "TCP", 3400, 0, 0.76, "Port Scanning", "High", "2026-09-20 16:55:00", "Mitigated", 0, "ASIA-PAC", "Subnet Sweep"),
            ("THR-9025", "45.142.120.9", "10.0.4.50", 8080, "HTTP", 120, 12, 0.65, "Suspicious IP Behaviour", "Medium", "2026-09-20 16:42:11", "Investigating", 2, "RU-NET", "Apache Tomcat"),
            ("THR-9026", "10.0.5.112", "10.0.4.12", 443, "HTTPS", 45, 1, 0.22, "Normal Baseline", "Low", "2026-09-20 16:30:00", "Closed", 1, "INTERNAL", "Internal Portal"),
            ("THR-9027", "198.51.100.42", "10.0.2.80", 21, "FTP", 620, 41, 0.79, "Brute Force", "High", "2026-09-20 16:15:33", "Active", 6, "SA-EAST", "vsftpd")
        ]
        cursor.executemany("""
        INSERT INTO threats (id, source_ip, dest_ip, port, protocol, requests, failed_logins, anomaly_score, threat_type, risk, timestamp, status, accounts_targeted, country, target_service)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_threats)

    # Seed baseline incidents
    cursor.execute("SELECT COUNT(*) FROM incidents")
    if cursor.fetchone()[0] == 0:
        initial_incidents = [
            ("INC-2026-00421", "Possible Brute Force Attack on Internal SSH Cluster", "Critical", "Open", "Dr. Elena Vance", 147, "192.168.1.50", "High volume of failed authentication requests targeted against root and admin accounts within 120 seconds.", "2026-09-20 17:14:02"),
            ("INC-2026-00420", "Internal Subnet Port Sweep Activity Detected", "High", "In Progress", "Marcus Holloway", 3400, "192.168.1.105", "Sequential TCP SYN requests sent across 254 endpoints on management subnet.", "2026-09-20 16:55:00"),
            ("INC-2026-00419", "Volumetric Traffic Anomaly on Public API Gateway", "Critical", "Investigating", "Sarah Connor", 14200, "10.0.12.88", "Requests/sec exceeded baseline by 840%. Potential HTTP Flood or misconfigured daemon.", "2026-09-20 17:12:45")
        ]
        cursor.executemany("""
        INSERT INTO incidents (id, title, severity, status, assigned_to, events_count, source_ip, summary, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_incidents)

    # Seed baseline audit log
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    if cursor.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO audit_logs (action, details, user_id, timestamp) VALUES (?, ?, ?, ?)",
                       ("SYSTEM_BOOT", "AetherGuard AI SOC Database initialized successfully.", "SYSTEM", now))

    conn.commit()

# --- Threat Data Access Methods ---
def get_all_threats(risk: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM threats WHERE 1=1"
    params = []

    if risk and risk.lower() != "all":
        query += " AND LOWER(risk) = LOWER(?)"
        params.append(risk)

    if search:
        query += " AND (LOWER(source_ip) LIKE ? OR LOWER(threat_type) LIKE ?)"
        s = f"%{search.lower()}%"
        params.extend([s, s])

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "sourceIp": r["source_ip"],
            "destIp": r["dest_ip"],
            "port": r["port"],
            "protocol": r["protocol"],
            "requests": r["requests"],
            "failedLogins": r["failed_logins"],
            "anomalyScore": r["anomaly_score"],
            "threatType": r["threat_type"],
            "risk": r["risk"],
            "timestamp": r["timestamp"],
            "status": r["status"],
            "accountsTargeted": r["accounts_targeted"],
            "country": r["country"],
            "targetService": r["target_service"]
        })
    return result

def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats WHERE LOWER(id) = LOWER(?) OR source_ip = ?", (threat_id, threat_id))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r["id"],
        "sourceIp": r["source_ip"],
        "destIp": r["dest_ip"],
        "port": r["port"],
        "protocol": r["protocol"],
        "requests": r["requests"],
        "failedLogins": r["failed_logins"],
        "anomalyScore": r["anomaly_score"],
        "threatType": r["threat_type"],
        "risk": r["risk"],
        "timestamp": r["timestamp"],
        "status": r["status"],
        "accountsTargeted": r["accounts_targeted"],
        "country": r["country"],
        "targetService": r["target_service"]
    }

def add_threat(t: Dict[str, Any]) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO threats (
        id, source_ip, dest_ip, port, protocol, requests, failed_logins, anomaly_score, threat_type, risk, timestamp, status, accounts_targeted, country, target_service
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        t["id"], t["sourceIp"], t["destIp"], t["port"], t["protocol"],
        t["requests"], t["failedLogins"], t["anomalyScore"], t["threatType"],
        t["risk"], t["timestamp"], t.get("status", "Active"),
        t.get("accountsTargeted", 1), t.get("country", "EXTERNAL"), t.get("targetService", "Unknown")
    ))
    conn.commit()
    conn.close()
    return t["id"]

def bulk_insert_threats(threats_list: List[Dict[str, Any]]):
    conn = get_connection()
    cursor = conn.cursor()
    for t in threats_list:
        cursor.execute("""
        INSERT OR REPLACE INTO threats (
            id, source_ip, dest_ip, port, protocol, requests, failed_logins, anomaly_score, threat_type, risk, timestamp, status, accounts_targeted, country, target_service
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            t["id"], t["sourceIp"], t["destIp"], t["port"], t["protocol"],
            t["requests"], t["failedLogins"], t["anomalyScore"], t["threatType"],
            t["risk"], t["timestamp"], t.get("status", "Active"),
            t.get("accountsTargeted", 1), t.get("country", "EXTERNAL"), t.get("targetService", "Unknown")
        ))
    conn.commit()
    conn.close()

def mitigate_threat(threat_id: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE threats SET status = 'Mitigated' WHERE LOWER(id) = LOWER(?)", (threat_id,))
    success = cursor.rowcount > 0
    if success:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO audit_logs (action, details, timestamp) VALUES (?, ?, ?)",
                       ("THREAT_MITIGATED", f"Threat {threat_id} quarantined and firewall drop applied.", now))
    conn.commit()
    conn.close()
    return success

# --- Incident Data Access Methods ---
def get_all_incidents() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "assignedTo": r["assigned_to"],
            "eventsCount": r["events_count"],
            "sourceIp": r["source_ip"],
            "summary": r["summary"],
            "createdAt": r["created_at"]
        })
    return result

def add_incident(inc: Dict[str, Any]) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO incidents (id, title, severity, status, assigned_to, events_count, source_ip, summary, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        inc["id"], inc["title"], inc["severity"], inc.get("status", "Open"),
        inc.get("assignedTo", "AI Auto-Task"), inc.get("eventsCount", 1),
        inc.get("sourceIp", "Unknown"), inc.get("summary", ""), inc["createdAt"]
    ))
    conn.commit()
    conn.close()
    return inc["id"]

# --- User & Auth Methods ---
def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r["id"],
        "name": r["name"],
        "email": r["email"],
        "role": r["role"],
        "status": r["status"],
        "lastLogin": r["last_login"],
        "avatar": r["avatar"]
    }

def get_all_users() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, role, status, last_login, avatar FROM users")
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r["id"], "name": r["name"], "email": r["email"],
        "role": r["role"], "status": r["status"], "lastLogin": r["last_login"],
        "avatar": r["avatar"]
    } for r in rows]

def register_user(name: str, email: str, role: str = "Security Analyst") -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    user_id = f"USR-{datetime.now().strftime('%m%d%H%M')}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    avatar = "".join([part[0].upper() for part in name.split()[:2]]) or "SA"

    cursor.execute("""
    INSERT INTO users (id, name, email, password_hash, role, status, last_login, avatar, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, name, email, "hashed_token", role, "Active", now, avatar, now))
    conn.commit()
    conn.close()
    return {
        "id": user_id, "name": name, "email": email, "role": role,
        "status": "Active", "lastLogin": now, "avatar": avatar
    }

# --- Settings & Audit Access ---
def save_setting(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)", (key, value, now))
    conn.commit()
    conn.close()

def get_setting(key: str, default: Any = None) -> Any:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    r = cursor.fetchone()
    conn.close()
    return r["value"] if r else default

def get_db_stats() -> Dict[str, int]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM threats")
    threat_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM incidents")
    incident_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()
    return {
        "threats": threat_count,
        "incidents": incident_count,
        "users": user_count
    }
