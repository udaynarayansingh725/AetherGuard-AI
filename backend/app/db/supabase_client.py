import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    from dotenv import load_dotenv
    # Load .env from backend directory or project root
    load_dotenv()
    root_env = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), ".env")
    if os.path.exists(root_env):
        load_dotenv(root_env)
except Exception:
    pass

try:
    from supabase import create_client, Client
    SUPABASE_SDK_AVAILABLE = True
except ImportError:
    SUPABASE_SDK_AVAILABLE = False
    Client = Any

# Global client cache
_supabase_client: Optional[Any] = None
_last_tested_status: Dict[str, Any] = {
    "connected": False,
    "latency_ms": 0,
    "last_checked": None,
    "error": "Not configured"
}

def get_supabase_credentials() -> tuple[Optional[str], Optional[str]]:
    """Retrieve Supabase URL and Key from environment or settings file."""
    url = os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
    key = os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    return url, key

def is_supabase_configured() -> bool:
    url, key = get_supabase_credentials()
    return bool(url and key and url.startswith("http") and not "your-project" in url)

def get_supabase_client():
    """Initializes or returns cached Supabase client."""
    global _supabase_client
    if not SUPABASE_SDK_AVAILABLE:
        return None

    url, key = get_supabase_credentials()
    if not (url and key and url.startswith("http") and not "your-project" in url):
        return None

    if _supabase_client is None:
        try:
            _supabase_client = create_client(url, key)
        except Exception as e:
            print(f"[Supabase] Client creation failed: {e}")
            return None

    return _supabase_client

def test_supabase_connection() -> Dict[str, Any]:
    """Tests live connection to Supabase Cloud."""
    global _last_tested_status
    if not is_supabase_configured():
        _last_tested_status = {
            "connected": False,
            "latency_ms": 0,
            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": "SUPABASE_URL or SUPABASE_KEY not configured in environment"
        }
        return _last_tested_status

    client = get_supabase_client()
    if not client:
        _last_tested_status = {
            "connected": False,
            "latency_ms": 0,
            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": "Failed to initialize Supabase client"
        }
        return _last_tested_status

    start = time.time()
    try:
        # Quick ping query against 'settings' or 'threats'
        res = client.table("settings").select("key").limit(1).execute()
        latency = int((time.time() - start) * 1000)
        _last_tested_status = {
            "connected": True,
            "latency_ms": latency,
            "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": None
        }
    except Exception as e:
        # Fallback test with threats table
        try:
            res = client.table("threats").select("id").limit(1).execute()
            latency = int((time.time() - start) * 1000)
            _last_tested_status = {
                "connected": True,
                "latency_ms": latency,
                "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": None
            }
        except Exception as e2:
            _last_tested_status = {
                "connected": False,
                "latency_ms": 0,
                "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e2)
            }

    return _last_tested_status

# --- Threat Data Operations on Supabase ---
def supabase_get_all_threats(risk: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    query = client.table("threats").select("*").order("timestamp", desc=True)
    if risk and risk.lower() != "all":
        query = query.ilike("risk", risk)
    
    res = query.execute()
    rows = res.data or []

    result = []
    for r in rows:
        # Apply search filter if present
        if search:
            s_lower = search.lower()
            if s_lower not in str(r.get("source_ip", "")).lower() and s_lower not in str(r.get("threat_type", "")).lower():
                continue

        result.append({
            "id": r["id"],
            "sourceIp": r["source_ip"],
            "destIp": r["dest_ip"],
            "port": r["port"],
            "protocol": r["protocol"],
            "requests": r["requests"],
            "failedLogins": r["failed_logins"],
            "anomalyScore": float(r["anomaly_score"]),
            "threatType": r["threat_type"],
            "risk": r["risk"],
            "timestamp": r["timestamp"],
            "status": r.get("status", "Active"),
            "accountsTargeted": r.get("accounts_targeted", 1),
            "country": r.get("country", "EXTERNAL"),
            "targetService": r.get("target_service", "Unknown")
        })
    return result

def supabase_get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("threats").select("*").or_(f"id.ilike.{threat_id},source_ip.eq.{threat_id}").limit(1).execute()
    rows = res.data or []
    if not rows:
        return None
    r = rows[0]
    return {
        "id": r["id"],
        "sourceIp": r["source_ip"],
        "destIp": r["dest_ip"],
        "port": r["port"],
        "protocol": r["protocol"],
        "requests": r["requests"],
        "failedLogins": r["failed_logins"],
        "anomalyScore": float(r["anomaly_score"]),
        "threatType": r["threat_type"],
        "risk": r["risk"],
        "timestamp": r["timestamp"],
        "status": r.get("status", "Active"),
        "accountsTargeted": r.get("accounts_targeted", 1),
        "country": r.get("country", "EXTERNAL"),
        "targetService": r.get("target_service", "Unknown")
    }

def supabase_add_threat(t: Dict[str, Any]) -> str:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    record = {
        "id": t["id"],
        "source_ip": t["sourceIp"],
        "dest_ip": t["destIp"],
        "port": int(t["port"]),
        "protocol": t["protocol"],
        "requests": int(t["requests"]),
        "failed_logins": int(t["failedLogins"]),
        "anomaly_score": float(t["anomalyScore"]),
        "threat_type": t["threatType"],
        "risk": t["risk"],
        "timestamp": t["timestamp"],
        "status": t.get("status", "Active"),
        "accounts_targeted": int(t.get("accountsTargeted", 1)),
        "country": t.get("country", "EXTERNAL"),
        "target_service": t.get("targetService", "Unknown")
    }
    client.table("threats").upsert(record).execute()
    return t["id"]

def supabase_bulk_insert_threats(threats_list: List[Dict[str, Any]]):
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    records = []
    for t in threats_list:
        records.append({
            "id": t["id"],
            "source_ip": t["sourceIp"],
            "dest_ip": t["destIp"],
            "port": int(t["port"]),
            "protocol": t["protocol"],
            "requests": int(t["requests"]),
            "failed_logins": int(t["failedLogins"]),
            "anomaly_score": float(t["anomalyScore"]),
            "threat_type": t["threatType"],
            "risk": t["risk"],
            "timestamp": t["timestamp"],
            "status": t.get("status", "Active"),
            "accounts_targeted": int(t.get("accountsTargeted", 1)),
            "country": t.get("country", "EXTERNAL"),
            "target_service": t.get("targetService", "Unknown")
        })
    if records:
        client.table("threats").upsert(records).execute()

def supabase_mitigate_threat(threat_id: str) -> bool:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("threats").update({"status": "Mitigated"}).ilike("id", threat_id).execute()
    success = bool(res.data and len(res.data) > 0)
    if success:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client.table("audit_logs").insert({
            "action": "THREAT_MITIGATED",
            "details": f"Threat {threat_id} quarantined and firewall drop applied in Supabase Cloud.",
            "timestamp": now,
            "user_id": "SOC_ANALYST"
        }).execute()
    return success

# --- Incident Operations on Supabase ---
def supabase_get_all_incidents() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("incidents").select("*").order("created_at", desc=True).execute()
    rows = res.data or []
    return [{
        "id": r["id"],
        "title": r["title"],
        "severity": r["severity"],
        "status": r.get("status", "Open"),
        "assignedTo": r.get("assigned_to", "AI Auto-Task"),
        "eventsCount": r.get("events_count", 1),
        "sourceIp": r.get("source_ip", "Unknown"),
        "summary": r.get("summary", ""),
        "createdAt": r["created_at"]
    } for r in rows]

def supabase_add_incident(inc: Dict[str, Any]) -> str:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    record = {
        "id": inc["id"],
        "title": inc["title"],
        "severity": inc["severity"],
        "status": inc.get("status", "Open"),
        "assigned_to": inc.get("assignedTo", "AI Auto-Task"),
        "events_count": int(inc.get("eventsCount", 1)),
        "source_ip": inc.get("sourceIp", "Unknown"),
        "summary": inc.get("summary", ""),
        "created_at": inc["createdAt"]
    }
    client.table("incidents").upsert(record).execute()
    return inc["id"]

# --- User & Auth Operations on Supabase ---
def supabase_get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("users").select("*").ilike("email", email).limit(1).execute()
    rows = res.data or []
    if not rows:
        return None
    r = rows[0]
    return {
        "id": r["id"],
        "name": r["name"],
        "email": r["email"],
        "role": r["role"],
        "status": r.get("status", "Active"),
        "lastLogin": r.get("last_login", "Just Now"),
        "avatar": r.get("avatar", "SA")
    }

def supabase_get_all_users() -> List[Dict[str, Any]]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("users").select("id, name, email, role, status, last_login, avatar").execute()
    rows = res.data or []
    return [{
        "id": r["id"],
        "name": r["name"],
        "email": r["email"],
        "role": r["role"],
        "status": r.get("status", "Active"),
        "lastLogin": r.get("last_login", "Active"),
        "avatar": r.get("avatar", "SA")
    } for r in rows]

def supabase_register_user(name: str, email: str, role: str = "Security Analyst") -> Dict[str, Any]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    user_id = f"USR-{datetime.now().strftime('%m%d%H%M')}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    avatar = "".join([part[0].upper() for part in name.split()[:2]]) or "SA"

    record = {
        "id": user_id,
        "name": name,
        "email": email,
        "password_hash": "supabase_auth_token",
        "role": role,
        "status": "Active",
        "last_login": now,
        "avatar": avatar,
        "created_at": now
    }
    client.table("users").insert(record).execute()
    return {
        "id": user_id,
        "name": name,
        "email": email,
        "role": role,
        "status": "Active",
        "lastLogin": now,
        "avatar": avatar
    }

# --- Settings & Telemetry Stats on Supabase ---
def supabase_save_setting(key: str, value: str):
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client.table("settings").upsert({
        "key": key,
        "value": value,
        "updated_at": now
    }).execute()

def supabase_get_setting(key: str, default: Any = None) -> Any:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    res = client.table("settings").select("value").eq("key", key).limit(1).execute()
    rows = res.data or []
    if rows:
        return rows[0]["value"]
    return default

def supabase_get_stats() -> Dict[str, int]:
    client = get_supabase_client()
    if not client:
        raise ConnectionError("Supabase not configured")

    threats_res = client.table("threats").select("id", count="exact").execute()
    incidents_res = client.table("incidents").select("id", count="exact").execute()
    users_res = client.table("users").select("id", count="exact").execute()

    return {
        "threats": threats_res.count if hasattr(threats_res, 'count') and threats_res.count is not None else len(threats_res.data or []),
        "incidents": incidents_res.count if hasattr(incidents_res, 'count') and incidents_res.count is not None else len(incidents_res.data or []),
        "users": users_res.count if hasattr(users_res, 'count') and users_res.count is not None else len(users_res.data or [])
    }
