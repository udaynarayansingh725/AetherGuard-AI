import sys
import os

# Put backend in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from fastapi.testclient import TestClient
from app.main import app

def test_all():
    client = TestClient(app)
    
    print("\n--- 1. Testing GET / ---")
    r = client.get("/")
    assert r.status_code == 200, f"Root failed: {r.text}"
    assert "<!DOCTYPE html>" in r.text or "html" in r.headers.get("content-type", "")
    print("[OK] Root UI OK: Successfully served index.html")

    print("\n--- 2. Testing GET /api/v1/status ---")
    r = client.get("/api/v1/status")
    assert r.status_code == 200, f"Status failed: {r.text}"
    data = r.json()
    assert data["fastapi"] == "Connected"
    assert data["isolation_forest"] == "Ready"
    print("[OK] Status OK:", data)

    print("\n--- 3. Testing GET /api/v1/threats ---")
    r = client.get("/api/v1/threats")
    assert r.status_code == 200
    threats = r.json()
    assert len(threats) >= 5
    print(f"[OK] Threats OK ({len(threats)} loaded)")

    print("\n--- 3b. Testing GET /api/v1/threats/export (CSV Download) ---")
    r = client.get("/api/v1/threats/export")
    assert r.status_code == 200
    assert "sourceIp" in r.text
    assert "192.168.1.50" in r.text
    assert "text/csv" in r.headers.get("content-type", "")
    print("[OK] Threats CSV Export OK")

    print("\n--- 3c. Testing GET /api/v1/threats/THR-9021/report (IP Forensic Report) ---")
    r = client.get("/api/v1/threats/THR-9021/report")
    assert r.status_code == 200
    assert "192.168.1.50" in r.text
    assert "THREATLEN AI - SOC THREAT INCIDENT REPORT" in r.text
    print("[OK] Single Threat IP Forensic Report Download OK")

    print("\n--- 4. Testing GET /api/v1/incidents ---")
    r = client.get("/api/v1/incidents")
    assert r.status_code == 200
    incidents = r.json()
    assert len(incidents) >= 3
    print(f"[OK] Incidents OK ({len(incidents)} loaded)")

    print("\n--- 5. Testing POST /api/v1/ai/query ---")
    r = client.post("/api/v1/ai/query", json={"prompt": "Explain brute force attack on 192.168.1.50"})
    assert r.status_code == 200
    ai_res = r.json()
    assert "192.168.1.50" in ai_res["answer"]
    assert len(ai_res["recommendations"]) > 0
    print("[OK] AI Assistant OK:", ai_res["answer"][:100], "...")

    print("\n--- 6. Testing POST /api/v1/analyze-logs with sample CSV ---")
    sample_csv_path = os.path.join(os.path.dirname(__file__), "backend", "app", "data", "sample_network_logs.csv")
    with open(sample_csv_path, "rb") as f:
        files = {"file": ("sample_network_logs.csv", f, "text/csv")}
        r = client.post("/api/v1/analyze-logs", files=files)
    assert r.status_code == 200, f"Analysis failed: {r.text}"
    analysis = r.json()
    assert analysis["status"] == "success"
    assert analysis["processedRows"] > 0
    assert len(analysis["featureImportance"]) > 0
    print("[OK] Isolation Forest Analysis OK:")
    print("  Model:", analysis["modelUsed"])
    print("  Processed rows:", analysis["processedRows"])
    print("  Anomalies detected:", analysis["anomaliesDetected"])
    print("  Critical risks:", analysis["criticalRisks"])
    print("  Execution time (ms):", analysis["executionTimeMs"])
    print("  Feature importances:", analysis["featureImportance"])
    print(f"  Flagged threats: {len(analysis['threats'])}")

    print("\n--- 7. Testing POST /api/v1/reports/generate ---")
    r = client.post("/api/v1/reports/generate", json={"timeHorizon": "Last 24 Hours"})
    assert r.status_code == 200
    rep = r.json()
    assert rep["totalLogs"] == 12540
    print("[OK] Report Generation OK:", rep["reportId"])

    print("\n--- 8. Testing POST /api/v1/auth/login ---")

    r = client.post("/api/v1/auth/login", json={"email": "analyst@ibm.security", "password": "password123"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    login_data = r.json()
    assert login_data["status"] == "success"
    assert login_data["user"]["email"] == "analyst@ibm.security"
    assert "token" in login_data["access_token"]
    print("[OK] Auth Login OK:", login_data["user"]["name"], f"({login_data['user']['role']})")

    print("\n--- 9. Testing GET /api/v1/auth/users ---")
    r = client.get("/api/v1/auth/users")
    assert r.status_code == 200
    users = r.json()
    assert len(users) >= 4
    print(f"[OK] Auth Users OK ({len(users)} users loaded from DB)")

    print("\n--- 10. Testing POST /api/v1/threats/THR-9021/mitigate ---")
    r = client.post("/api/v1/threats/THR-9021/mitigate")
    assert r.status_code == 200
    mit_res = r.json()
    assert mit_res["status"] == "success"
    # Verify in DB that status is Mitigated
    r_check = client.get("/api/v1/threats/THR-9021")
    assert r_check.status_code == 200
    assert r_check.json()["status"] == "Mitigated"
    print("[OK] Threat Mitigation OK: THR-9021 status updated to 'Mitigated' in DB")

    print("\n--- 11. Testing GET /api/v1/database/status ---")
    r = client.get("/api/v1/database/status")
    assert r.status_code == 200
    db_status = r.json()
    assert "primary_database" in db_status
    assert "provider" in db_status
    print(f"[OK] Database Telemetry OK: Primary is '{db_status['primary_database']}' (Provider: {db_status['provider']})")

    print("\n==========================================")
    print(" ALL BACKEND TESTS PASSED SUCCESSFULLY! ")
    print("==========================================\n")

if __name__ == "__main__":
    test_all()


