from fastapi import APIRouter, HTTPException, Query, Response
from typing import List, Optional
from ..schemas.models import Threat
from ..db import database as db

router = APIRouter(prefix="/threats", tags=["Threat Detection"])

@router.get("", response_model=List[Threat])
async def get_threats(
    risk: Optional[str] = Query(None, description="Filter by risk (Critical, High, Medium, Low)"),
    search: Optional[str] = Query(None, description="Search by IP or Threat Type")
):
    """Retrieve threats from SQLite database with risk and search filters"""
    records = db.get_all_threats(risk=risk, search=search)
    return [Threat(**r) for r in records]

@router.get("/export")
async def export_threats_csv():
    """Export all detected threats from SQLite database as CSV file download"""
    records = db.get_all_threats()
    lines = ["id,sourceIp,destIp,port,protocol,requests,failedLogins,anomalyScore,threatType,risk,status,timestamp,accountsTargeted,country,targetService"]
    for t in records:
        lines.append(f"{t['id']},{t['sourceIp']},{t['destIp']},{t['port']},{t['protocol']},{t['requests']},{t['failedLogins']},{t['anomalyScore']},{t['threatType']},{t['risk']},{t['status']},{t['timestamp']},{t.get('accountsTargeted', 0)},{t.get('country', '')},{t.get('targetService', '')}")
    csv_content = "\n".join(lines)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aetherguard_threats_export.csv"}
    )

@router.get("/{threat_id}", response_model=Threat)
async def get_threat_by_id(threat_id: str):
    """Retrieve single threat from SQLite database by ID or Source IP"""
    t = db.get_threat_by_id(threat_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
    return Threat(**t)

@router.get("/{threat_id}/report")
async def export_threat_report(threat_id: str):
    """Export detailed forensic investigation report from SQLite database for an IP"""
    threat = db.get_threat_by_id(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

    report_text = f"""================================================================================
                AETHERGUARD AI - SOC THREAT INCIDENT REPORT
================================================================================
Incident Reference ID : {threat['id']}
Target Source IP      : {threat['sourceIp']}
Destination IP        : {threat['destIp']}
Port / Protocol       : {threat['port']} ({threat['protocol']})
Target Service        : {threat.get('targetService') or 'N/A'}
Risk Severity Level   : {threat['risk'].upper()}
ML Anomaly Score      : {threat['anomalyScore']} / 1.00
Threat Classification : {threat['threatType']}
Incident Status       : {threat['status']}
Timestamp Recorded    : {threat['timestamp']}
Origin Location       : {threat.get('country') or 'Unknown'}
--------------------------------------------------------------------------------
[1] TELEMETRY SUMMARY
- Total Requests Logged  : {threat['requests']}
- Failed Authentication  : {threat['failedLogins']}
- Accounts Targeted      : {threat.get('accountsTargeted', 0)} user accounts

[2] AI MODEL EXPLANATION (Scikit-Learn Isolation Forest)
Source IP {threat['sourceIp']} generated {threat['requests']} requests with {threat['failedLogins']} failed
attempts targeting service {threat.get('targetService') or threat['protocol']} on port {threat['port']}.
Anomaly score of {threat['anomalyScore']} exceeds baseline threshold (0.70).
Pattern matches signature: {threat['threatType']}.

[3] RECOMMENDED REMEDIATION ACTIONS
1. Quarantine source IP {threat['sourceIp']} on edge firewall / security group.
2. Invalidate sessions and force password reset for targeted user accounts.
3. Review audit logs for lateral movement within destination host {threat['destIp']}.
4. Enforce strict rate-limiting on port {threat['port']}.
================================================================================
CONFIDENTIAL - AUTHORIZED SOC PERSONNEL ONLY - AETHERGUARD AI
================================================================================
"""
    filename = f"Threat_Report_{threat['sourceIp'].replace('.', '_')}_{threat['id']}.txt"
    return Response(
        content=report_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/{threat_id}/mitigate")
async def mitigate_threat(threat_id: str):
    """Mitigate threat in SQLite database and log audit trail"""
    success = db.mitigate_threat(threat_id)
    if not success:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"status": "success", "message": f"Threat {threat_id} successfully isolated & firewall rule applied in database."}

