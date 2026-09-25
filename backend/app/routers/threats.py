from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from ..schemas.models import Threat

router = APIRouter(prefix="/threats", tags=["Threat Detection"])

# Initial threat telemetry records
CURRENT_THREATS: List[Threat] = [
    Threat(
        id="THR-9021",
        sourceIp="192.168.1.50",
        destIp="10.0.4.12",
        port=22,
        protocol="SSH",
        requests=500,
        failedLogins=147,
        anomalyScore=0.94,
        threatType="Brute Force",
        risk="Critical",
        timestamp="2026-09-20 17:14:02",
        status="Active",
        accountsTargeted=18,
        country="US-EAST",
        targetService="OpenSSH 8.9"
    ),
    Threat(
        id="THR-9022",
        sourceIp="10.0.12.88",
        destIp="10.0.2.1",
        port=443,
        protocol="HTTPS",
        requests=14200,
        failedLogins=2,
        anomalyScore=0.88,
        threatType="DoS-like Pattern",
        risk="Critical",
        timestamp="2026-09-20 17:12:45",
        status="Investigating",
        accountsTargeted=1,
        country="INTERNAL",
        targetService="Nginx Gateway"
    ),
    Threat(
        id="THR-9023",
        sourceIp="172.16.42.11",
        destIp="10.0.10.15",
        port=3389,
        protocol="RDP",
        requests=840,
        failedLogins=89,
        anomalyScore=0.81,
        threatType="Abnormal Login",
        risk="High",
        timestamp="2026-09-20 17:08:19",
        status="Active",
        accountsTargeted=4,
        country="EU-WEST",
        targetService="WinRDP"
    ),
    Threat(
        id="THR-9024",
        sourceIp="192.168.1.105",
        destIp="10.0.1.0/24",
        port=80,
        protocol="TCP",
        requests=3400,
        failedLogins=0,
        anomalyScore=0.76,
        threatType="Port Scanning",
        risk="High",
        timestamp="2026-09-20 16:55:00",
        status="Mitigated",
        accountsTargeted=0,
        country="ASIA-PAC",
        targetService="Subnet Sweep"
    ),
    Threat(
        id="THR-9025",
        sourceIp="45.142.120.9",
        destIp="10.0.4.50",
        port=8080,
        protocol="HTTP",
        requests=120,
        failedLogins=12,
        anomalyScore=0.65,
        threatType="Suspicious IP Behaviour",
        risk="Medium",
        timestamp="2026-09-20 16:42:11",
        status="Investigating",
        accountsTargeted=2,
        country="RU-NET",
        targetService="Apache Tomcat"
    ),
    Threat(
        id="THR-9026",
        sourceIp="10.0.5.112",
        destIp="10.0.4.12",
        port=443,
        protocol="HTTPS",
        requests=45,
        failedLogins=1,
        anomalyScore=0.22,
        threatType="Normal Baseline",
        risk="Low",
        timestamp="2026-09-20 16:30:00",
        status="Closed",
        accountsTargeted=1,
        country="INTERNAL",
        targetService="Internal Portal"
    ),
    Threat(
        id="THR-9027",
        sourceIp="198.51.100.42",
        destIp="10.0.2.80",
        port=21,
        protocol="FTP",
        requests=620,
        failedLogins=41,
        anomalyScore=0.79,
        threatType="Brute Force",
        risk="High",
        timestamp="2026-09-20 16:15:33",
        status="Active",
        accountsTargeted=6,
        country="SA-EAST",
        targetService="vsftpd"
    )
]

@router.get("", response_model=List[Threat])
async def get_threats(
    risk: Optional[str] = Query(None, description="Filter by risk (Critical, High, Medium, Low)"),
    search: Optional[str] = Query(None, description="Search by IP or Threat Type")
):
    results = CURRENT_THREATS
    if risk and risk != "All":
        results = [t for t in results if t.risk.lower() == risk.lower()]
    if search:
        s = search.lower()
        results = [t for t in results if s in t.sourceIp.lower() or s in t.threatType.lower()]
    return results

@router.get("/{threat_id}", response_model=Threat)
async def get_threat_by_id(threat_id: str):
    for t in CURRENT_THREATS:
        if t.id.lower() == threat_id.lower():
            return t
    raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

@router.post("/{threat_id}/mitigate")
async def mitigate_threat(threat_id: str):
    for t in CURRENT_THREATS:
        if t.id.lower() == threat_id.lower():
            t.status = "Mitigated"
            return {"status": "success", "message": f"Threat {threat_id} ({t.sourceIp}) successfully isolated & firewall rule applied."}
    raise HTTPException(status_code=404, detail="Threat not found")
