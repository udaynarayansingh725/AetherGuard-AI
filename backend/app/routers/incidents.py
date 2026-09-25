from fastapi import APIRouter, HTTPException
from typing import List
from ..schemas.models import Incident

router = APIRouter(prefix="/incidents", tags=["Incidents Correlation"])

INCIDENTS: List[Incident] = [
    Incident(
        id="INC-2026-00421",
        title="Possible Brute Force Attack on Internal SSH Cluster",
        severity="Critical",
        status="Open",
        assignedTo="Sarah Connor (Analyst)",
        eventsCount=147,
        sourceIp="192.168.1.50",
        createdAt="2026-09-20 17:14:02",
        summary="High volume of failed authentication requests targeted against root and admin accounts within 120 seconds."
    ),
    Incident(
        id="INC-2026-00420",
        title="Internal Subnet Port Sweep Activity Detected",
        severity="High",
        status="In Progress",
        assignedTo="Alex Mercer",
        eventsCount=3400,
        sourceIp="192.168.1.105",
        createdAt="2026-09-20 16:55:00",
        summary="Sequential TCP SYN requests sent across 254 endpoints on management subnet."
    ),
    Incident(
        id="INC-2026-00419",
        title="Volumetric Traffic Anomaly on Public API Gateway",
        severity="Critical",
        status="Investigating",
        assignedTo="AI Guard Auto-Task",
        eventsCount=14200,
        sourceIp="10.0.12.88",
        createdAt="2026-09-20 17:12:45",
        summary="Requests/sec exceeded baseline by 840%. Potential HTTP Flood or misconfigured daemon."
    )
]

@router.get("", response_model=List[Incident])
async def get_incidents():
    return INCIDENTS

@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    for inc in INCIDENTS:
        if inc.id.lower() == incident_id.lower():
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
