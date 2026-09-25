from fastapi import APIRouter, HTTPException
from typing import List
from ..schemas.models import Incident
from ..db import database as db

router = APIRouter(prefix="/incidents", tags=["Incidents Correlation"])

@router.get("", response_model=List[Incident])
async def get_incidents():
    records = db.get_all_incidents()
    return [Incident(**r) for r in records]

@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    records = db.get_all_incidents()
    for inc in records:
        if inc["id"].lower() == incident_id.lower():
            return Incident(**inc)
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

