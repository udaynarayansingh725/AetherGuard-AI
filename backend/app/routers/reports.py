from datetime import datetime
from fastapi import APIRouter
from ..schemas.models import ReportRequest, ReportResponse

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.post("/generate", response_model=ReportResponse)
async def generate_report(request: ReportRequest):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_id = f"REP-{datetime.now().strftime('%Y%m%d%H%M')}"
    
    return ReportResponse(
        reportId=report_id,
        title=f"AetherGuard Executive Threat Intelligence Report ({request.timeHorizon})",
        timeHorizon=request.timeHorizon,
        generatedAt=now_str,
        totalLogs=12540,
        criticalIncidents=3,
        threatBreakdown={
            "Brute Force": 420,
            "Port Scanning": 210,
            "Abnormal Login": 125,
            "DoS-like Pattern": 78
        },
        executiveSummary=(
            f"During the {request.timeHorizon} monitoring period, AetherGuard AI inspected 12,540 log records. "
            "The Scikit-Learn Isolation Forest model identified 1,964 anomalous deviations, of which 755 were classified as High or Critical severity. "
            "Key incident: Brute force attempts on SSH cluster (192.168.1.50) successfully quarantined."
        )
    )
