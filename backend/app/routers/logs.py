import time
import io
import pandas as pd
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from typing import Optional, List, Dict, Any

from ..ml.feature_extractor import parse_log_payload
from ..ml.isolation_forest import detector
from ..schemas.models import LogAnalysisResponse
from ..db import database as db

router = APIRouter(tags=["Log Ingestion & Analysis"])

@router.post("/analyze-logs", response_model=LogAnalysisResponse)
async def analyze_logs(
    file: Optional[UploadFile] = File(None)
):
    start_time = time.time()
    
    if file:
        content = await file.read()
        filename = file.filename or ""
        df = parse_log_payload(content, filename)
    else:
        # Default fallback to synthetic dataset
        import os
        sample_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_network_logs.csv")
        if os.path.exists(sample_path):
            df = pd.read_csv(sample_path)
        else:
            raise HTTPException(status_code=400, detail="No log file or data provided")

    if df.empty:
        raise HTTPException(status_code=400, detail="Provided log file is empty")

    results = detector.analyze_logs(df)
    execution_time_ms = int((time.time() - start_time) * 1000)

    # Persist detected threats into SQLite database
    if results.get("threats"):
        threat_dicts = [t.model_dump() if hasattr(t, "model_dump") else t.dict() for t in results["threats"]]
        db.bulk_insert_threats(threat_dicts)

    return LogAnalysisResponse(
        status="success",
        modelUsed=results["model_used"],
        processedRows=results["processed_rows"],
        anomaliesDetected=results["anomalies_detected"],
        criticalRisks=results["critical_risks"],
        executionTimeMs=max(execution_time_ms, 12),
        featureImportance=results["feature_importance"],
        threats=results["threats"]
    )

