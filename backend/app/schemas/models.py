from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class SystemStatus(BaseModel):
    status: str = "healthy"
    fastapi: str = "Connected"
    isolation_forest: str = "Ready"
    version: str = "v3.4-e"
    active_threats: int = 5
    active_incidents: int = 3
    model_contamination: float = 0.05
    n_estimators: int = 100

class Threat(BaseModel):
    id: str
    sourceIp: str
    destIp: str
    port: int
    protocol: str
    requests: int
    failedLogins: int
    anomalyScore: float
    threatType: str
    risk: str
    timestamp: str
    status: str
    accountsTargeted: int
    country: str
    targetService: str

class Incident(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    assignedTo: str
    eventsCount: int
    sourceIp: str
    createdAt: str
    summary: str

class UserProfile(BaseModel):
    id: str
    name: str
    email: str
    role: str
    status: str
    lastLogin: str
    avatar: str

class FeatureImportance(BaseModel):
    failed_logins: float
    request_count: float
    port_variance: float
    time_delta: float

class LogAnalysisResponse(BaseModel):
    status: str
    modelUsed: str
    processedRows: int
    anomaliesDetected: int
    criticalRisks: int
    executionTimeMs: int
    featureImportance: Dict[str, float]
    threats: List[Threat] = []

class AIQueryRequest(BaseModel):
    prompt: str
    context: Optional[Dict[str, Any]] = None

class AIQueryResponse(BaseModel):
    answer: str
    threat_id: Optional[str] = None
    recommendations: List[str] = []
    timestamp: str

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    status: str
    access_token: str
    token_type: str = "bearer"
    user: UserProfile

class ReportRequest(BaseModel):
    timeHorizon: str = "Last 24 Hours"
    detailLevel: str = "Full Anomaly Model Diagnostics (Technical)"

class ReportResponse(BaseModel):
    reportId: str
    title: str
    timeHorizon: str
    generatedAt: str
    totalLogs: int
    criticalIncidents: int
    threatBreakdown: Dict[str, int]
    executiveSummary: str
