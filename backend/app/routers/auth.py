from fastapi import APIRouter, HTTPException
from ..schemas.models import LoginRequest, LoginResponse, UserProfile

router = APIRouter(prefix="/auth", tags=["Authentication"])

MOCK_USER = UserProfile(
    id="USR-01",
    name="Dr. Elena Vance",
    email="analyst@ibm.security",
    role="Security Analyst",
    status="Active",
    lastLogin="2026-09-22 15:10",
    avatar="EV"
)

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    if not request.email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    return LoginResponse(
        status="success",
        access_token="aetherguard_jwt_token_sample_8f90a",
        token_type="bearer",
        user=MOCK_USER
    )

@router.post("/register")
async def register(payload: dict):
    return {
        "status": "success",
        "message": f"Analyst profile {payload.get('email', 'new_user')} registered successfully.",
        "user_id": "USR-05"
    }
