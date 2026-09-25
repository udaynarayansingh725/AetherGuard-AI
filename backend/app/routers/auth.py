from fastapi import APIRouter, HTTPException
from typing import List
from ..schemas.models import LoginRequest, LoginResponse, UserProfile
from ..db import database as db

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    if not request.email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    user_record = db.get_user_by_email(request.email)
    if not user_record:
        # Auto-provision user if first-time analyst login
        display_name = request.email.split('@')[0].replace('.', ' ').title()
        user_record = db.register_user(name=display_name, email=request.email, role="Security Analyst")

    user_profile = UserProfile(
        id=user_record["id"],
        name=user_record["name"],
        email=user_record["email"],
        role=user_record["role"],
        status=user_record.get("status", "Active"),
        lastLogin=user_record.get("lastLogin", "Just Now"),
        avatar=user_record.get("avatar", "SA")
    )
    
    return LoginResponse(
        status="success",
        access_token=f"threatlen_jwt_{user_record['id']}_auth_token",
        token_type="bearer",
        user=user_profile
    )

@router.post("/register")
async def register(payload: dict):
    name = payload.get("name") or payload.get("email", "Analyst").split("@")[0].capitalize()
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    role = payload.get("role", "Security Analyst")
    
    existing = db.get_user_by_email(email)
    if existing:
        return {
            "status": "success",
            "message": f"User {email} already registered.",
            "user": existing
        }

    user = db.register_user(name=name, email=email, role=role)
    return {
        "status": "success",
        "message": f"Analyst profile {user['name']} registered successfully.",
        "user": user
    }

@router.get("/users", response_model=List[UserProfile])
async def list_users():
    users = db.get_all_users()
    return [UserProfile(**u) for u in users]

