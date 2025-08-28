"""
Authentication API endpoints for CyberGuard System.
Handles user login, token generation, and authentication.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any
import logging

from ..core.database import get_database
from ..core.auth import get_auth_handler, AuthHandler

router = APIRouter()
logger = logging.getLogger(__name__)
security = HTTPBearer()

@router.post("/login", response_model=Dict[str, Any])
async def login(credentials: Dict[str, Any]):
    """Authenticate user and generate JWT token."""
    try:
        username = credentials.get("username")
        password = credentials.get("password")
        
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
        
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        # Authenticate user
        user = await auth_handler.authenticate_user(username, password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Generate token
        token = await auth_handler.create_token(
            user_id=str(user.get("_id", "")),
            username=user.get("username", ""),
            roles=user.get("roles", [])
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user_id": str(user.get("_id", "")),
            "username": user.get("username", ""),
            "roles": user.get("roles", []),
            "expires_in": auth_handler.settings.jwt_expire_minutes * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/verify", response_model=Dict[str, Any])
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token validity."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        payload = await auth_handler.verify_token(credentials.credentials)
        
        return {
            "valid": True,
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "roles": payload.get("roles", []),
            "expires_at": payload.get("exp")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token verification failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/refresh", response_model=Dict[str, Any])
async def refresh_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Refresh JWT token."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        # Verify current token
        payload = await auth_handler.verify_token(credentials.credentials)
        
        # Get user data
        user = await auth_handler.get_user_by_id(payload["sub"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Generate new token
        new_token = await auth_handler.create_token(
            user_id=payload["sub"],
            username=payload["username"],
            roles=payload["roles"]
        )
        
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "user_id": payload["sub"],
            "username": payload["username"],
            "roles": payload["roles"],
            "expires_in": auth_handler.settings.jwt_expire_minutes * 60
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/me", response_model=Dict[str, Any])
async def get_current_user_info(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user information."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        user_data = await auth_handler.get_current_user(credentials)
        return {
            "user_id": user_data["sub"],
            "username": user_data["username"],
            "roles": user_data["roles"],
            "user_data": user_data.get("user_data", {})
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/logout", response_model=Dict[str, Any])
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout user (client-side token invalidation)."""
    # Note: JWT tokens are stateless, so this is mainly for client-side cleanup
    # In production, you might want to implement a token blacklist
    
    return {
        "message": "Logout successful",
        "timestamp": "2024-01-01T00:00:00Z"  # Placeholder timestamp
    }
