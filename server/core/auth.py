"""
Authentication and authorization module for CyberGuard Server.
Handles JWT token generation, validation, and user management.
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

from .config import get_settings
from .database import Database, USERS_COLLECTION

logger = logging.getLogger(__name__)
security = HTTPBearer()

class AuthHandler:
    """Authentication handler for JWT tokens."""
    
    def __init__(self, database: Database):
        self.database = database
        self.settings = get_settings()
        self.secret_key = self.settings.jwt_secret_key
        self.algorithm = self.settings.jwt_algorithm
    
    async def create_token(self, user_id: str, username: str, roles: list) -> str:
        """Create a JWT token for a user."""
        payload = {
            "sub": user_id,
            "username": username,
            "roles": roles,
            "exp": datetime.utcnow() + timedelta(minutes=self.settings.jwt_expire_minutes),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def _encode_token(self, payload: Dict[str, Any]) -> str:
        """Encode a JWT token with the given payload."""
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
        """Get current user from token."""
        token = credentials.credentials
        payload = await self.verify_token(token)
        
        # Check if user still exists and is active
        user = await self.get_user_by_id(payload["sub"])
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return {**payload, "user_data": user}
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID from database."""
        try:
            collection = self.database.get_collection(USERS_COLLECTION)
            user = await collection.find_one({"_id": user_id})
            return user
        except Exception as e:
            logger.error(f"Failed to get user: {e}")
            return None
    
    async def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with username and password."""
        # Placeholder for actual authentication logic
        # This would typically involve password hashing and verification
        try:
            collection = self.database.get_collection(USERS_COLLECTION)
            user = await collection.find_one({"username": username, "is_active": True})
            
            if user and self._verify_password(password, user.get("password_hash", "")):
                return user
            return None
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None
    
    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash."""
        # Placeholder for actual password verification
        # This would use bcrypt or similar in production
        return plain_password == hashed_password  # Remove this in production!
    
    def _hash_password(self, password: str) -> str:
        """Hash a password."""
        # Placeholder for actual password hashing
        # This would use bcrypt or similar in production
        return password  # Remove this in production!

async def verify_token(token: str) -> Dict[str, Any]:
    """Verify token without requiring database instance."""
    handler = AuthHandler(None)  # Create handler without database for basic verification
    return await handler.verify_token(token)

# Global auth handler instance
_auth_handler: Optional[AuthHandler] = None

async def get_auth_handler(database: Database) -> AuthHandler:
    """Get or create auth handler instance."""
    global _auth_handler
    if _auth_handler is None:
        _auth_handler = AuthHandler(database)
    return _auth_handler
