"""
System management API endpoints for CyberGuard System.
Handles system configuration, monitoring, and administration.
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Any, List
import logging
import psutil
import platform

from ..core.database import get_database
from ..core.auth import get_auth_handler, AuthHandler
from ..core.config import get_settings

router = APIRouter()
logger = logging.getLogger(__name__)
security = HTTPBearer()

@router.get("/health", response_model=Dict[str, Any])
async def system_health():
    """Get system health status."""
    try:
        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get database status
        database = await get_database()
        db_connected = database is not None
        
        return {
            "status": "healthy",
            "timestamp": "2024-01-01T00:00:00Z",
            "system": {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "memory_total": memory.total,
                "memory_available": memory.available,
                "disk_usage": disk.percent,
                "disk_total": disk.total,
                "disk_free": disk.free,
                "platform": platform.platform(),
                "python_version": platform.python_version()
            },
            "services": {
                "database_connected": db_connected,
                "api_server": "running",
                "threat_engine": "running"  # Placeholder
            },
            "uptime": "0 days, 0:00:00"  # Placeholder
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/config", response_model=Dict[str, Any])
async def get_system_config(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get system configuration (admin only)."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        # Verify admin privileges
        user_data = await auth_handler.get_current_user(credentials)
        if "admin" not in user_data.get("roles", []):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        settings = get_settings()
        
        # Return safe configuration (without sensitive data)
        return {
            "server": {
                "host": settings.server_host,
                "port": settings.server_port,
                "environment": settings.environment,
                "debug": settings.debug
            },
            "database": {
                "name": settings.database_name,
                "connected": True  # Placeholder
            },
            "ml": {
                "model_path": settings.ml_model_path,
                "threshold": settings.ml_threshold,
                "update_interval": settings.ml_update_interval
            },
            "threat_intelligence": {
                "update_interval": settings.threat_update_interval
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system config: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/stats", response_model=Dict[str, Any])
async def get_system_stats():
    """Get system statistics."""
    try:
        database = await get_database()
        
        # Get collection statistics (placeholder)
        stats = {
            "total_clients": 0,
            "active_clients": 0,
            "total_threats": 0,
            "threats_today": 0,
            "scans_completed": 0,
            "system_uptime": "0 days, 0:00:00"
        }
        
        try:
            clients_collection = database.get_collection("clients")
            threats_collection = database.get_collection("threats")
            
            stats["total_clients"] = await clients_collection.count_documents({})
            stats["active_clients"] = await clients_collection.count_documents({"is_active": True})
            stats["total_threats"] = await threats_collection.count_documents({})
            
        except Exception as db_error:
            logger.warning(f"Database stats unavailable: {db_error}")
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/logs", response_model=List[Dict[str, Any]])
async def get_system_logs(limit: int = 100, 
                         credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get system logs (admin only)."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        # Verify admin privileges
        user_data = await auth_handler.get_current_user(credentials)
        if "admin" not in user_data.get("roles", []):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Placeholder for actual log retrieval
        # In production, this would query log files or database
        logs = [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "level": "INFO",
                "message": "System started successfully",
                "component": "server"
            },
            {
                "timestamp": "2024-01-01T00:01:00Z",
                "level": "INFO",
                "message": "Database connection established",
                "component": "database"
            }
        ]
        
        return logs[:limit]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get system logs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/restart", response_model=Dict[str, Any])
async def restart_system(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Restart system services (admin only)."""
    try:
        database = await get_database()
        auth_handler = await get_auth_handler(database)
        
        # Verify admin privileges
        user_data = await auth_handler.get_current_user(credentials)
        if "admin" not in user_data.get("roles", []):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Placeholder for actual restart logic
        # In production, this would trigger service restarts
        
        return {
            "message": "System restart initiated",
            "timestamp": "2024-01-01T00:00:00Z",
            "services": ["api", "threat_engine", "database"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"System restart failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
