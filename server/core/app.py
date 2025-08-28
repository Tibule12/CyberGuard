"""
Main FastAPI application for CyberGuard Server.
Handles threat detection, client communication, and system management.
"""

import os
import logging
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager

from .config import get_settings, Settings
from .database import get_database
from .threat_detection import ThreatDetectionEngine
from .auth import verify_token

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events for the application."""
    # Startup
    logger.info("Starting CyberGuard Server...")
    app.state.database = await get_database()
    app.state.threat_engine = ThreatDetectionEngine(app.state.database)
    
    # Start threat engine
    await app.state.threat_engine.initialize()
    logger.info("Threat detection engine initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CyberGuard Server...")
    if hasattr(app.state, 'database'):
        await app.state.database.close()
    logger.info("Server shutdown complete")

app = FastAPI(
    title="CyberGuard Server API",
    description="Advanced threat detection and security management system",
    version="0.1.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint - system status."""
    return {
        "message": "CyberGuard Server is running",
        "version": "0.1.0",
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

@app.get("/api/v1/threats/stats")
async def get_threat_stats(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Get threat statistics."""
    # Verify authentication
    await verify_token(credentials.credentials)
    
    if not hasattr(app.state, 'threat_engine'):
        raise HTTPException(status_code=503, detail="Threat engine not initialized")
    
    stats = await app.state.threat_engine.get_stats()
    return stats

@app.get("/api/v1/system/info")
async def get_system_info(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Get system information and configuration."""
    await verify_token(credentials.credentials)
    
    settings = get_settings()
    return {
        "environment": settings.environment,
        "debug": settings.debug,
        "database_connected": hasattr(app.state, 'database') and app.state.database is not None,
        "threat_engine_ready": hasattr(app.state, 'threat_engine') and app.state.threat_engine.initialized
    }

if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        app,
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug
    )
