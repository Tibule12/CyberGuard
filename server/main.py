"""
Main entry point for CyberGuard Server.
Starts the FastAPI application and registers all API routes.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .core.app import app as main_app
from .core.config import get_settings
from .api import threats, clients, auth, system

# Import and include all API routers
main_app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
main_app.include_router(clients.router, prefix="/api/v1/clients", tags=["clients"])
main_app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
main_app.include_router(system.router, prefix="/api/v1/system", tags=["system"])

# Add CORS middleware
main_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "server.main:main_app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
