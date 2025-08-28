"""
API endpoints for managing client applications in the CyberGuard System.
Handles client registration, heartbeat, and communication.
"""

from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

from ..core.database import get_database, CLIENTS_COLLECTION
from ..core.auth import get_auth_handler

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/register", response_model=Dict[str, Any])
async def register_client(client_data: Dict[str, Any]):
    """Register a new client application."""
    try:
        database = await get_database()
        collection = database.get_collection(CLIENTS_COLLECTION)
        
        # Validate required fields
        required_fields = ["client_id", "platform", "version", "system_info"]
        for field in required_fields:
            if field not in client_data:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
        
        # Check if client already exists
        existing_client = await collection.find_one({"client_id": client_data["client_id"]})
        if existing_client:
            raise HTTPException(status_code=409, detail="Client already registered")
        
        # Create client document
        client_doc = {
            **client_data,
            "registered_at": datetime.utcnow(),
            "last_heartbeat": datetime.utcnow(),
            "is_active": True,
            "threat_count": 0,
            "last_scan": None
        }
        
        result = await collection.insert_one(client_doc)
        
        return {
            "client_id": client_data["client_id"],
            "registered": True,
            "message": "Client registered successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Client registration failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/heartbeat/{client_id}", response_model=Dict[str, Any])
async def client_heartbeat(client_id: str):
    """Receive heartbeat from client application."""
    try:
        database = await get_database()
        collection = database.get_collection(CLIENTS_COLLECTION)
        
        # Update last heartbeat timestamp
        result = await collection.update_one(
            {"client_id": client_id},
            {"$set": {"last_heartbeat": datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Client not found")
        
        return {
            "client_id": client_id,
            "heartbeat_received": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Heartbeat failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{client_id}", response_model=Dict[str, Any])
async def get_client_info(client_id: str):
    """Get information about a specific client."""
    try:
        database = await get_database()
        collection = database.get_collection(CLIENTS_COLLECTION)
        
        client = await collection.find_one({"client_id": client_id})
        if not client:
            raise HTTPException(status_code=404, detail="Client not found")
        
        # Remove sensitive information
        client.pop("_id", None)
        client.pop("system_info", None)  # Remove detailed system info for security
        
        return client
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get client info: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/", response_model=List[Dict[str, Any]])
async def list_clients(active_only: bool = True):
    """List all registered clients."""
    try:
        database = await get_database()
        collection = database.get_collection(CLIENTS_COLLECTION)
        
        query = {"is_active": True} if active_only else {}
        clients = await collection.find(query).to_list(length=100)
        
        # Clean up response
        for client in clients:
            client.pop("_id", None)
            client.pop("system_info", None)
        
        return clients
        
    except Exception as e:
        logger.error(f"Failed to list clients: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/scan/{client_id}", response_model=Dict[str, Any])
async def initiate_scan(client_id: str):
    """Initiate a security scan on a client."""
    try:
        database = await get_database()
        collection = database.get_collection(CLIENTS_COLLECTION)
        
        # Update last scan timestamp
        result = await collection.update_one(
            {"client_id": client_id},
            {"$set": {"last_scan": datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Client not found")
        
        return {
            "client_id": client_id,
            "scan_initiated": True,
            "scan_time": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan initiation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
