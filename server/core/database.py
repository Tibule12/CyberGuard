"""
Database connection and management for CyberGuard Server.
Handles MongoDB and Redis connections.
"""

import motor.motor_asyncio
import redis.asyncio as redis
from typing import Optional
import logging
from .config import get_settings

logger = logging.getLogger(__name__)

class Database:
    """Database connection manager."""
    
    def __init__(self):
        self.settings = get_settings()
        self.mongo_client: Optional[motor.motor_asyncio.AsyncIOMotorClient] = None
        self.redis_client: Optional[redis.Redis] = None
        self.database: Optional[motor.motor_asyncio.AsyncIOMotorDatabase] = None
    
    async def connect(self):
        """Connect to MongoDB and Redis."""
        try:
            # Connect to MongoDB
            self.mongo_client = motor.motor_asyncio.AsyncIOMotorClient(
                self.settings.mongodb_uri,
                maxPoolSize=10,
                minPoolSize=1
            )
            self.database = self.mongo_client[self.settings.database_name]
            
            # Connect to Redis
            self.redis_client = redis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            
            # Test connections
            await self.mongo_client.admin.command('ping')
            await self.redis_client.ping()
            
            logger.info("Connected to MongoDB and Redis successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    async def close(self):
        """Close database connections."""
        if self.mongo_client:
            self.mongo_client.close()
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Database connections closed")
    
    def get_collection(self, collection_name: str):
        """Get a MongoDB collection."""
        if not self.database:
            raise RuntimeError("Database not connected")
        return self.database[collection_name]
    
    async def get_redis(self):
        """Get Redis client."""
        if not self.redis_client:
            raise RuntimeError("Redis not connected")
        return self.redis_client

# Global database instance
_db_instance: Optional[Database] = None

async def get_database() -> Database:
    """Get or create database connection."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
        await _db_instance.connect()
    return _db_instance

async def close_database():
    """Close database connection."""
    global _db_instance
    if _db_instance:
        await _db_instance.close()
        _db_instance = None

# Collection names
THREATS_COLLECTION = "threats"
CLIENTS_COLLECTION = "clients"
EVENTS_COLLECTION = "events"
SCANS_COLLECTION = "scans"
USERS_COLLECTION = "users"
SETTINGS_COLLECTION = "settings"
