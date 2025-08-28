"""
Mock database implementation for testing without MongoDB.
Provides in-memory storage for testing API endpoints.
"""

from typing import Optional, Dict, Any, List
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class MockDatabase:
    """Mock database for testing without MongoDB."""
    
    def __init__(self):
        self.collections = {
            "threats": [],
            "clients": [],
            "events": [],
            "scans": [],
            "users": [
                {
                    "_id": "admin_user_id",
                    "username": "admin",
                    "password_hash": "admin123",  # Plaintext for testing
                    "roles": ["admin", "user"],
                    "is_active": True,
                    "created_at": datetime.now().isoformat()
                },
                {
                    "_id": "regular_user_id",
                    "username": "user",
                    "password_hash": "user123",  # Plaintext for testing
                    "roles": ["user"],
                    "is_active": True,
                    "created_at": datetime.now().isoformat()
                }
            ],
            "settings": []
        }
        self.connected = True
    
    async def connect(self):
        """Mock connection method."""
        self.connected = True
        logger.info("Connected to mock database")
        return True
    
    async def close(self):
        """Mock close method."""
        self.connected = False
        logger.info("Mock database connection closed")
    
    def get_collection(self, collection_name: str):
        """Get a mock collection."""
        if collection_name not in self.collections:
            self.collections[collection_name] = []
        return MockCollection(self.collections[collection_name])
    
    async def get_redis(self):
        """Mock Redis client."""
        return MockRedis()

class MockCollection:
    """Mock MongoDB collection."""
    
    def __init__(self, data: List[Dict[str, Any]]):
        self.data = data
    
    async def find_one(self, query: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Find one document matching query."""
        for doc in self.data:
            match = True
            for key, value in query.items():
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                return doc
        return None
    
    async def find(self, query: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Find documents matching query."""
        if query is None:
            return self.data.copy()
        
        results = []
        for doc in self.data:
            match = True
            for key, value in query.items():
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                results.append(doc)
        return results
    
    async def insert_one(self, document: Dict[str, Any]) -> str:
        """Insert one document."""
        if "_id" not in document:
            document["_id"] = str(uuid.uuid4())
        document["created_at"] = datetime.now().isoformat()
        self.data.append(document)
        return document["_id"]
    
    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any]) -> bool:
        """Update one document."""
        for doc in self.data:
            match = True
            for key, value in query.items():
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                doc.update(update)
                return True
        return False
    
    async def delete_one(self, query: Dict[str, Any]) -> bool:
        """Delete one document."""
        for i, doc in enumerate(self.data):
            match = True
            for key, value in query.items():
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                self.data.pop(i)
                return True
        return False
    
    async def count_documents(self, query: Dict[str, Any] = None) -> int:
        """Count documents matching query."""
        if query is None:
            return len(self.data)
        
        count = 0
        for doc in self.data:
            match = True
            for key, value in query.items():
                if doc.get(key) != value:
                    match = False
                    break
            if match:
                count += 1
        return count

class MockRedis:
    """Mock Redis client."""
    
    def __init__(self):
        self.data = {}
    
    async def ping(self):
        """Mock ping."""
        return True
    
    async def get(self, key: str) -> Optional[str]:
        """Mock get."""
        return self.data.get(key)
    
    async def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Mock set."""
        self.data[key] = value
        return True
    
    async def delete(self, key: str) -> bool:
        """Mock delete."""
        if key in self.data:
            del self.data[key]
            return True
        return False
    
    async def close(self):
        """Mock close."""
        pass

# Global mock database instance
_mock_db_instance: Optional[MockDatabase] = None

async def get_mock_database() -> MockDatabase:
    """Get or create mock database."""
    global _mock_db_instance
    if _mock_db_instance is None:
        _mock_db_instance = MockDatabase()
        await _mock_db_instance.connect()
    return _mock_db_instance
