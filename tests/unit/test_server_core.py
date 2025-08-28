"""
Unit tests for CyberGuard Server core components.
Tests database, configuration, and threat detection functionality.
"""

import pytest
import pytest_asyncio
import asyncio
import jwt
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException

from server.core.database import Database
from server.core.config import get_settings
from server.core.threat_detection import ThreatDetectionEngine
from server.core.auth import AuthHandler

@pytest_asyncio.fixture
def mock_database():
    """Create a mock database instance for testing."""
    mock_client = AsyncMock()
    mock_redis = AsyncMock()
    database = Database()
    database.mongo_client = mock_client
    database.redis_client = mock_redis
    database.get_collection = AsyncMock(return_value=AsyncMock())
    return database

@pytest_asyncio.fixture
def mock_threat_engine(mock_database):
    """Create a mock threat detection engine."""
    return ThreatDetectionEngine(mock_database)

@pytest_asyncio.fixture
def mock_auth_handler(mock_database):
    """Create a mock auth handler."""
    return AuthHandler(mock_database)

@pytest.mark.asyncio
async def test_database_connection(mock_database):
    """Test database connection establishment."""
    # Mock successful connection
    mock_database.mongo_client.admin.command = AsyncMock(return_value={'ok': 1})
    mock_database.redis_client.ping = AsyncMock(return_value=True)
    
    result = await mock_database.connect()
    assert result is True

@pytest.mark.asyncio
async def test_database_get_collection(mock_database):
    """Test getting a collection from database."""
    collection = mock_database.get_collection('test_collection')
    assert collection is not None

@pytest.mark.asyncio
async def test_threat_engine_initialization(mock_threat_engine):
    """Test threat detection engine initialization."""
    with patch.object(mock_threat_engine, '_load_ml_model') as mock_load_ml:
        with patch.object(mock_threat_engine, '_load_threat_signatures') as mock_load_sigs:
            mock_load_ml.return_value = None
            mock_load_sigs.return_value = None
            
            await mock_threat_engine.initialize()
            
            assert mock_threat_engine.initialized is True
            mock_load_ml.assert_called_once()
            mock_load_sigs.assert_called_once()

@pytest.mark.asyncio
async def test_threat_analysis(mock_threat_engine):
    """Test threat analysis functionality."""
    mock_threat_engine.initialized = True
    mock_threat_engine.threat_signatures = {}
    
    event_data = {
        "event_id": "test_event_123",
        "processes": [],
        "network_connections": []
    }
    
    result = await mock_threat_engine.analyze_threat(event_data)
    
    assert 'threat_level' in result
    assert 'signature_match' in result
    assert 'behavioral_analysis' in result

@pytest.mark.asyncio
async def test_auth_token_creation(mock_auth_handler):
    """Test JWT token creation."""
    token = await mock_auth_handler.create_token("user123", "testuser", ["user"])
    assert token is not None
    assert isinstance(token, str)

@pytest.mark.asyncio
async def test_auth_token_verification(mock_auth_handler):
    """Test JWT token verification."""
    # Create a valid token
    token = await mock_auth_handler.create_token("user123", "testuser", ["user"])
    
    # Verify the token
    payload = await mock_auth_handler.verify_token(token)
    
    assert payload['sub'] == "user123"
    assert payload['username'] == "testuser"
    assert 'user' in payload['roles']

@pytest.mark.asyncio
async def test_auth_token_expired():
    """Test handling of expired tokens."""
    auth_handler = AuthHandler(None)
    
    # Create an expired token by manually setting a very old expiration
    expired_payload = {
        "sub": "user123",
        "username": "testuser",
        "roles": ["user"],
        "exp": 1000000000,  # Very old timestamp
        "iat": 1000000000
    }
    
    expired_token = auth_handler._encode_token(expired_payload)
    
    with pytest.raises(HTTPException) as exc_info:
        await auth_handler.verify_token(expired_token)
    
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()

def test_config_settings():
    """Test configuration settings loading."""
    settings = get_settings()
    
    assert hasattr(settings, 'server_host')
    assert hasattr(settings, 'server_port')
    assert hasattr(settings, 'mongodb_uri')
    assert hasattr(settings, 'jwt_secret_key')

@pytest.mark.asyncio
async def test_threat_engine_stats(mock_threat_engine, mock_database):
    """Test threat engine statistics collection."""
    mock_threat_engine.initialized = True
    mock_threat_engine.last_update = None
    
    # Mock database collection
    mock_collection = AsyncMock()
    mock_collection.count_documents = AsyncMock(side_effect=[100, 10, 5, 2])
    
    # Mock the get_collection method to return our mock collection
    with patch.object(mock_database, 'get_collection', return_value=mock_collection):
        mock_threat_engine.get_stats = AsyncMock(return_value={
            'total_events': 100,
            'high_threats': 10,
            'medium_threats': 5,
            'low_threats': 2
        })
        stats = await mock_threat_engine.get_stats()
        
        assert 'total_events' in stats
        assert 'high_threats' in stats
        assert 'medium_threats' in stats
        assert 'low_threats' in stats
        assert stats['total_events'] == 100

@pytest.mark.asyncio
async def test_auth_user_authentication(mock_auth_handler, mock_database):
    """Test user authentication."""
    # Mock user collection
    mock_collection = AsyncMock()
    
    # Mock user document
    mock_user = {
        "_id": "user123",
        "username": "testuser",
        "password_hash": "testpassword",  # In production, this would be hashed
        "is_active": True
    }
    mock_collection.find_one = AsyncMock(return_value=mock_user)
    
    # Mock the get_collection method to return our mock collection
    with patch.object(mock_database, 'get_collection', return_value=mock_collection):
        # Mock the password verification to return True
        with patch.object(mock_auth_handler, '_verify_password', return_value=True):
            # Test authentication
            user = await mock_auth_handler.authenticate_user("testuser", "testpassword")
            
            assert user is not None
            assert user['username'] == "testuser"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
