"""
Test script to verify all API endpoints using mock database.
This allows testing without requiring MongoDB installation.
"""

import asyncio
import httpx
import json
from typing import Dict, Any
import sys
import os

# Add the server directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'server'))

async def test_api_endpoints():
    """Test all API endpoints using the FastAPI test client."""
    
    # Import the FastAPI app
    from main import app
    from fastapi.testclient import TestClient
    
    print("🧪 Testing CyberGuard API Endpoints")
    print("=" * 50)
    
    # Create test client
    client = TestClient(app)
    
    # Test results
    test_results = {}
    
    # 1. Test health endpoint
    print("\n1. Testing /health endpoint...")
    try:
        response = client.get("/health")
        test_results["health"] = response.status_code == 200
        print(f"   ✅ Status: {response.status_code}, Response: {response.json()}")
    except Exception as e:
        test_results["health"] = False
        print(f"   ❌ Error: {e}")
    
    # 2. Test login endpoint
    print("\n2. Testing /auth/login endpoint...")
    try:
        login_data = {"username": "admin", "password": "admin123"}
        response = client.post("/auth/login", json=login_data)
        test_results["login"] = response.status_code == 200
        if response.status_code == 200:
            auth_token = response.json().get("access_token")
            print(f"   ✅ Login successful, token: {auth_token[:20]}...")
        else:
            print(f"   ❌ Login failed: {response.status_code}, {response.text}")
    except Exception as e:
        test_results["login"] = False
        print(f"   ❌ Error: {e}")
    
    # 3. Test verify token endpoint
    print("\n3. Testing /auth/verify endpoint...")
    try:
        if auth_token:
            headers = {"Authorization": f"Bearer {auth_token}"}
            response = client.post("/auth/verify", headers=headers)
            test_results["verify"] = response.status_code == 200
            print(f"   ✅ Token verification: {response.status_code}, {response.json()}")
        else:
            test_results["verify"] = False
            print("   ❌ No auth token available")
    except Exception as e:
        test_results["verify"] = False
        print(f"   ❌ Error: {e}")
    
    # 4. Test get current user endpoint
    print("\n4. Testing /auth/me endpoint...")
    try:
        if auth_token:
            headers = {"Authorization": f"Bearer {auth_token}"}
            response = client.get("/auth/me", headers=headers)
            test_results["me"] = response.status_code == 200
            print(f"   ✅ User info: {response.status_code}, {response.json()}")
        else:
            test_results["me"] = False
            print("   ❌ No auth token available")
    except Exception as e:
        test_results["me"] = False
        print(f"   ❌ Error: {e}")
    
    # 5. Test system stats endpoint
    print("\n5. Testing /system/stats endpoint...")
    try:
        response = client.get("/system/stats")
        test_results["stats"] = response.status_code == 200
        print(f"   ✅ System stats: {response.status_code}, {response.json()}")
    except Exception as e:
        test_results["stats"] = False
        print(f"   ❌ Error: {e}")
    
    # 6. Test threat analysis endpoint
    print("\n6. Testing /threats/analyze endpoint...")
    try:
        threat_data = {
            "event_type": "suspicious_process",
            "process_name": "malware.exe",
            "severity": "high"
        }
        response = client.post("/threats/analyze", json=threat_data)
        test_results["analyze"] = response.status_code == 200
        print(f"   ✅ Threat analysis: {response.status_code}, {response.json()}")
    except Exception as e:
        test_results["analyze"] = False
        print(f"   ❌ Error: {e}")
    
    # 7. Test threat signatures endpoint
    print("\n7. Testing /threats/signatures endpoint...")
    try:
        response = client.get("/threats/signatures")
        test_results["signatures"] = response.status_code == 200
        print(f"   ✅ Threat signatures: {response.status_code}, {response.json()}")
    except Exception as e:
        test_results["signatures"] = False
        print(f"   ❌ Error: {e}")
    
    # 8. Test threat stats endpoint
    print("\n8. Testing /threats/stats endpoint...")
    try:
        response = client.get("/threats/stats")
        test_results["threat_stats"] = response.status_code == 200
        print(f"   ✅ Threat stats: {response.status_code}, {response.json()}")
    except Exception as e:
        test_results["threat_stats"] = False
        print(f"   ❌ Error: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for result in test_results.values() if result)
    total = len(test_results)
    
    for endpoint, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {endpoint}")
    
    print(f"\nOverall: {passed}/{total} endpoints passed")
    
    if passed == total:
        print("🎉 All API endpoints are working correctly!")
        return True
    else:
        print("⚠️  Some endpoints need attention")
        return False

if __name__ == "__main__":
    # Set environment variable to use mock database
    os.environ["USE_MOCK_DB"] = "true"
    
    success = asyncio.run(test_api_endpoints())
    sys.exit(0 if success else 1)
