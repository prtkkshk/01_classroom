#!/usr/bin/env python3
"""
Debug script to test the create-professor endpoint and identify routing issues
"""

import requests
import json
import sys

def test_endpoint(base_url, token=None):
    """Test the create-professor endpoint with different scenarios"""
    
    endpoint = f"{base_url}/api/admin/create-professor"
    
    print(f"🔍 Testing endpoint: {endpoint}")
    print("=" * 60)
    
    # Test 1: Check if endpoint exists (OPTIONS request)
    print("1️⃣ Testing OPTIONS request to check allowed methods...")
    try:
        response = requests.options(endpoint)
        print(f"   Status: {response.status_code}")
        print(f"   Allow header: {response.headers.get('Allow', 'Not found')}")
        print(f"   Response: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()
    
    # Test 2: Test GET request (should return 405 Method Not Allowed)
    print("2️⃣ Testing GET request (should return 405)...")
    try:
        response = requests.get(endpoint)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()
    
    # Test 3: Test POST request without auth
    print("3️⃣ Testing POST request without authentication...")
    test_data = {
        "name": "Test Professor",
        "userid": "testprof123",
        "email": "test@example.com",
        "password": "password123"
    }
    
    try:
        response = requests.post(endpoint, json=test_data)
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()
    
    # Test 4: Test POST request with auth (if token provided)
    if token:
        print("4️⃣ Testing POST request with authentication...")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(endpoint, json=test_data, headers=headers)
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    else:
        print("4️⃣ Skipping authenticated test (no token provided)")
    
    print()
    
    # Test 5: Check API info endpoint
    print("5️⃣ Checking API info endpoint...")
    try:
        response = requests.get(f"{base_url}/api/info")
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            admin_endpoints = data.get("endpoints", {}).get("admin", [])
            print(f"   Admin endpoints: {admin_endpoints}")
            if "/api/admin/create-professor" in admin_endpoints:
                print("   ✅ create-professor endpoint is listed in API info")
            else:
                print("   ❌ create-professor endpoint is NOT listed in API info")
        else:
            print(f"   Response: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print()
    
    # Test 6: Check if server is running
    print("6️⃣ Checking if server is running...")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"   Health check status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_endpoint.py <base_url> [token]")
        print("Example: python debug_endpoint.py https://zero1-classroom-1.onrender.com")
        print("Example: python debug_endpoint.py https://zero1-classroom-1.onrender.com your_token_here")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip('/')
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    print(f"🚀 Debugging endpoint for: {base_url}")
    if token:
        print(f"🔑 Using token: {token[:20]}...")
    else:
        print("🔑 No token provided - some tests will be skipped")
    
    print()
    
    test_endpoint(base_url, token)
    
    print("=" * 60)
    print("📋 Summary:")
    print("• If OPTIONS returns 405, the endpoint doesn't exist")
    print("• If GET returns 405, the endpoint exists but doesn't support GET")
    print("• If POST without auth returns 401, the endpoint exists and requires auth")
    print("• If POST with auth returns 403, you need moderator privileges")
    print("• If POST with auth returns 422, there's a validation error")
    print("• If POST with auth returns 200, the endpoint works!")

if __name__ == "__main__":
    main() 