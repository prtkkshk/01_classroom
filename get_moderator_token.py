#!/usr/bin/env python3
"""
Script to get a moderator token for testing the create-professor endpoint
"""

import requests
import json

def get_moderator_token(base_url):
    """Get a moderator token by logging in"""
    
    login_data = {
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    }
    
    print(f"🔑 Logging in as moderator...")
    print(f"URL: {base_url}/api/login")
    
    try:
        response = requests.post(f"{base_url}/api/login", json=login_data)
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            user = data.get('user', {})
            
            print(f"✅ Login successful!")
            print(f"User: {user.get('name', 'Unknown')} ({user.get('role', 'Unknown')})")
            print(f"Token: {token[:20]}...")
            
            return token
        else:
            print(f"❌ Login failed: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_create_professor(base_url, token):
    """Test the create-professor endpoint with the token"""
    
    endpoint = f"{base_url}/api/admin/create-professor"
    
    # Use a unique userid to avoid conflicts
    import time
    timestamp = int(time.time())
    
    test_data = {
        "name": "Test Professor",
        "userid": f"testprof{timestamp}",
        "email": f"test{timestamp}@example.com",
        "password": "password123"
    }
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"\n🧪 Testing create-professor endpoint...")
    print(f"URL: {endpoint}")
    print(f"Data: {json.dumps(test_data, indent=2)}")
    
    try:
        response = requests.post(endpoint, json=test_data, headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ Professor created successfully!")
        elif response.status_code == 403:
            print("❌ Access denied - you need moderator privileges")
        elif response.status_code == 422:
            print("❌ Validation error - check the request data")
        else:
            print(f"❌ Unexpected error: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    base_url = "https://zero1-classroom-1.onrender.com"
    
    print("🚀 Getting moderator token and testing create-professor endpoint")
    print("=" * 60)
    
    # Get moderator token
    token = get_moderator_token(base_url)
    
    if token:
        # Test the endpoint
        test_create_professor(base_url, token)
    else:
        print("❌ Could not get moderator token. Cannot test endpoint.")

if __name__ == "__main__":
    main() 