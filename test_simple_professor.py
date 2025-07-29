#!/usr/bin/env python3
"""
Simple test to isolate the professor creation issue
"""

import requests
import json

def test_professor_creation():
    base_url = "https://zero1-classroom-1.onrender.com"
    
    # Login as moderator
    login_data = {
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    }
    
    print("🔑 Logging in as moderator...")
    response = requests.post(f"{base_url}/api/login", json=login_data)
    
    if response.status_code != 200:
        print(f"❌ Login failed: {response.text}")
        return
    
    token = response.json()['access_token']
    print("✅ Login successful")
    
    # Test data with minimal fields
    import time
    timestamp = int(time.time())
    
    test_data = {
        "name": f"Test Prof {timestamp}",
        "userid": f"prof{timestamp}",
        "email": f"prof{timestamp}@test.com",
        "password": "password123"
    }
    
    print(f"\n🧪 Testing with data: {test_data}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Test the endpoint
    response = requests.post(f"{base_url}/api/admin/create-professor", 
                           json=test_data, headers=headers)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Professor created successfully!")
    elif response.status_code == 400:
        print("❌ Validation error")
        try:
            error_data = response.json()
            print(f"Error details: {error_data}")
        except:
            print("Could not parse error response")
    else:
        print(f"❌ Unexpected error: {response.status_code}")

if __name__ == "__main__":
    test_professor_creation() 