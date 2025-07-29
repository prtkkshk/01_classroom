#!/usr/bin/env python3
"""
Comprehensive debug script for professor creation
"""

import requests
import json
import time

def test_professor_creation_debug():
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
    
    # Test data with completely unique values
    timestamp = int(time.time())
    
    test_data = {
        "name": f"Debug Professor {timestamp}",
        "userid": f"debugprof{timestamp}",
        "email": f"debug{timestamp}@testdomain.com",
        "password": "password123"
    }
    
    print(f"\n🧪 Testing with data: {test_data}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # First, check if the user already exists
    print("\n🔍 Checking if user already exists...")
    try:
        users_response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if users_response.status_code == 200:
            users_data = users_response.json()
            users = users_data.get('users', [])
            print(f"Found {len(users)} users in database")
            
            # Check for conflicts
            email_conflict = any(user.get('email') == test_data['email'] for user in users)
            userid_conflict = any(user.get('userid') == test_data['userid'] for user in users)
            
            if email_conflict:
                print(f"❌ Email conflict: {test_data['email']}")
            else:
                print(f"✅ Email available: {test_data['email']}")
                
            if userid_conflict:
                print(f"❌ UserID conflict: {test_data['userid']}")
            else:
                print(f"✅ UserID available: {test_data['userid']}")
        else:
            print(f"❌ Failed to get users: {users_response.text}")
    except Exception as e:
        print(f"❌ Error checking users: {e}")
    
    # Test the endpoint
    print(f"\n🚀 Testing create-professor endpoint...")
    response = requests.post(f"{base_url}/api/admin/create-professor", 
                           json=test_data, headers=headers)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ Professor created successfully!")
        try:
            result_data = response.json()
            print(f"Professor data: {result_data}")
        except:
            pass
    elif response.status_code == 400:
        print("❌ Validation error")
        try:
            error_data = response.json()
            print(f"Error details: {error_data}")
        except:
            print("Could not parse error response")
    else:
        print(f"❌ Unexpected error: {response.status_code}")
    
    # Check the health endpoint to see if backend is running latest code
    print(f"\n🏥 Checking backend health...")
    try:
        health_response = requests.get(f"{base_url}/api/health")
        print(f"Health status: {health_response.status_code}")
        print(f"Health response: {health_response.text}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")

if __name__ == "__main__":
    test_professor_creation_debug() 