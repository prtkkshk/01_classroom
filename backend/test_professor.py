#!/usr/bin/env python3
"""
Simple test script to debug professor creation
"""

import asyncio
import os
import requests
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'classroom_live')]

async def test_professor_creation():
    """Test professor creation directly"""
    print("🧪 Testing professor creation...")
    
    # First, let's check what users exist
    users = await db.users.find().to_list(10)
    print(f"Current users in database: {len(users)}")
    for user in users:
        print(f"  - {user.get('name')} ({user.get('email')}) - userid: {user.get('userid')}")
    
    # Check for specific conflicts
    test_email = "prof_debug@test.com"
    test_userid = "prof_debug_123"
    
    existing_email = await db.users.find_one({"email": test_email})
    existing_userid = await db.users.find_one({"userid": test_userid})
    
    print(f"Existing email check: {existing_email is not None}")
    print(f"Existing userid check: {existing_userid is not None}")
    
    # Test creating a professor via API
    base_url = "http://localhost:8001"
    
    # First login as moderator
    moderator_login = {
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    }
    
    try:
        response = requests.post(f"{base_url}/api/login", json=moderator_login)
        print(f"Moderator login status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            token = data["access_token"]
            print(f"Got moderator token: {token[:20]}...")
            
            # Now try to create a professor
            professor_data = {
                "name": "Test Professor Debug",
                "userid": "prof_debug_123",
                "email": "prof_debug@test.com",
                "password": "SecurePassword123!"
            }
            
            headers = {"Authorization": f"Bearer {token}"}
            response2 = requests.post(f"{base_url}/api/admin/professors", json=professor_data, headers=headers)
            print(f"Professor creation status: {response2.status_code}")
            print(f"Professor creation response: {response2.text}")
            
            if response2.status_code == 200:
                print("✅ Professor created successfully!")
            else:
                print("❌ Professor creation failed!")
                
        else:
            print(f"Moderator login failed: {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_professor_creation()) 