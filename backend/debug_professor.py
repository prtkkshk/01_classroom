#!/usr/bin/env python3
"""
Debug script to test professor creation step by step
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

async def debug_professor_creation():
    """Debug professor creation step by step"""
    print("🔍 Debugging professor creation...")
    
    # First, let's check what users exist
    users = await db.users.find().to_list(10)
    print(f"Current users in database: {len(users)}")
    for user in users:
        print(f"  - {user.get('name')} ({user.get('email')}) - userid: {user.get('userid')} - roll_number: {user.get('roll_number')}")
    
    # Test data
    test_email = "prof_debug2@test.com"
    test_userid = "prof_debug_456"
    
    print(f"\n🔍 Testing with email: {test_email}")
    print(f"🔍 Testing with userid: {test_userid}")
    
    # Check for conflicts directly in database
    existing_email = await db.users.find_one({"email": test_email})
    existing_userid = await db.users.find_one({"userid": test_userid})
    
    print(f"Database check - existing email: {existing_email is not None}")
    print(f"Database check - existing userid: {existing_userid is not None}")
    
    # Test the API endpoint
    print("\n🔍 Testing API endpoint...")
    
    # First login as moderator
    moderator_login = {
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    }
    
    response = requests.post("http://localhost:8001/api/login", json=moderator_login)
    print(f"Moderator login status: {response.status_code}")
    
    if response.status_code == 200:
        token = response.json()["access_token"]
        print(f"Got moderator token: {token[:20]}...")
        
        # Test professor creation
        professor_data = {
            "name": "Debug Professor",
            "userid": test_userid,
            "email": test_email,
            "password": "testpass123"
        }
        
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post("http://localhost:8001/api/admin/professors", json=professor_data, headers=headers)
        print(f"Professor creation status: {response.status_code}")
        print(f"Professor creation response: {response.text}")
        
        if response.status_code != 200:
            print("❌ Professor creation failed!")
        else:
            print("✅ Professor creation succeeded!")
    else:
        print(f"❌ Moderator login failed: {response.text}")

if __name__ == "__main__":
    asyncio.run(debug_professor_creation()) 