#!/usr/bin/env python3
"""
Test script to demonstrate what happens when adding multiple professors
"""

import requests
import json
import time

def test_multiple_professors():
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
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Test creating multiple professors
    professors_data = [
        {
            "name": "Dr. Alice Johnson",
            "userid": "alice_johnson",
            "email": "alice.johnson@university.edu",
            "password": "password123"
        },
        {
            "name": "Prof. Bob Smith",
            "userid": "bob_smith",
            "email": "bob.smith@university.edu",
            "password": "password123"
        },
        {
            "name": "Dr. Carol Davis",
            "userid": "carol_davis",
            "email": "carol.davis@university.edu",
            "password": "password123"
        }
    ]
    
    print(f"\n🧪 Testing creation of {len(professors_data)} professors...")
    print("=" * 60)
    
    created_professors = []
    
    for i, prof_data in enumerate(professors_data, 1):
        print(f"\n{i}. Creating professor: {prof_data['name']}")
        print(f"   UserID: {prof_data['userid']}")
        print(f"   Email: {prof_data['email']}")
        
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=prof_data, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Success! Professor created")
            print(f"   Roll Number: PROF_{prof_data['userid']}")
            print(f"   User ID: {result['user']['id']}")
            created_professors.append(prof_data['userid'])
        elif response.status_code == 400:
            error_data = response.json()
            print(f"   ❌ Failed: {error_data.get('message', 'Unknown error')}")
        else:
            print(f"   ❌ Unexpected error: {response.status_code}")
            print(f"   Response: {response.text}")
    
    # Check all users to see the roll numbers
    print(f"\n📊 Checking all users in database...")
    print("=" * 60)
    
    try:
        users_response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if users_response.status_code == 200:
            users_data = users_response.json()
            users = users_data.get('users', [])
            
            print(f"Total users: {len(users)}")
            print("\nUser details:")
            for user in users:
                print(f"  👤 {user.get('name', 'Unknown')}")
                print(f"     Role: {user.get('role', 'Unknown')}")
                print(f"     Email: {user.get('email', 'None')}")
                print(f"     UserID: {user.get('userid', 'None')}")
                print(f"     Roll Number: {user.get('roll_number', 'None')}")
                print()
        else:
            print(f"❌ Failed to get users: {users_response.text}")
    except Exception as e:
        print(f"❌ Error getting users: {e}")
    
    # Test what happens with duplicate data
    print(f"\n🧪 Testing duplicate professor creation...")
    print("=" * 60)
    
    if created_professors:
        duplicate_data = {
            "name": "Duplicate Professor",
            "userid": created_professors[0],  # Use existing userid
            "email": "duplicate@university.edu",
            "password": "password123"
        }
        
        print(f"Attempting to create professor with existing UserID: {duplicate_data['userid']}")
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=duplicate_data, headers=headers)
        
        if response.status_code == 400:
            error_data = response.json()
            print(f"✅ Correctly rejected: {error_data.get('message', 'Unknown error')}")
        else:
            print(f"❌ Unexpected: Should have been rejected but got {response.status_code}")
    
    print(f"\n🎉 Test completed!")
    print(f"✅ Successfully created {len(created_professors)} professors")
    print(f"💡 Each professor gets a unique roll number: PROF_<userid>")

if __name__ == "__main__":
    test_multiple_professors() 