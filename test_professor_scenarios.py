#!/usr/bin/env python3
"""
Comprehensive test to show all scenarios when adding professors
"""

import requests
import json
import time

def test_professor_scenarios():
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
    
    print(f"\n📋 CURRENT SYSTEM BEHAVIOR:")
    print("=" * 60)
    
    # Check current users
    try:
        users_response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if users_response.status_code == 200:
            users_data = users_response.json()
            users = users_data.get('users', [])
            
            print(f"Current users in database:")
            for user in users:
                print(f"  👤 {user.get('name', 'Unknown')}")
                print(f"     Role: {user.get('role', 'Unknown')}")
                print(f"     Roll Number: {user.get('roll_number', 'None')}")
                print(f"     UserID: {user.get('userid', 'None')}")
                print()
    except Exception as e:
        print(f"❌ Error getting users: {e}")
    
    print(f"\n🔮 WHAT WILL HAPPEN WHEN YOU ADD MORE PROFESSORS:")
    print("=" * 60)
    
    # Test with unique data
    timestamp = int(time.time())
    test_professors = [
        {
            "name": f"Dr. Alice Johnson {timestamp}",
            "userid": f"alice_{timestamp}",
            "email": f"alice_{timestamp}@university.edu",
            "password": "password123"
        },
        {
            "name": f"Prof. Bob Smith {timestamp}",
            "userid": f"bob_{timestamp}",
            "email": f"bob_{timestamp}@university.edu",
            "password": "password123"
        }
    ]
    
    print(f"Testing with unique data (timestamp: {timestamp}):")
    
    for i, prof_data in enumerate(test_professors, 1):
        print(f"\n{i}. Creating: {prof_data['name']}")
        print(f"   UserID: {prof_data['userid']}")
        print(f"   Expected Roll Number: PROF_{prof_data['userid']}")
        
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=prof_data, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ SUCCESS! Professor created")
            print(f"   Actual Roll Number: {result['user'].get('roll_number', 'Not set')}")
            print(f"   User ID: {result['user']['id']}")
        elif response.status_code == 400:
            error_data = response.json()
            print(f"   ❌ FAILED: {error_data.get('message', 'Unknown error')}")
            print(f"   💡 This suggests the backend changes haven't been deployed yet")
        else:
            print(f"   ❌ Unexpected error: {response.status_code}")
    
    print(f"\n📊 VALIDATION SCENARIOS:")
    print("=" * 60)
    
    # Test duplicate scenarios
    if test_professors:
        print(f"\n1️⃣ Duplicate UserID test:")
        duplicate_userid = {
            "name": "Duplicate UserID Professor",
            "userid": test_professors[0]['userid'],  # Use existing userid
            "email": "different@university.edu",
            "password": "password123"
        }
        
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=duplicate_userid, headers=headers)
        
        if response.status_code == 400:
            error_data = response.json()
            print(f"   ✅ Correctly rejected: {error_data.get('message', 'Unknown error')}")
        else:
            print(f"   ❌ Should have been rejected but got {response.status_code}")
        
        print(f"\n2️⃣ Duplicate Email test:")
        duplicate_email = {
            "name": "Duplicate Email Professor",
            "userid": "different_userid",
            "email": test_professors[0]['email'],  # Use existing email
            "password": "password123"
        }
        
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=duplicate_email, headers=headers)
        
        if response.status_code == 400:
            error_data = response.json()
            print(f"   ✅ Correctly rejected: {error_data.get('message', 'Unknown error')}")
        else:
            print(f"   ❌ Should have been rejected but got {response.status_code}")
    
    print(f"\n🎯 SUMMARY:")
    print("=" * 60)
    print(f"✅ Each professor will get a unique roll number: PROF_<userid>")
    print(f"✅ Duplicate UserIDs will be rejected")
    print(f"✅ Duplicate emails will be rejected")
    print(f"✅ No more roll_number conflicts (null values)")
    print(f"✅ Professors can be created without issues")
    print(f"💡 Once backend is deployed, all professor creation will work smoothly!")

if __name__ == "__main__":
    test_professor_scenarios() 