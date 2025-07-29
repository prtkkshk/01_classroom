#!/usr/bin/env python3
"""
Test script to verify timestamp-based roll numbers for multiple professors
"""

import requests
import json
import time

def test_timestamp_professors():
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
    
    print(f"\n🧪 Testing timestamp-based roll numbers for multiple professors...")
    print("=" * 70)
    
    # Test creating multiple professors rapidly
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
        },
        {
            "name": "Prof. David Wilson",
            "userid": "david_wilson",
            "email": "david.wilson@university.edu",
            "password": "password123"
        }
    ]
    
    created_professors = []
    
    for i, prof_data in enumerate(professors_data, 1):
        print(f"\n{i}. Creating professor: {prof_data['name']}")
        print(f"   UserID: {prof_data['userid']}")
        print(f"   Email: {prof_data['email']}")
        
        response = requests.post(f"{base_url}/api/admin/create-professor", 
                               json=prof_data, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            roll_number = result['user'].get('roll_number', 'Not set')
            print(f"   ✅ SUCCESS! Professor created")
            print(f"   Roll Number: {roll_number}")
            print(f"   User ID: {result['user']['id']}")
            
            # Verify roll number format
            if roll_number.startswith('PROF_'):
                print(f"   ✅ Roll number format is correct")
                created_professors.append({
                    'name': prof_data['name'],
                    'roll_number': roll_number,
                    'userid': prof_data['userid']
                })
            else:
                print(f"   ⚠️  Roll number format is unexpected: {roll_number}")
                
        elif response.status_code == 400:
            error_data = response.json()
            print(f"   ❌ FAILED: {error_data.get('message', 'Unknown error')}")
            print(f"   💡 This suggests the backend changes haven't been deployed yet")
        else:
            print(f"   ❌ Unexpected error: {response.status_code}")
            print(f"   Response: {response.text}")
    
    # Check all users to see the roll numbers
    print(f"\n📊 Checking all users in database...")
    print("=" * 70)
    
    try:
        users_response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if users_response.status_code == 200:
            users_data = users_response.json()
            users = users_data.get('users', [])
            
            print(f"Total users: {len(users)}")
            print("\nUser details:")
            
            professor_count = 0
            for user in users:
                print(f"  👤 {user.get('name', 'Unknown')}")
                print(f"     Role: {user.get('role', 'Unknown')}")
                print(f"     Roll Number: {user.get('roll_number', 'None')}")
                print(f"     UserID: {user.get('userid', 'None')}")
                
                if user.get('role') == 'professor':
                    professor_count += 1
                    roll_number = user.get('roll_number', 'None')
                    if roll_number and roll_number.startswith('PROF_'):
                        print(f"     ✅ Professor roll number is properly formatted")
                    else:
                        print(f"     ⚠️  Professor roll number needs attention")
                print()
            
            print(f"📈 Summary:")
            print(f"   Total professors: {professor_count}")
            print(f"   Successfully created: {len(created_professors)}")
            
        else:
            print(f"❌ Failed to get users: {users_response.text}")
    except Exception as e:
        print(f"❌ Error getting users: {e}")
    
    # Test uniqueness of roll numbers
    if created_professors:
        print(f"\n🔍 Testing roll number uniqueness...")
        print("=" * 70)
        
        roll_numbers = [prof['roll_number'] for prof in created_professors]
        unique_roll_numbers = set(roll_numbers)
        
        if len(roll_numbers) == len(unique_roll_numbers):
            print(f"✅ All roll numbers are unique!")
            print(f"   Roll numbers: {roll_numbers}")
        else:
            print(f"❌ Duplicate roll numbers found!")
            print(f"   Total: {len(roll_numbers)}, Unique: {len(unique_roll_numbers)}")
    
    print(f"\n🎯 BENEFITS OF TIMESTAMP-BASED ROLL NUMBERS:")
    print("=" * 70)
    print(f"✅ Each professor gets a unique roll number automatically")
    print(f"✅ No manual roll number assignment needed")
    print(f"✅ No conflicts with existing users")
    print(f"✅ Works even with rapid professor creation")
    print(f"✅ Format: PROF_<timestamp_in_milliseconds>")
    print(f"✅ Example: PROF_1753815253123")

if __name__ == "__main__":
    test_timestamp_professors() 