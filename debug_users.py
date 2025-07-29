#!/usr/bin/env python3
"""
Script to debug existing users and identify conflicts
"""

import requests
import json

def get_moderator_token(base_url):
    """Get a moderator token by logging in"""
    
    login_data = {
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    }
    
    try:
        response = requests.post(f"{base_url}/api/login", json=login_data)
        if response.status_code == 200:
            data = response.json()
            return data.get('access_token')
        else:
            print(f"Login failed: {response.text}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def check_existing_users(base_url, token):
    """Check what users exist in the database"""
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if response.status_code == 200:
            data = response.json()
            users = data.get('users', [])
            
            print(f"📊 Found {len(users)} users in database:")
            print("=" * 60)
            
            for user in users:
                print(f"ID: {user.get('id', 'N/A')}")
                print(f"Name: {user.get('name', 'N/A')}")
                print(f"Email: {user.get('email', 'N/A')}")
                print(f"UserID: {user.get('userid', 'N/A')}")
                print(f"Role: {user.get('role', 'N/A')}")
                print(f"Roll Number: {user.get('roll_number', 'N/A')}")
                print("-" * 40)
            
            return users
        else:
            print(f"Failed to get users: {response.text}")
            return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def test_specific_conflicts(base_url, token, test_data):
    """Test specific conflicts with the test data"""
    
    print(f"\n🔍 Testing conflicts for:")
    print(f"Email: {test_data['email']}")
    print(f"UserID: {test_data['userid']}")
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Test email conflict
    try:
        response = requests.get(f"{base_url}/api/admin/users", headers=headers)
        if response.status_code == 200:
            data = response.json()
            users = data.get('users', [])
            
            email_conflict = any(user.get('email') == test_data['email'] for user in users)
            userid_conflict = any(user.get('userid') == test_data['userid'] for user in users)
            
            if email_conflict:
                print(f"❌ Email conflict found: {test_data['email']}")
            else:
                print(f"✅ Email available: {test_data['email']}")
                
            if userid_conflict:
                print(f"❌ UserID conflict found: {test_data['userid']}")
            else:
                print(f"✅ UserID available: {test_data['userid']}")
                
            return email_conflict or userid_conflict
    except Exception as e:
        print(f"Error checking conflicts: {e}")
        return True

def main():
    base_url = "https://zero1-classroom-1.onrender.com"
    
    print("🔍 Debugging user conflicts...")
    print("=" * 60)
    
    # Get moderator token
    token = get_moderator_token(base_url)
    if not token:
        print("❌ Could not get moderator token")
        return
    
    print("✅ Got moderator token")
    
    # Check existing users
    users = check_existing_users(base_url, token)
    
    # Test with the data that failed
    test_data = {
        "name": "Test Professor 1753813926300",
        "userid": "testprof1753813926300",
        "email": "test1753813926300@example.com",
        "password": "password123"
    }
    
    has_conflicts = test_specific_conflicts(base_url, token, test_data)
    
    if has_conflicts:
        print("\n❌ Conflicts found - this explains the 400 error")
    else:
        print("\n✅ No conflicts found - the error might be elsewhere")
        
        # Try to create the professor
        print("\n🧪 Attempting to create professor...")
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(f"{base_url}/api/admin/create-professor", 
                                   json=test_data, headers=headers)
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main() 