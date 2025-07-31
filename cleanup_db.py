#!/usr/bin/env python3
"""
Database cleanup script to remove test data
"""

import requests
import json
import time

BASE_URL = "http://localhost:8001"

def get_moderator_token():
    """Get moderator token for admin operations"""
    response = requests.post(f"{BASE_URL}/api/login", json={
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    })
    if response.status_code == 200:
        return response.json()["access_token"]
    return None

def get_all_users(token):
    """Get all users from the database"""
    response = requests.get(f"{BASE_URL}/api/admin/users", headers={
        "Authorization": f"Bearer {token}"
    })
    if response.status_code == 200:
        return response.json()["users"]
    return []

def delete_user(token, user_id):
    """Delete a user by ID"""
    response = requests.delete(f"{BASE_URL}/api/admin/users/{user_id}", headers={
        "Authorization": f"Bearer {token}"
    })
    return response.status_code == 200

def cleanup_test_users():
    """Clean up all test users"""
    print("🧹 Starting database cleanup...")
    
    # Get moderator token
    token = get_moderator_token()
    if not token:
        print("❌ Failed to get moderator token")
        return
    
    # Get all users
    users = get_all_users(token)
    print(f"Found {len(users)} users in database")
    
    # Delete test users (excluding moderator and professor accounts)
    deleted_count = 0
    for user in users:
        user_id = user.get("id")
        email = user.get("email", "")
        name = user.get("name", "")
        role = user.get("role", "")
        
        # Skip moderator accounts only
        if role == "moderator":
            print(f"⏭️  Skipping {role}: {name} ({email})")
            continue
        
        # Delete test users and professors
        if delete_user(token, user_id):
            print(f"✅ Deleted user: {name} ({email})")
            deleted_count += 1
        else:
            print(f"❌ Failed to delete user: {name} ({email})")
    
    print(f"🧹 Cleanup complete. Deleted {deleted_count} test users.")

if __name__ == "__main__":
    cleanup_test_users() 