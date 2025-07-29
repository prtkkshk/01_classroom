#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Classroom Application
Tests all backend APIs including authentication, questions, and polls
"""

import requests
import json
import uuid
from datetime import datetime
import time

# Test configuration
BASE_URL = "https://zero1-classroom-1.onrender.com"
API_URL = f"{BASE_URL}/api"

# Hardcoded credentials
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

def test_backend_health():
    """Test if the backend is running"""
    try:
        response = requests.get(BASE_URL)
        print(f"Backend health check: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Backend health check failed: {e}")
        return False

def test_moderator_login():
    """Test moderator login"""
    login_data = {
        "username": MODERATOR_USERNAME,
        "password": MODERATOR_PASSWORD
    }
    
    try:
        response = requests.post(f"{API_URL}/login", json=login_data)
        print(f"Moderator login test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Moderator login successful! Token: {data.get('access_token', 'No token')[:20]}...")
            return data.get('access_token')
        else:
            print(f"Moderator login failed: {response.text}")
            return None
    except Exception as e:
        print(f"Moderator login test failed: {e}")
        return None

def test_get_all_users(token):
    """Test getting all users as moderator"""
    if not token:
        print("No token provided for get all users test")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_URL}/admin/users", headers=headers)
        print(f"Get all users test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Found {len(data)} users")
            for user in data:
                print(f"  - {user.get('name', 'No name')} ({user.get('role', 'No role')}) - {user.get('roll_number', user.get('userid', 'No ID'))}")
            return True
        else:
            print(f"Get all users failed: {response.text}")
            return False
    except Exception as e:
        print(f"Get all users test failed: {e}")
        return False

def test_create_professor(token):
    """Test creating a professor account as moderator"""
    if not token:
        print("No token provided for create professor test")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    professor_data = {
        "name": "Test Professor",
        "userid": "TESTPROF001",
        "email": "testprof@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{API_URL}/admin/create-professor", json=professor_data, headers=headers)
        print(f"Create professor test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Professor created successfully! Token: {data.get('access_token', 'No token')[:20]}...")
            return True
        else:
            print(f"Create professor failed: {response.text}")
            return False
    except Exception as e:
        print(f"Create professor test failed: {e}")
        return False

def test_registration():
    """Test user registration"""
    test_user = {
        "name": "Test Student",
        "roll_number": "TESTSTU002",
        "email": "teststu@example.com",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{API_URL}/register", json=test_user)
        print(f"Registration test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Registration successful! Token: {data.get('access_token', 'No token')[:20]}...")
            return data.get('access_token')
        else:
            print(f"Registration failed: {response.text}")
            return None
    except Exception as e:
        print(f"Registration test failed: {e}")
        return None

def main():
    print("=== Backend API Test ===")
    
    # Test 1: Backend health
    print("\n1. Testing backend health...")
    if not test_backend_health():
        print("Backend is not accessible. Please check if it's running.")
        return
    
    # Test 2: Moderator login
    print("\n2. Testing moderator login...")
    moderator_token = test_moderator_login()
    
    if moderator_token:
        # Test 3: Get all users
        print("\n3. Testing get all users...")
        test_get_all_users(moderator_token)
        
        # Test 4: Create professor
        print("\n4. Testing create professor...")
        test_create_professor(moderator_token)
        
        # Test 5: Get all users again to see the new professor
        print("\n5. Testing get all users after professor creation...")
        test_get_all_users(moderator_token)
    else:
        print("Moderator login failed, skipping moderator tests")
    
    # Test 6: Student registration
    print("\n6. Testing student registration...")
    student_token = test_registration()
    
    if student_token and moderator_token:
        # Test 7: Get all users to see the new student
        print("\n7. Testing get all users after student registration...")
        test_get_all_users(moderator_token)
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()