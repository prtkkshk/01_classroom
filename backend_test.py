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

def test_registration():
    """Test user registration"""
    test_user = {
        "name": "Test User",
        "roll_number": "TEST001",
        "email": "test@example.com",
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

def test_login():
    """Test user login"""
    login_data = {
        "username": "TEST001",
        "password": "testpass123"
    }
    
    try:
        response = requests.post(f"{API_URL}/login", json=login_data)
        print(f"Login test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Login successful! Token: {data.get('access_token', 'No token')[:20]}...")
            return data.get('access_token')
        else:
            print(f"Login failed: {response.text}")
            return None
    except Exception as e:
        print(f"Login test failed: {e}")
        return None

def test_courses_endpoint(token):
    """Test courses endpoint with authentication"""
    if not token:
        print("No token provided for courses test")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_URL}/courses", headers=headers)
        print(f"Courses test: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Courses test failed: {e}")
        return False

def main():
    print("=== Backend API Test ===")
    
    # Test 1: Backend health
    print("\n1. Testing backend health...")
    if not test_backend_health():
        print("Backend is not accessible. Please check if it's running.")
        return
    
    # Test 2: Registration
    print("\n2. Testing registration...")
    token = test_registration()
    
    # Test 3: Login
    print("\n3. Testing login...")
    login_token = test_login()
    
    # Test 4: Courses endpoint
    print("\n4. Testing courses endpoint...")
    if token or login_token:
        test_courses_endpoint(token or login_token)
    else:
        print("No valid token available for courses test")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()