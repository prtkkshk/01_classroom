#!/usr/bin/env python3
import requests
import json
import time

BASE_URL = "http://localhost:8001"

def test_moderator_login():
    print("Testing moderator login...")
    response = requests.post(f"{BASE_URL}/api/login", json={
        "username": "pepper_moderator",
        "password": "pepper_14627912"
    })
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Token: {data['access_token']}")
        return data['access_token']
    else:
        print(f"Error: {response.text}")
        return None

def test_student_registration_for_login():
    print("\nTesting student registration for login test...")
    timestamp = int(time.time())
    student_data = {
        "name": f"Test Student {timestamp}",
        "roll_number": f"23BT{timestamp}",
        "email": f"student{timestamp}@test.com",
        "password": "SecurePassword123!"
    }
    
    response = requests.post(f"{BASE_URL}/api/register", json=student_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    return response.status_code == 200

def test_professor_creation_for_login(token):
    print("\nTesting professor creation for login test...")
    timestamp = int(time.time())
    professor_data = {
        "name": "Test Professor",
        "userid": f"prof{timestamp}",
        "email": f"professor{timestamp}@test.com",
        "password": "SecurePassword123!"
    }
    
    response = requests.post(f"{BASE_URL}/api/admin/professors", json=professor_data, headers={
        "Authorization": f"Bearer {token}"
    })
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    return response.status_code == 200

if __name__ == "__main__":
    # Test moderator login
    token = test_moderator_login()
    
    # Test the specific failing scenarios
    test_student_registration_for_login()
    
    if token:
        test_professor_creation_for_login(token) 