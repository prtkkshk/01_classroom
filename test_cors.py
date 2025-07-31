#!/usr/bin/env python3
"""
Test script to verify CORS configuration
"""
import requests
import json

def test_cors():
    # Test the CORS endpoint
    url = "https://zero1-classroom-1.onrender.com/api/cors-test"
    
    # Test with different origins
    origins = [
        "https://zero1-classroom-2.onrender.com",
        "https://zero1-classroom-1.onrender.com",
        "http://localhost:3000"
    ]
    
    for origin in origins:
        print(f"\nTesting with origin: {origin}")
        
        headers = {
            "Origin": origin,
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers:")
            for key, value in response.headers.items():
                if key.lower().startswith('access-control'):
                    print(f"  {key}: {value}")
            
            if response.status_code == 200:
                print(f"Response Body: {response.json()}")
            else:
                print(f"Error Response: {response.text}")
                
        except Exception as e:
            print(f"Error: {e}")

def test_login_cors():
    """Test the login endpoint specifically"""
    url = "https://zero1-classroom-1.onrender.com/api/login"
    
    headers = {
        "Origin": "https://zero1-classroom-2.onrender.com",
        "Content-Type": "application/json",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type"
    }
    
    # First test OPTIONS (preflight)
    print("\nTesting OPTIONS preflight request:")
    try:
        response = requests.options(url, headers=headers)
        print(f"OPTIONS Status Code: {response.status_code}")
        print(f"OPTIONS Response Headers:")
        for key, value in response.headers.items():
            if key.lower().startswith('access-control'):
                print(f"  {key}: {value}")
    except Exception as e:
        print(f"OPTIONS Error: {e}")
    
    # Then test actual POST
    print("\nTesting POST request:")
    data = {
        "username": "test",
        "password": "test"
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        print(f"POST Status Code: {response.status_code}")
        print(f"POST Response Headers:")
        for key, value in response.headers.items():
            if key.lower().startswith('access-control'):
                print(f"  {key}: {value}")
        
        if response.status_code != 200:
            print(f"POST Error Response: {response.text}")
            
    except Exception as e:
        print(f"POST Error: {e}")

if __name__ == "__main__":
    print("Testing CORS configuration...")
    test_cors()
    test_login_cors() 