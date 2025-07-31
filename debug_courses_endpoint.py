#!/usr/bin/env python3
"""
Debug script to test the courses endpoint and identify the root cause of 500 errors
"""

import asyncio
import aiohttp
import json
import sys
from datetime import datetime

async def test_courses_endpoint():
    """Test the courses endpoint to identify the issue"""
    
    # Test URLs
    base_url = "https://zero1-classroom-1.onrender.com"
    health_url = f"{base_url}/api/health"
    courses_url = f"{base_url}/api/courses"
    
    print(f"🔍 DEBUGGING COURSES ENDPOINT")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Base URL: {base_url}")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Health check
        print("1. Testing health endpoint...")
        try:
            async with session.get(health_url) as response:
                print(f"   Status: {response.status}")
                if response.status == 200:
                    health_data = await response.json()
                    print(f"   Health: {health_data.get('status', 'unknown')}")
                    print(f"   Database: {health_data.get('database', {}).get('status', 'unknown')}")
                else:
                    print(f"   Error: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 2: Courses endpoint without auth
        print("2. Testing courses endpoint without authentication...")
        try:
            async with session.get(courses_url) as response:
                print(f"   Status: {response.status}")
                if response.status == 401:
                    print("   Expected: 401 Unauthorized (no auth token)")
                else:
                    print(f"   Unexpected: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 3: Courses endpoint with invalid auth
        print("3. Testing courses endpoint with invalid auth...")
        headers = {"Authorization": "Bearer invalid_token"}
        try:
            async with session.get(courses_url, headers=headers) as response:
                print(f"   Status: {response.status}")
                if response.status == 401:
                    print("   Expected: 401 Unauthorized (invalid token)")
                else:
                    print(f"   Unexpected: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 4: Courses endpoint with malformed auth
        print("4. Testing courses endpoint with malformed auth...")
        headers = {"Authorization": "Bearer"}
        try:
            async with session.get(courses_url, headers=headers) as response:
                print(f"   Status: {response.status}")
                print(f"   Response: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 5: Check if the issue is with the endpoint itself
        print("5. Testing with a valid JWT token structure...")
        # Create a fake JWT token with proper structure but invalid signature
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNjE2MjM5MDIyfQ.invalid_signature"
        headers = {"Authorization": f"Bearer {fake_token}"}
        try:
            async with session.get(courses_url, headers=headers) as response:
                print(f"   Status: {response.status}")
                if response.status == 401:
                    print("   Expected: 401 Unauthorized (invalid signature)")
                else:
                    print(f"   Unexpected: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_courses_endpoint()) 