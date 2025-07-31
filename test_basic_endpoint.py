#!/usr/bin/env python3
"""
Test script to check if basic endpoints are working
"""

import asyncio
import aiohttp
import json
from datetime import datetime

async def test_basic_endpoints():
    """Test basic endpoints that don't require authentication"""
    
    base_url = "https://zero1-classroom-1.onrender.com"
    
    print(f"🔍 TESTING BASIC ENDPOINTS")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Base URL: {base_url}")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Test 1: Root endpoint
        print("1. Testing root endpoint...")
        try:
            async with session.get(f"{base_url}/") as response:
                print(f"   Status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    print(f"   Response: {data}")
                else:
                    print(f"   Error: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 2: Status endpoint
        print("2. Testing status endpoint...")
        try:
            async with session.get(f"{base_url}/status") as response:
                print(f"   Status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    print(f"   Response: {data}")
                else:
                    print(f"   Error: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 3: Health endpoint
        print("3. Testing health endpoint...")
        try:
            async with session.get(f"{base_url}/api/health") as response:
                print(f"   Status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    print(f"   Response: {data}")
                else:
                    print(f"   Error: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")
        
        print()
        
        # Test 4: Test endpoint
        print("4. Testing test endpoint...")
        try:
            async with session.get(f"{base_url}/api/test") as response:
                print(f"   Status: {response.status}")
                if response.status == 200:
                    data = await response.json()
                    print(f"   Response: {data}")
                else:
                    print(f"   Error: {await response.text()}")
        except Exception as e:
            print(f"   Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_basic_endpoints()) 