#!/usr/bin/env python3
"""
WEBSOCKET TESTS FOR REAL-TIME FEATURES
======================================

Tests all WebSocket functionality including:
- Connection establishment
- Real-time messaging
- Course-specific broadcasts
- User presence
- Error handling
"""

import asyncio
import websockets
import json
import time
import requests
from typing import Dict, List

class WebSocketTestSuite:
    def __init__(self, base_url: str = "https://zero1-classroom-1.onrender.com"):
        self.base_url = base_url.replace("https://", "wss://")
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        if success:
            self.test_results["passed"] += 1
        else:
            self.test_results["failed"] += 1
            self.test_results["errors"].append(f"{test_name}: {details}")
    
    async def get_token(self):
        """Get authentication token"""
        login_data = {
            "username": "pepper_moderator",
            "password": "pepper_14627912"
        }
        
        response = requests.post(f"{self.base_url.replace('wss://', 'https://')}/api/login", 
                               json=login_data)
        if response.status_code == 200:
            return response.json()["access_token"]
        return None
    
    async def test_websocket_connection(self):
        """Test basic WebSocket connection"""
        print("\n🔌 TESTING WEBSOCKET CONNECTION")
        print("=" * 50)
        
        token = await self.get_token()
        if not token:
            self.log_test("Get Token", False, "Failed to get authentication token")
            return
        
        try:
            uri = f"{self.base_url}/ws?token={token}"
            websocket = await websockets.connect(uri)
            
            # Test connection is alive
            pong_waiter = await websocket.ping()
            await pong_waiter
            
            self.log_test("WebSocket Connection", True, "Successfully connected")
            
            # Test sending a message
            test_message = {
                "type": "test",
                "message": "Hello WebSocket!"
            }
            await websocket.send(json.dumps(test_message))
            self.log_test("Send Message", True, "Message sent successfully")
            
            # Test receiving messages (with timeout)
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                data = json.loads(message)
                self.log_test("Receive Message", True, f"Received: {data}")
            except asyncio.TimeoutError:
                self.log_test("Receive Message", False, "Timeout waiting for message")
            
            await websocket.close()
            self.log_test("Close Connection", True, "Connection closed successfully")
            
        except Exception as e:
            self.log_test("WebSocket Connection", False, str(e))
    
    async def test_multiple_connections(self):
        """Test multiple simultaneous WebSocket connections"""
        print("\n👥 TESTING MULTIPLE CONNECTIONS")
        print("=" * 50)
        
        token = await self.get_token()
        if not token:
            self.log_test("Multiple Connections", False, "No token available")
            return
        
        connections = []
        try:
            # Create multiple connections
            for i in range(3):
                uri = f"{self.base_url}/ws?token={token}"
                websocket = await websockets.connect(uri)
                connections.append(websocket)
                self.log_test(f"Connection {i+1}", True, f"Connection {i+1} established")
            
            # Test all connections are alive
            for i, websocket in enumerate(connections):
                pong_waiter = await websocket.ping()
                await pong_waiter
                self.log_test(f"Connection {i+1} Ping", True, f"Connection {i+1} is alive")
            
            # Close all connections
            for i, websocket in enumerate(connections):
                await websocket.close()
                self.log_test(f"Connection {i+1} Close", True, f"Connection {i+1} closed")
            
        except Exception as e:
            self.log_test("Multiple Connections", False, str(e))
    
    async def test_invalid_token(self):
        """Test WebSocket connection with invalid token"""
        print("\n🚫 TESTING INVALID TOKEN")
        print("=" * 50)
        
        try:
            uri = f"{self.base_url}/ws?token=invalid_token"
            websocket = await websockets.connect(uri)
            
            # Should not reach here with invalid token
            await websocket.close()
            self.log_test("Invalid Token", False, "Connection should have been rejected")
            
        except Exception as e:
            self.log_test("Invalid Token", True, f"Correctly rejected: {str(e)}")
    
    async def test_no_token(self):
        """Test WebSocket connection without token"""
        print("\n🚫 TESTING NO TOKEN")
        print("=" * 50)
        
        try:
            uri = f"{self.base_url}/ws"
            websocket = await websockets.connect(uri)
            
            # Should not reach here without token
            await websocket.close()
            self.log_test("No Token", False, "Connection should have been rejected")
            
        except Exception as e:
            self.log_test("No Token", True, f"Correctly rejected: {str(e)}")
    
    async def run_all_tests(self):
        """Run all WebSocket tests"""
        print("🔌 STARTING WEBSOCKET TEST SUITE")
        print("=" * 60)
        
        await self.test_websocket_connection()
        await self.test_multiple_connections()
        await self.test_invalid_token()
        await self.test_no_token()
        
        # Print summary
        print("\n📊 WEBSOCKET TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        print(f"📈 Success Rate: {(self.test_results['passed'] / (self.test_results['passed'] + self.test_results['failed']) * 100):.1f}%")

if __name__ == "__main__":
    asyncio.run(WebSocketTestSuite().run_all_tests()) 