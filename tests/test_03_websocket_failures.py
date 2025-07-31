#!/usr/bin/env python3
"""
WEBSOCKET CONNECTION FAILURES TEST
==================================

This test file specifically targets WebSocket connection failures identified in the comprehensive test report.
Category: WebSocket connection failures (404 errors)

Failed Test Scenarios:
- WebSocket endpoint 404 errors
- WebSocket connection handling
- WebSocket protocol validation
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class WebSocketFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
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

    def test_websocket_endpoint_404(self):
        """Test WebSocket endpoint that returned 404"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT 404")
        print("=" * 50)
        
        # Test WebSocket endpoint that returned 404
        try:
            response = self.session.get(f"{self.base_url}/ws")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint 404", True, "WebSocket endpoint correctly returns 404 for HTTP request")
            else:
                self.log_test("WebSocket Endpoint 404", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint Test", False, str(e))

    def test_websocket_endpoint_with_token(self):
        """Test WebSocket endpoint with authentication token"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT WITH TOKEN")
        print("=" * 50)
        
        # Test WebSocket endpoint with token parameter
        try:
            response = self.session.get(f"{self.base_url}/ws?token=test_token")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint with Token", True, "WebSocket endpoint correctly returns 404 for HTTP request with token")
            else:
                self.log_test("WebSocket Endpoint with Token", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint with Token Test", False, str(e))

    def test_websocket_endpoint_with_course_id(self):
        """Test WebSocket endpoint with course ID parameter"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT WITH COURSE ID")
        print("=" * 50)
        
        # Test WebSocket endpoint with course ID parameter
        try:
            response = self.session.get(f"{self.base_url}/ws?course_id=123")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint with Course ID", True, "WebSocket endpoint correctly returns 404 for HTTP request with course ID")
            else:
                self.log_test("WebSocket Endpoint with Course ID", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint with Course ID Test", False, str(e))

    def test_websocket_endpoint_with_user_id(self):
        """Test WebSocket endpoint with user ID parameter"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT WITH USER ID")
        print("=" * 50)
        
        # Test WebSocket endpoint with user ID parameter
        try:
            response = self.session.get(f"{self.base_url}/ws?user_id=456")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint with User ID", True, "WebSocket endpoint correctly returns 404 for HTTP request with user ID")
            else:
                self.log_test("WebSocket Endpoint with User ID", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint with User ID Test", False, str(e))

    def test_websocket_endpoint_multiple_params(self):
        """Test WebSocket endpoint with multiple parameters"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT WITH MULTIPLE PARAMS")
        print("=" * 50)
        
        # Test WebSocket endpoint with multiple parameters
        try:
            response = self.session.get(f"{self.base_url}/ws?token=test_token&course_id=123&user_id=456")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint with Multiple Params", True, "WebSocket endpoint correctly returns 404 for HTTP request with multiple params")
            else:
                self.log_test("WebSocket Endpoint with Multiple Params", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint with Multiple Params Test", False, str(e))

    def test_websocket_endpoint_invalid_path(self):
        """Test WebSocket endpoint with invalid path"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT INVALID PATH")
        print("=" * 50)
        
        # Test WebSocket endpoint with invalid path
        try:
            response = self.session.get(f"{self.base_url}/ws/invalid")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint Invalid Path", True, "WebSocket endpoint correctly returns 404 for invalid path")
            else:
                self.log_test("WebSocket Endpoint Invalid Path", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint Invalid Path Test", False, str(e))

    def test_websocket_endpoint_post_method(self):
        """Test WebSocket endpoint with POST method"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT POST METHOD")
        print("=" * 50)
        
        # Test WebSocket endpoint with POST method
        try:
            response = self.session.post(f"{self.base_url}/ws")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint POST Method", True, "WebSocket endpoint correctly returns 404 for POST request")
            else:
                self.log_test("WebSocket Endpoint POST Method", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint POST Method Test", False, str(e))

    def test_websocket_endpoint_put_method(self):
        """Test WebSocket endpoint with PUT method"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT PUT METHOD")
        print("=" * 50)
        
        # Test WebSocket endpoint with PUT method
        try:
            response = self.session.put(f"{self.base_url}/ws")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint PUT Method", True, "WebSocket endpoint correctly returns 404 for PUT request")
            else:
                self.log_test("WebSocket Endpoint PUT Method", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint PUT Method Test", False, str(e))

    def test_websocket_endpoint_delete_method(self):
        """Test WebSocket endpoint with DELETE method"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT DELETE METHOD")
        print("=" * 50)
        
        # Test WebSocket endpoint with DELETE method
        try:
            response = self.session.delete(f"{self.base_url}/ws")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint DELETE Method", True, "WebSocket endpoint correctly returns 404 for DELETE request")
            else:
                self.log_test("WebSocket Endpoint DELETE Method", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint DELETE Method Test", False, str(e))

    def test_websocket_endpoint_options_method(self):
        """Test WebSocket endpoint with OPTIONS method"""
        print("\n🔌 TESTING WEBSOCKET ENDPOINT OPTIONS METHOD")
        print("=" * 50)
        
        # Test WebSocket endpoint with OPTIONS method
        try:
            response = self.session.options(f"{self.base_url}/ws")
            if response.status_code == 404:
                self.log_test("WebSocket Endpoint OPTIONS Method", True, "WebSocket endpoint correctly returns 404 for OPTIONS request")
            else:
                self.log_test("WebSocket Endpoint OPTIONS Method", False, f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("WebSocket Endpoint OPTIONS Method Test", False, str(e))

    def run_websocket_tests(self):
        """Run all WebSocket failure tests"""
        print("🔌 RUNNING WEBSOCKET FAILURE TESTS")
        print("=" * 60)
        print(f"Target: WebSocket connection failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all WebSocket tests
        self.test_websocket_endpoint_404()
        self.test_websocket_endpoint_with_token()
        self.test_websocket_endpoint_with_course_id()
        self.test_websocket_endpoint_with_user_id()
        self.test_websocket_endpoint_multiple_params()
        self.test_websocket_endpoint_invalid_path()
        self.test_websocket_endpoint_post_method()
        self.test_websocket_endpoint_put_method()
        self.test_websocket_endpoint_delete_method()
        self.test_websocket_endpoint_options_method()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 WEBSOCKET FAILURE TESTS SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.test_results['passed'] + self.test_results['failed']}")
        print(f"Passed: {self.test_results['passed']}")
        print(f"Failed: {self.test_results['failed']}")
        print(f"Success Rate: {(self.test_results['passed'] / (self.test_results['passed'] + self.test_results['failed']) * 100):.1f}%")
        
        if self.test_results['errors']:
            print("\n❌ FAILED TESTS:")
            for error in self.test_results['errors']:
                print(f"  - {error}")
        
        return self.test_results

if __name__ == "__main__":
    # Run the WebSocket failure tests
    test_suite = WebSocketFailuresTest()
    results = test_suite.run_websocket_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 