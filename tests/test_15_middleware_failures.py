#!/usr/bin/env python3
"""
MIDDLEWARE FAILURES TEST
========================

This test file specifically targets middleware failures identified in the comprehensive test report.
Category: Middleware failures (rate limiting, authentication)

Failed Test Scenarios:
- Rate limiting middleware failures
- Authentication middleware failures
- Middleware error handling
"""

import requests
import time
from datetime import datetime

class MiddlewareFailuresTest:
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

    def test_rate_limiting(self):
        """Test rate limiting middleware by making rapid requests"""
        print("\n⏱️ TESTING RATE LIMITING MIDDLEWARE")
        print("=" * 50)
        responses = []
        for i in range(15):
            try:
                response = self.session.get(f"{self.base_url}/api/health")
                responses.append(response.status_code)
                time.sleep(0.05)
            except Exception as e:
                responses.append(f"Error: {e}")
        rate_limited_count = sum(1 for status in responses if status == 429)
        if rate_limited_count > 0:
            self.log_test("Rate Limiting Middleware", True, f"Rate limited {rate_limited_count} requests")
        else:
            self.log_test("Rate Limiting Middleware", False, "No rate limiting detected")

    def test_authentication_middleware(self):
        """Test authentication middleware by accessing protected endpoints without token"""
        print("\n🔒 TESTING AUTHENTICATION MIDDLEWARE")
        print("=" * 50)
        protected_endpoints = [
            "/api/courses",
            "/api/questions",
            "/api/polls",
            "/api/announcements",
            "/api/admin/users"
        ]
        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code in [401, 403]:
                    self.log_test(f"Authentication Middleware {endpoint}", True, f"Correctly returned {response.status_code}")
                else:
                    self.log_test(f"Authentication Middleware {endpoint}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Authentication Middleware {endpoint}", False, str(e))

    def test_middleware_error_handling(self):
        """Test middleware error handling for malformed requests"""
        print("\n⚠️ TESTING MIDDLEWARE ERROR HANDLING")
        print("=" * 50)
        try:
            response = self.session.post(f"{self.base_url}/api/courses", data="notjson", headers={"Content-Type": "application/json"})
            if response.status_code in [400, 422]:
                self.log_test("Middleware Error Handling", True, f"Correctly handled malformed request: {response.status_code}")
            else:
                self.log_test("Middleware Error Handling", False, f"Expected 400/422, got {response.status_code}")
        except Exception as e:
            self.log_test("Middleware Error Handling", False, str(e))

    def run_middleware_tests(self):
        print("🔧 RUNNING MIDDLEWARE FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Middleware failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        self.test_rate_limiting()
        self.test_authentication_middleware()
        self.test_middleware_error_handling()
        print("\n" + "=" * 60)
        print("📊 MIDDLEWARE FAILURE TESTS SUMMARY")
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
    test_suite = MiddlewareFailuresTest()
    results = test_suite.run_middleware_tests()
    exit(0 if results['failed'] == 0 else 1) 