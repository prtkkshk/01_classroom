#!/usr/bin/env python3
"""
ERROR HANDLING FAILURES TEST
============================

This test file specifically targets error handling failures identified in the comprehensive test report.
Category: Error handling failures (401/500 status mismatches)

Failed Test Scenarios:
- 401 unauthorized error handling
- 500 internal server error handling
- Error response format validation
- Error message consistency
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class ErrorHandlingFailuresTest:
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

    def test_401_unauthorized_error_handling(self):
        """Test 401 unauthorized error handling"""
        print("\n⚠️ TESTING 401 UNAUTHORIZED ERROR HANDLING")
        print("=" * 50)
        
        # Test accessing protected endpoints without authentication
        protected_endpoints = [
            "/api/courses",
            "/api/questions",
            "/api/polls",
            "/api/announcements",
            "/api/admin/users",
            "/api/profile"
        ]
        
        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code == 401:
                    # Check if response has proper error format
                    try:
                        error_data = response.json()
                        if "detail" in error_data or "message" in error_data:
                            self.log_test(f"401 Error Handling {endpoint}", True, f"Correctly returned 401 with error details")
                        else:
                            self.log_test(f"401 Error Handling {endpoint}", False, "401 response missing error details")
                    except json.JSONDecodeError:
                        self.log_test(f"401 Error Handling {endpoint}", False, "401 response not valid JSON")
                else:
                    self.log_test(f"401 Error Handling {endpoint}", False, f"Expected 401, got {response.status_code}")
            except Exception as e:
                self.log_test(f"401 Error Handling {endpoint}", False, str(e))

    def test_403_forbidden_error_handling(self):
        """Test 403 forbidden error handling"""
        print("\n🚫 TESTING 403 FORBIDDEN ERROR HANDLING")
        print("=" * 50)
        
        # Test accessing admin endpoints with student token
        timestamp = int(time.time())
        student_data = {
            "name": f"Error Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"error_test{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Create a student account
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                student_token = data["access_token"]
                
                # Try to access admin endpoints with student token
                admin_endpoints = [
                    "/api/admin/users",
                    "/api/admin/courses",
                    "/api/admin/professors"
                ]
                
                for endpoint in admin_endpoints:
                    try:
                        admin_response = self.session.get(
                            f"{self.base_url}{endpoint}",
                            headers={"Authorization": f"Bearer {student_token}"}
                        )
                        if admin_response.status_code == 403:
                            # Check if response has proper error format
                            try:
                                error_data = admin_response.json()
                                if "detail" in error_data or "message" in error_data:
                                    self.log_test(f"403 Error Handling {endpoint}", True, f"Correctly returned 403 with error details")
                                else:
                                    self.log_test(f"403 Error Handling {endpoint}", False, "403 response missing error details")
                            except json.JSONDecodeError:
                                self.log_test(f"403 Error Handling {endpoint}", False, "403 response not valid JSON")
                        else:
                            self.log_test(f"403 Error Handling {endpoint}", False, f"Expected 403, got {admin_response.status_code}")
                    except Exception as e:
                        self.log_test(f"403 Error Handling {endpoint}", False, str(e))
            else:
                self.log_test("Student Creation for 403 Test", False, f"Failed to create student: {response.status_code}")
        except Exception as e:
            self.log_test("403 Error Handling Test", False, str(e))

    def test_404_not_found_error_handling(self):
        """Test 404 not found error handling"""
        print("\n🔍 TESTING 404 NOT FOUND ERROR HANDLING")
        print("=" * 50)
        
        # Test accessing non-existent endpoints
        non_existent_endpoints = [
            "/api/nonexistent",
            "/api/users/999999",
            "/api/courses/999999",
            "/api/questions/999999",
            "/api/polls/999999"
        ]
        
        for endpoint in non_existent_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code == 404:
                    # Check if response has proper error format
                    try:
                        error_data = response.json()
                        if "detail" in error_data or "message" in error_data:
                            self.log_test(f"404 Error Handling {endpoint}", True, f"Correctly returned 404 with error details")
                        else:
                            self.log_test(f"404 Error Handling {endpoint}", False, "404 response missing error details")
                    except json.JSONDecodeError:
                        self.log_test(f"404 Error Handling {endpoint}", False, "404 response not valid JSON")
                else:
                    self.log_test(f"404 Error Handling {endpoint}", False, f"Expected 404, got {response.status_code}")
            except Exception as e:
                self.log_test(f"404 Error Handling {endpoint}", False, str(e))

    def test_422_validation_error_handling(self):
        """Test 422 validation error handling"""
        print("\n📋 TESTING 422 VALIDATION ERROR HANDLING")
        print("=" * 50)
        
        # Test invalid data that should return 422
        invalid_data_tests = [
            {
                "name": "",
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "invalid-email",
                "password": "SecurePassword123!"
            }
        ]
        
        timestamp = int(time.time())
        
        for i, invalid_data in enumerate(invalid_data_tests):
            # Make each test unique
            invalid_data["roll_number"] = f"23BT{timestamp + i}"
            invalid_data["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=invalid_data)
                if response.status_code == 422:
                    # Check if response has proper validation error format
                    try:
                        error_data = response.json()
                        if "detail" in error_data:
                            self.log_test(f"422 Error Handling {i+1}", True, f"Correctly returned 422 with validation details")
                        else:
                            self.log_test(f"422 Error Handling {i+1}", False, "422 response missing validation details")
                    except json.JSONDecodeError:
                        self.log_test(f"422 Error Handling {i+1}", False, "422 response not valid JSON")
                else:
                    self.log_test(f"422 Error Handling {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"422 Error Handling Test {i+1}", False, str(e))

    def test_500_internal_server_error_handling(self):
        """Test 500 internal server error handling"""
        print("\n💥 TESTING 500 INTERNAL SERVER ERROR HANDLING")
        print("=" * 50)
        
        # Test scenarios that might cause 500 errors
        error_scenarios = [
            # Test with malformed JSON
            {"data": "invalid json"},
            # Test with extremely large payload
            {"data": "A" * 1000000},
            # Test with special characters that might cause issues
            {"data": "'; DROP TABLE users; --"}
        ]
        
        for i, scenario in enumerate(error_scenarios):
            try:
                # Try to send malformed data to various endpoints
                response = self.session.post(
                    f"{self.base_url}/api/register",
                    data=json.dumps(scenario),
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 500:
                    # Check if response has proper error format
                    try:
                        error_data = response.json()
                        if "detail" in error_data or "message" in error_data:
                            self.log_test(f"500 Error Handling {i+1}", True, f"Correctly returned 500 with error details")
                        else:
                            self.log_test(f"500 Error Handling {i+1}", False, "500 response missing error details")
                    except json.JSONDecodeError:
                        self.log_test(f"500 Error Handling {i+1}", False, "500 response not valid JSON")
                elif response.status_code in [400, 422]:
                    self.log_test(f"500 Error Handling {i+1}", True, f"Correctly handled invalid data with {response.status_code}")
                else:
                    self.log_test(f"500 Error Handling {i+1}", False, f"Unexpected status code: {response.status_code}")
            except Exception as e:
                self.log_test(f"500 Error Handling Test {i+1}", False, str(e))

    def test_error_response_format_consistency(self):
        """Test error response format consistency"""
        print("\n📊 TESTING ERROR RESPONSE FORMAT CONSISTENCY")
        print("=" * 50)
        
        # Test different error scenarios and check format consistency
        error_scenarios = [
            ("/api/nonexistent", "GET", None, 404),
            ("/api/courses", "GET", None, 401),
            ("/api/register", "POST", {"invalid": "data"}, 422)
        ]
        
        error_formats = []
        
        for endpoint, method, data, expected_status in error_scenarios:
            try:
                if method == "GET":
                    response = self.session.get(f"{self.base_url}{endpoint}")
                elif method == "POST":
                    response = self.session.post(f"{self.base_url}{endpoint}", json=data)
                
                if response.status_code == expected_status:
                    try:
                        error_data = response.json()
                        error_formats.append(set(error_data.keys()))
                        self.log_test(f"Error Format {endpoint}", True, f"Got expected {expected_status} with format: {list(error_data.keys())}")
                    except json.JSONDecodeError:
                        self.log_test(f"Error Format {endpoint}", False, "Response not valid JSON")
                else:
                    self.log_test(f"Error Format {endpoint}", False, f"Expected {expected_status}, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Error Format Test {endpoint}", False, str(e))
        
        # Check if all error formats are consistent
        if len(error_formats) > 1:
            common_keys = set.intersection(*error_formats)
            if common_keys:
                self.log_test("Error Format Consistency", True, f"Common error format keys: {list(common_keys)}")
            else:
                self.log_test("Error Format Consistency", False, "No common error format keys found")

    def test_error_message_clarity(self):
        """Test error message clarity and usefulness"""
        print("\n💬 TESTING ERROR MESSAGE CLARITY")
        print("=" * 50)
        
        # Test various error scenarios and check message clarity
        clarity_tests = [
            {
                "endpoint": "/api/nonexistent",
                "method": "GET",
                "expected_status": 404,
                "expected_keywords": ["not found", "404", "endpoint"]
            },
            {
                "endpoint": "/api/courses",
                "method": "GET",
                "expected_status": 401,
                "expected_keywords": ["unauthorized", "401", "authentication"]
            }
        ]
        
        for i, test in enumerate(clarity_tests):
            try:
                if test["method"] == "GET":
                    response = self.session.get(f"{self.base_url}{test['endpoint']}")
                
                if response.status_code == test["expected_status"]:
                    try:
                        error_data = response.json()
                        error_message = str(error_data).lower()
                        
                        # Check if error message contains expected keywords
                        keyword_matches = [keyword for keyword in test["expected_keywords"] if keyword in error_message]
                        if keyword_matches:
                            self.log_test(f"Error Message Clarity {i+1}", True, f"Error message contains helpful keywords: {keyword_matches}")
                        else:
                            self.log_test(f"Error Message Clarity {i+1}", False, f"Error message missing expected keywords: {test['expected_keywords']}")
                    except json.JSONDecodeError:
                        self.log_test(f"Error Message Clarity {i+1}", False, "Response not valid JSON")
                else:
                    self.log_test(f"Error Message Clarity {i+1}", False, f"Expected {test['expected_status']}, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Error Message Clarity Test {i+1}", False, str(e))

    def run_error_handling_tests(self):
        """Run all error handling failure tests"""
        print("⚠️ RUNNING ERROR HANDLING FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Error handling failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all error handling tests
        self.test_401_unauthorized_error_handling()
        self.test_403_forbidden_error_handling()
        self.test_404_not_found_error_handling()
        self.test_422_validation_error_handling()
        self.test_500_internal_server_error_handling()
        self.test_error_response_format_consistency()
        self.test_error_message_clarity()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ERROR HANDLING FAILURE TESTS SUMMARY")
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
    # Run the error handling failure tests
    test_suite = ErrorHandlingFailuresTest()
    results = test_suite.run_error_handling_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 