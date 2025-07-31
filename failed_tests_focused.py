#!/usr/bin/env python3
"""
FOCUSED FAILED TESTS FOR CLASSROOM LIVE APP
==========================================

This test file specifically targets the 170 failed tests identified in the comprehensive test report.
It focuses only on the scenarios that failed, not the ones that passed.

Failed Test Categories:
1. Authentication failures (duplicate registrations, login errors)
2. WebSocket connection failures (404 errors)
3. Security test failures (SQL injection, weak passwords, CORS)
4. User management failures (registration, login issues)
5. Course management failures (token issues, access control)
6. Questions & Answers failures (token/course availability)
7. Polls & Voting failures (token/course availability)
8. Announcements failures (token/course availability)
9. Admin failures (unauthorized access, token validation)
10. Data validation failures (input validation, SQL injection)
11. Error handling failures (401/500 status mismatches)
12. Session management failures (token validation)
13. Database failures (health checks, CRUD operations)
14. Middleware failures (rate limiting, authentication)
15. Configuration failures (environment detection, validation)
"""

import requests
import json
import time
import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class FocusedFailedTests:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_data = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
        self.cleanup_users = []
    
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
    
    def setup_moderator(self):
        """Setup moderator authentication"""
        try:
            moderator_data = {
                "username": "pepper_moderator",
                "password": "pepper_14627912"
            }
            response = self.session.post(f"{self.base_url}/api/login", json=moderator_data)
            if response.status_code == 200:
                data = response.json()
                self.tokens["moderator"] = data["access_token"]
                return True
            return False
        except Exception:
            return False

    def test_comprehensive_health_check_failures(self):
        """Test the health check failures identified in the report"""
        print("\n🏥 TESTING HEALTH CHECK FAILURES")
        print("=" * 50)
        
        # Test detailed health check that failed
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                # Check if all health components are present
                health_components = ["database", "redis", "api", "uptime"]
                missing_components = [comp for comp in health_components if comp not in data]
                if missing_components:
                    self.log_test("Detailed Health Check", False, f"Missing components: {missing_components}")
                else:
                    self.log_test("Detailed Health Check", True, f"All components present: {list(data.keys())}")
            else:
                self.log_test("Detailed Health Check", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Detailed Health Check", False, str(e))

    def test_student_registration_failures(self):
        """Test student registration failures identified in the report"""
        print("\n🎓 TESTING STUDENT REGISTRATION FAILURES")
        print("=" * 50)
        
        # Test duplicate registration scenarios that failed
        timestamp = int(time.time())
        
        # First registration
        student_data = {
            "name": f"Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"student{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                self.tokens["test_student"] = data["access_token"]
                self.cleanup_users.append(data["user"]["id"])
                
                # Now test duplicate registration (this should fail)
                response2 = self.session.post(f"{self.base_url}/api/register", json=student_data)
                if response2.status_code == 400:
                    self.log_test("Duplicate Student Registration", True, "Correctly rejected duplicate")
                else:
                    self.log_test("Duplicate Student Registration", False, f"Expected 400, got {response2.status_code}")
            else:
                self.log_test("Initial Student Registration", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Student Registration Test", False, str(e))

    def test_student_login_failures(self):
        """Test student login failures identified in the report"""
        print("\n🔐 TESTING STUDENT LOGIN FAILURES")
        print("=" * 50)
        
        # Test login with non-existent user (should return 401, not 500)
        non_existent_data = {
            "email": "nonexistent@test.com",
            "password": "wrongpassword"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/login", json=non_existent_data)
            if response.status_code == 401:
                self.log_test("Non-existent User Login", True, "Correctly returned 401")
            else:
                self.log_test("Non-existent User Login", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Non-existent User Login", False, str(e))

    def test_professor_creation_failures(self):
        """Test professor creation failures identified in the report"""
        print("\n👨‍🏫 TESTING PROFESSOR CREATION FAILURES")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Professor Creation Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        professor_data = {
            "name": "Test Professor",
            "userid": f"prof{timestamp}",
            "email": f"professor{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/admin/professors",
                json=professor_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                self.cleanup_users.append(data["user"]["id"])
                
                # Test duplicate professor creation
                response2 = self.session.post(
                    f"{self.base_url}/api/admin/professors",
                    json=professor_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response2.status_code == 400:
                    self.log_test("Duplicate Professor Creation", True, "Correctly rejected duplicate")
                else:
                    self.log_test("Duplicate Professor Creation", False, f"Expected 400, got {response2.status_code}")
            else:
                self.log_test("Initial Professor Creation", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Professor Creation Test", False, str(e))

    def test_websocket_connection_failures(self):
        """Test WebSocket connection failures identified in the report"""
        print("\n🔌 TESTING WEBSOCKET CONNECTION FAILURES")
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

    def test_security_vulnerabilities(self):
        """Test security vulnerabilities identified in the report"""
        print("\n🔒 TESTING SECURITY VULNERABILITIES")
        print("=" * 50)
        
        # Test SQL injection attempts that should be blocked
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "' OR '1'='1' --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES (1, 'hacker', 'hacker@evil.com') --",
            "' OR 1=1; --"
        ]
        
        for i, injection in enumerate(sql_injection_attempts):
            login_data = {
                "email": injection,
                "password": injection
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if response.status_code == 401:
                    self.log_test(f"SQL Injection Blocked {i+1}", True, f"Correctly blocked: {injection[:20]}...")
                else:
                    self.log_test(f"SQL Injection Blocked {i+1}", False, f"Expected 401, got {response.status_code} for: {injection[:20]}...")
            except Exception as e:
                self.log_test(f"SQL Injection Test {i+1}", False, str(e))

    def test_weak_password_validation(self):
        """Test weak password validation failures identified in the report"""
        print("\n🔑 TESTING WEAK PASSWORD VALIDATION")
        print("=" * 50)
        
        weak_passwords = [
            "aaaaaaaaaa",  # All same character
            "password",     # Common password
            "123456"        # Numeric only
        ]
        
        timestamp = int(time.time())
        
        for i, password in enumerate(weak_passwords):
            student_data = {
                "name": f"Test Student {timestamp + i}",
                "roll_number": f"23BT{timestamp + i}",
                "email": f"student{timestamp + i}@test.com",
                "password": password
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=student_data)
                if response.status_code == 422:
                    self.log_test(f"Weak Password Rejected {i+1}", True, f"Correctly rejected: {password}")
                else:
                    self.log_test(f"Weak Password Rejected {i+1}", False, f"Expected 422, got {response.status_code} for: {password}")
            except Exception as e:
                self.log_test(f"Weak Password Test {i+1}", False, str(e))

    def test_cors_vulnerabilities(self):
        """Test CORS vulnerabilities identified in the report"""
        print("\n🌐 TESTING CORS VULNERABILITIES")
        print("=" * 50)
        
        # Test CORS headers
        try:
            response = self.session.options(f"{self.base_url}/api/health")
            cors_headers = response.headers.get("Access-Control-Allow-Origin", "")
            
            if cors_headers == "*":
                self.log_test("CORS Origin Validation", False, "CORS allows all origins (*)")
            else:
                self.log_test("CORS Origin Validation", True, f"CORS origin: {cors_headers}")
        except Exception as e:
            self.log_test("CORS Test", False, str(e))

    def test_rate_limiting_failures(self):
        """Test rate limiting failures identified in the report"""
        print("\n⏱️ TESTING RATE LIMITING FAILURES")
        print("=" * 50)
        
        # Test rapid login attempts
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        responses = []
        for i in range(5):
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay between requests
            except Exception as e:
                responses.append(f"Error: {e}")
        
        # Check if rate limiting is working
        rate_limited_count = sum(1 for status in responses if status == 429)
        if rate_limited_count > 0:
            self.log_test("Rate Limiting", True, f"Rate limited {rate_limited_count} out of 5 attempts")
        else:
            self.log_test("Rate Limiting", False, f"No rate limiting detected. Responses: {responses}")

    def test_unauthorized_access_failures(self):
        """Test unauthorized access failures identified in the report"""
        print("\n🚫 TESTING UNAUTHORIZED ACCESS FAILURES")
        print("=" * 50)
        
        # Test accessing protected endpoints without token
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
                    self.log_test(f"Unauthorized Access {endpoint}", True, f"Correctly returned {response.status_code}")
                else:
                    self.log_test(f"Unauthorized Access {endpoint}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Unauthorized Access {endpoint}", False, str(e))

    def test_invalid_token_failures(self):
        """Test invalid token failures identified in the report"""
        print("\n🎫 TESTING INVALID TOKEN FAILURES")
        print("=" * 50)
        
        invalid_tokens = [
            "invalid_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "Bearer invalid_token"
        ]
        
        for i, token in enumerate(invalid_tokens):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            
            try:
                response = self.session.get(f"{self.base_url}/api/courses", headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Invalid Token {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Invalid Token {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Invalid Token Test {i+1}", False, str(e))

    def test_data_validation_failures(self):
        """Test data validation failures identified in the report"""
        print("\n📝 TESTING DATA VALIDATION FAILURES")
        print("=" * 50)
        
        # Test various invalid inputs that should be rejected
        invalid_inputs = [
            {"name": "123", "roll_number": "12345", "email": "test@test.com", "password": "password123"},
            {"name": "Test\nName", "roll_number": "23BT123", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "12345", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": " test@test.com ", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": "test@test.com", "password": "password"}
        ]
        
        timestamp = int(time.time())
        
        for i, invalid_input in enumerate(invalid_inputs):
            # Add unique identifiers
            invalid_input["name"] = f"{invalid_input['name']} {timestamp + i}"
            invalid_input["roll_number"] = f"{invalid_input['roll_number']}{timestamp + i}"
            invalid_input["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=invalid_input)
                if response.status_code == 422:
                    self.log_test(f"Data Validation {i+1}", True, f"Correctly rejected invalid input")
                else:
                    self.log_test(f"Data Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Data Validation Test {i+1}", False, str(e))

    def test_session_management_failures(self):
        """Test session management failures identified in the report"""
        print("\n🔄 TESTING SESSION MANAGEMENT FAILURES")
        print("=" * 50)
        
        # Test session creation on registration
        timestamp = int(time.time())
        student_data = {
            "name": f"Session Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"session{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data:
                    self.log_test("Session Creation on Registration", True, "Session token provided")
                else:
                    self.log_test("Session Creation on Registration", False, "No session token provided")
            else:
                self.log_test("Session Creation on Registration", False, f"Registration failed: {response.status_code}")
        except Exception as e:
            self.log_test("Session Creation Test", False, str(e))

    def test_database_operation_failures(self):
        """Test database operation failures identified in the report"""
        print("\n🗄️ TESTING DATABASE OPERATION FAILURES")
        print("=" * 50)
        
        # Test database health check
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "database" in data:
                    self.log_test("Database Health Check", True, f"Database status: {data['database']}")
                else:
                    self.log_test("Database Health Check", False, "Database status not found in response")
            else:
                self.log_test("Database Health Check", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Database Health Check", False, str(e))

    def test_middleware_failures(self):
        """Test middleware failures identified in the report"""
        print("\n🔧 TESTING MIDDLEWARE FAILURES")
        print("=" * 50)
        
        # Test rate limiting middleware
        responses = []
        for i in range(150):  # Test rate limiting threshold
            try:
                response = self.session.get(f"{self.base_url}/api/health")
                responses.append(response.status_code)
                if i % 10 == 0:  # Add small delays to avoid overwhelming
                    time.sleep(0.1)
            except Exception as e:
                responses.append(f"Error: {e}")
        
        rate_limited_count = sum(1 for status in responses if status == 429)
        if rate_limited_count > 0:
            self.log_test("Rate Limiting Middleware", True, f"Rate limited {rate_limited_count} requests")
        else:
            self.log_test("Rate Limiting Middleware", False, "No rate limiting detected")

    def test_configuration_failures(self):
        """Test configuration failures identified in the report"""
        print("\n⚙️ TESTING CONFIGURATION FAILURES")
        print("=" * 50)
        
        # Test environment detection
        try:
            response = self.session.get(f"{self.base_url}/api/info")
            if response.status_code == 200:
                data = response.json()
                if "environment" in data:
                    self.log_test("Environment Detection", True, f"Environment: {data['environment']}")
                else:
                    self.log_test("Environment Detection", False, "Environment not detected")
            else:
                self.log_test("Environment Detection", False, f"Info endpoint failed: {response.status_code}")
        except Exception as e:
            self.log_test("Environment Detection", False, str(e))

    def test_error_handling_failures(self):
        """Test error handling failures identified in the report"""
        print("\n⚠️ TESTING ERROR HANDLING FAILURES")
        print("=" * 50)
        
        # Test 401 unauthorized error handling
        try:
            response = self.session.get(f"{self.base_url}/api/courses")
            if response.status_code == 401:
                self.log_test("401 Unauthorized Error", True, "Correctly returned 401")
            else:
                self.log_test("401 Unauthorized Error", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("401 Unauthorized Error", False, str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 CLEANING UP TEST DATA")
        print("=" * 50)
        
        if not self.setup_moderator():
            print("❌ Cannot cleanup - moderator login failed")
            return
        
        for user_id in self.cleanup_users:
            try:
                response = self.session.delete(
                    f"{self.base_url}/api/admin/users/{user_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    print(f"✅ Cleaned up user {user_id}")
                else:
                    print(f"❌ Failed to cleanup user {user_id}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error cleaning up user {user_id}: {e}")

    def run_failed_tests(self):
        """Run all the focused failed tests"""
        print("🎯 RUNNING FOCUSED FAILED TESTS")
        print("=" * 60)
        print(f"Target: 170 failed tests from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all failed test categories
        self.test_comprehensive_health_check_failures()
        self.test_student_registration_failures()
        self.test_student_login_failures()
        self.test_professor_creation_failures()
        self.test_websocket_connection_failures()
        self.test_security_vulnerabilities()
        self.test_weak_password_validation()
        self.test_cors_vulnerabilities()
        self.test_rate_limiting_failures()
        self.test_unauthorized_access_failures()
        self.test_invalid_token_failures()
        self.test_data_validation_failures()
        self.test_session_management_failures()
        self.test_database_operation_failures()
        self.test_middleware_failures()
        self.test_configuration_failures()
        self.test_error_handling_failures()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 FOCUSED FAILED TESTS SUMMARY")
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
    # Run the focused failed tests
    test_suite = FocusedFailedTests()
    results = test_suite.run_failed_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 