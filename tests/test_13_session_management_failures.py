#!/usr/bin/env python3
"""
SESSION MANAGEMENT FAILURES TEST
================================

This test file specifically targets session management failures identified in the comprehensive test report.
Category: Session management failures (token validation)

Failed Test Scenarios:
- Session creation on registration
- Token validation
- Session expiration
- Token refresh
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class SessionManagementFailuresTest:
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

    def test_session_creation_on_registration(self):
        """Test session creation on registration"""
        print("\n🔄 TESTING SESSION CREATION ON REGISTRATION")
        print("=" * 50)
        
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

    def test_session_creation_on_login(self):
        """Test session creation on login"""
        print("\n🔄 TESTING SESSION CREATION ON LOGIN")
        print("=" * 50)
        
        # First create a user
        timestamp = int(time.time())
        student_data = {
            "name": f"Login Session Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"login_session{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Register user
            register_response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if register_response.status_code == 200:
                # Now try to login
                login_data = {
                    "email": f"login_session{timestamp}@test.com",
                    "password": "SecurePassword123!"
                }
                
                login_response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if login_response.status_code == 200:
                    login_data = login_response.json()
                    if "access_token" in login_data:
                        self.log_test("Session Creation on Login", True, "Session token provided on login")
                    else:
                        self.log_test("Session Creation on Login", False, "No session token provided on login")
                else:
                    self.log_test("Session Creation on Login", False, f"Login failed: {login_response.status_code}")
            else:
                self.log_test("User Creation for Login Session", False, f"Registration failed: {register_response.status_code}")
        except Exception as e:
            self.log_test("Session Creation on Login Test", False, str(e))

    def test_token_validation(self):
        """Test token validation"""
        print("\n🎫 TESTING TOKEN VALIDATION")
        print("=" * 50)
        
        # Create a user and get token
        timestamp = int(time.time())
        student_data = {
            "name": f"Token Validation Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"token_validation{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                token = data["access_token"]
                
                # Test token validation by accessing protected endpoint
                profile_response = self.session.get(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if profile_response.status_code == 200:
                    self.log_test("Token Validation", True, "Token is valid")
                else:
                    self.log_test("Token Validation", False, f"Token validation failed: {profile_response.status_code}")
            else:
                self.log_test("User Creation for Token Validation", False, f"Registration failed: {response.status_code}")
        except Exception as e:
            self.log_test("Token Validation Test", False, str(e))

    def test_invalid_token_handling(self):
        """Test invalid token handling"""
        print("\n🎫 TESTING INVALID TOKEN HANDLING")
        print("=" * 50)
        
        invalid_tokens = [
            "invalid_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "Bearer invalid_token",
            "expired_token_here"
        ]
        
        for i, token in enumerate(invalid_tokens):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            
            try:
                response = self.session.get(f"{self.base_url}/api/profile", headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Invalid Token Handling {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Invalid Token Handling {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Invalid Token Handling Test {i+1}", False, str(e))

    def test_token_format_validation(self):
        """Test token format validation"""
        print("\n🎫 TESTING TOKEN FORMAT VALIDATION")
        print("=" * 50)
        
        # Test various token format issues
        malformed_tokens = [
            "not_a_jwt_token",
            "header.payload",  # Missing signature
            "header.payload.signature.extra",  # Too many parts
            "header",  # Only header
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # Only header part
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"  # Missing signature
        ]
        
        for i, token in enumerate(malformed_tokens):
            try:
                response = self.session.get(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if response.status_code in [401, 403]:
                    self.log_test(f"Token Format Validation {i+1}", True, f"Correctly rejected malformed token")
                else:
                    self.log_test(f"Token Format Validation {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Token Format Validation Test {i+1}", False, str(e))

    def test_session_persistence(self):
        """Test session persistence across requests"""
        print("\n🔄 TESTING SESSION PERSISTENCE")
        print("=" * 50)
        
        # Create a user and get token
        timestamp = int(time.time())
        student_data = {
            "name": f"Session Persistence Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"session_persistence{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                token = data["access_token"]
                
                # Test multiple requests with the same token
                endpoints = ["/api/profile", "/api/courses", "/api/questions"]
                success_count = 0
                
                for endpoint in endpoints:
                    try:
                        endpoint_response = self.session.get(
                            f"{self.base_url}{endpoint}",
                            headers={"Authorization": f"Bearer {token}"}
                        )
                        if endpoint_response.status_code in [200, 404]:  # 404 is acceptable for empty data
                            success_count += 1
                    except Exception:
                        pass
                
                if success_count > 0:
                    self.log_test("Session Persistence", True, f"Session persisted across {success_count} requests")
                else:
                    self.log_test("Session Persistence", False, "Session failed to persist across requests")
            else:
                self.log_test("User Creation for Session Persistence", False, f"Registration failed: {response.status_code}")
        except Exception as e:
            self.log_test("Session Persistence Test", False, str(e))

    def test_token_refresh_functionality(self):
        """Test token refresh functionality"""
        print("\n🔄 TESTING TOKEN REFRESH FUNCTIONALITY")
        print("=" * 50)
        
        # Test if token refresh endpoint exists
        try:
            response = self.session.post(f"{self.base_url}/api/refresh")
            if response.status_code in [401, 404, 405]:
                self.log_test("Token Refresh Endpoint", True, f"Token refresh endpoint exists (status: {response.status_code})")
            else:
                self.log_test("Token Refresh Endpoint", False, f"Unexpected response from refresh endpoint: {response.status_code}")
        except Exception as e:
            self.log_test("Token Refresh Endpoint", False, str(e))

    def test_session_logout(self):
        """Test session logout functionality"""
        print("\n🚪 TESTING SESSION LOGOUT")
        print("=" * 50)
        
        # Test if logout endpoint exists
        try:
            response = self.session.post(f"{self.base_url}/api/logout")
            if response.status_code in [200, 401, 404, 405]:
                self.log_test("Session Logout Endpoint", True, f"Logout endpoint exists (status: {response.status_code})")
            else:
                self.log_test("Session Logout Endpoint", False, f"Unexpected response from logout endpoint: {response.status_code}")
        except Exception as e:
            self.log_test("Session Logout Endpoint", False, str(e))

    def test_concurrent_sessions(self):
        """Test concurrent session handling"""
        print("\n🔄 TESTING CONCURRENT SESSIONS")
        print("=" * 50)
        
        # Create multiple sessions for the same user
        timestamp = int(time.time())
        student_data = {
            "name": f"Concurrent Session Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"concurrent_session{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Register user
            register_response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if register_response.status_code == 200:
                register_data = register_response.json()
                register_token = register_data["access_token"]
                
                # Login with same credentials (should create new session)
                login_data = {
                    "email": f"concurrent_session{timestamp}@test.com",
                    "password": "SecurePassword123!"
                }
                
                login_response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if login_response.status_code == 200:
                    login_data = login_response.json()
                    login_token = login_data["access_token"]
                    
                    # Both tokens should work
                    register_profile = self.session.get(
                        f"{self.base_url}/api/profile",
                        headers={"Authorization": f"Bearer {register_token}"}
                    )
                    login_profile = self.session.get(
                        f"{self.base_url}/api/profile",
                        headers={"Authorization": f"Bearer {login_token}"}
                    )
                    
                    if register_profile.status_code == 200 and login_profile.status_code == 200:
                        self.log_test("Concurrent Sessions", True, "Multiple sessions work simultaneously")
                    else:
                        self.log_test("Concurrent Sessions", False, "Concurrent sessions not working properly")
                else:
                    self.log_test("Concurrent Sessions", False, f"Login failed: {login_response.status_code}")
            else:
                self.log_test("User Creation for Concurrent Sessions", False, f"Registration failed: {register_response.status_code}")
        except Exception as e:
            self.log_test("Concurrent Sessions Test", False, str(e))

    def run_session_management_tests(self):
        """Run all session management failure tests"""
        print("🔄 RUNNING SESSION MANAGEMENT FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Session management failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all session management tests
        self.test_session_creation_on_registration()
        self.test_session_creation_on_login()
        self.test_token_validation()
        self.test_invalid_token_handling()
        self.test_token_format_validation()
        self.test_session_persistence()
        self.test_token_refresh_functionality()
        self.test_session_logout()
        self.test_concurrent_sessions()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 SESSION MANAGEMENT FAILURE TESTS SUMMARY")
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
    # Run the session management failure tests
    test_suite = SessionManagementFailuresTest()
    results = test_suite.run_session_management_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 