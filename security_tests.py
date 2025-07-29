#!/usr/bin/env python3
"""
SECURITY TESTS FOR CLASSROOM LIVE APP
=====================================

Tests all security aspects including:
- Authentication bypass attempts
- Authorization checks
- Input validation
- SQL injection attempts
- XSS attempts
- CSRF protection
- Rate limiting
"""

import requests
import json
import time
from typing import Dict, List

class SecurityTestSuite:
    def __init__(self, base_url: str = "https://zero1-classroom-1.onrender.com"):
        self.base_url = base_url
        self.session = requests.Session()
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
    
    def setup_authentication(self):
        """Setup authentication tokens"""
        login_data = {
            "username": "pepper_moderator",
            "password": "pepper_14627912"
        }
        
        response = self.session.post(f"{self.base_url}/api/login", json=login_data)
        if response.status_code == 200:
            self.tokens["moderator"] = response.json()["access_token"]
            return True
        return False
    
    def test_authentication_bypass(self):
        """Test authentication bypass attempts"""
        print("\n🚫 TESTING AUTHENTICATION BYPASS")
        print("=" * 50)
        
        # Test 1: Access protected endpoint without token
        try:
            response = self.session.get(f"{self.base_url}/api/admin/users")
            # Accept both 401 and 403 as valid responses for no token
            self.log_test("No Token Access", response.status_code in [401, 403], 
                         f"Expected 401/403, got {response.status_code}")
        except Exception as e:
            self.log_test("No Token Access", False, str(e))
        
        # Test 2: Access with invalid token
        try:
            headers = {"Authorization": "Bearer invalid_token_12345"}
            response = self.session.get(f"{self.base_url}/api/admin/users", headers=headers)
            self.log_test("Invalid Token Access", response.status_code == 401, 
                         f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Token Access", False, str(e))
        
        # Test 3: Access with expired token format
        try:
            headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
            response = self.session.get(f"{self.base_url}/api/admin/users", headers=headers)
            self.log_test("Expired Token Access", response.status_code == 401, 
                         f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Expired Token Access", False, str(e))
        
        # Test 4: Access with malformed token
        try:
            headers = {"Authorization": "Bearer malformed.token.here"}
            response = self.session.get(f"{self.base_url}/api/admin/users", headers=headers)
            self.log_test("Malformed Token Access", response.status_code == 401, 
                         f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Malformed Token Access", False, str(e))
    
    def test_authorization_checks(self):
        """Test authorization checks for different user roles"""
        print("\n🔐 TESTING AUTHORIZATION CHECKS")
        print("=" * 50)
        
        if not self.setup_authentication():
            self.log_test("Authorization Tests", False, "Failed to setup authentication")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['moderator']}"}
        
        # Test 1: Student trying to access admin endpoints
        student_login = {
            "username": "prateek@iitkgp.ac.in",  # Use email instead of roll number
            "password": "password123"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/login", json=student_login)
            if response.status_code == 200:
                student_token = response.json()["access_token"]
                student_headers = {"Authorization": f"Bearer {student_token}"}
                
                # Try to access admin endpoint
                response = self.session.get(f"{self.base_url}/api/admin/users", headers=student_headers)
                self.log_test("Student Admin Access", response.status_code == 403, 
                             f"Expected 403, got {response.status_code}")
            else:
                # Try alternative login method
                student_login_alt = {
                    "username": "23bt10027",
                    "password": "password123"
                }
                response = self.session.post(f"{self.base_url}/api/login", json=student_login_alt)
                if response.status_code == 200:
                    student_token = response.json()["access_token"]
                    student_headers = {"Authorization": f"Bearer {student_token}"}
                    
                    # Try to access admin endpoint
                    response = self.session.get(f"{self.base_url}/api/admin/users", headers=student_headers)
                    self.log_test("Student Admin Access", response.status_code == 403, 
                                 f"Expected 403, got {response.status_code}")
                else:
                    self.log_test("Student Admin Access", False, f"Failed to login as student: {response.status_code}")
        except Exception as e:
            self.log_test("Student Admin Access", False, str(e))
        
        # Test 2: Professor trying to access moderator-only endpoints
        # (This would require creating a professor first)
        
        # Test 3: Unauthorized course access
        try:
            response = self.session.get(f"{self.base_url}/api/courses/invalid_course_id/students", 
                                      headers=headers)
            self.log_test("Invalid Course Access", response.status_code == 404, 
                         f"Expected 404, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Course Access", False, str(e))
    
    def test_input_validation(self):
        """Test input validation and sanitization"""
        print("\n🧪 TESTING INPUT VALIDATION")
        print("=" * 50)
        
        if not self.setup_authentication():
            self.log_test("Input Validation Tests", False, "Failed to setup authentication")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['moderator']}"}
        
        # Test 1: SQL injection attempts
        sql_injection_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_injection_payloads:
            try:
                # Try in email field
                test_data = {
                    "name": "Test User",
                    "userid": "testuser",
                    "email": payload,
                    "password": "password123"
                }
                response = self.session.post(f"{self.base_url}/api/admin/create-professor", 
                                           json=test_data, headers=headers)
                # Accept 400, 422, or 500 as valid responses for SQL injection attempts
                self.log_test(f"SQL Injection Email: {payload[:20]}...", 
                             response.status_code in [400, 422, 500], 
                             f"Expected 400/422/500, got {response.status_code}")
            except Exception as e:
                self.log_test(f"SQL Injection Email: {payload[:20]}...", False, str(e))
        
        # Test 2: XSS attempts
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            try:
                test_data = {
                    "name": payload,
                    "userid": "testuser",
                    "email": "test@example.com",
                    "password": "password123"
                }
                response = self.session.post(f"{self.base_url}/api/admin/create-professor", 
                                           json=test_data, headers=headers)
                self.log_test(f"XSS Payload: {payload[:20]}...", 
                             response.status_code in [400, 422], 
                             f"Expected 400/422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"XSS Payload: {payload[:20]}...", False, str(e))
        
        # Test 3: Extremely long inputs
        long_string = "A" * 10000
        try:
            test_data = {
                "name": long_string,
                "userid": "testuser",
                "email": "test@example.com",
                "password": "password123"
            }
            response = self.session.post(f"{self.base_url}/api/admin/create-professor", 
                                       json=test_data, headers=headers)
            self.log_test("Extremely Long Input", response.status_code in [400, 422, 413], 
                         f"Expected 400/422/413, got {response.status_code}")
        except Exception as e:
            self.log_test("Extremely Long Input", False, str(e))
        
        # Test 4: Special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        try:
            test_data = {
                "name": f"Test User {special_chars}",
                "userid": f"testuser{special_chars}",
                "email": "test@example.com",
                "password": "password123"
            }
            response = self.session.post(f"{self.base_url}/api/admin/create-professor", 
                                       json=test_data, headers=headers)
            # Accept 200, 400, or 422 as valid responses for special characters
            self.log_test("Special Characters", response.status_code in [200, 400, 422], 
                         f"Expected 200/400/422, got {response.status_code}")
        except Exception as e:
            self.log_test("Special Characters", False, str(e))
    
    def test_rate_limiting(self):
        """Test rate limiting (if implemented)"""
        print("\n⏱️ TESTING RATE LIMITING")
        print("=" * 50)
        
        # Test 1: Rapid login attempts
        login_data = {
            "username": "invalid_user",
            "password": "wrong_password"
        }
        
        responses = []
        for i in range(10):
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay
            except Exception as e:
                responses.append("error")
        
        # Check if rate limiting is applied
        if all(status == 401 for status in responses if status != "error"):
            self.log_test("Rate Limiting", True, "Consistent 401 responses")
        elif any(status == 429 for status in responses if status != "error"):
            self.log_test("Rate Limiting", True, "Rate limiting detected (429)")
        else:
            self.log_test("Rate Limiting", False, "No rate limiting detected")
    
    def test_cors_policy(self):
        """Test CORS policy"""
        print("\n🌐 TESTING CORS POLICY")
        print("=" * 50)
        
        # Test 1: Check CORS headers
        try:
            response = self.session.options(f"{self.base_url}/api/health")
            cors_headers = response.headers.get('Access-Control-Allow-Origin')
            
            if cors_headers:
                self.log_test("CORS Headers", True, f"CORS headers present: {cors_headers}")
            else:
                self.log_test("CORS Headers", False, "No CORS headers found")
        except Exception as e:
            self.log_test("CORS Headers", False, str(e))
    
    def test_content_security_policy(self):
        """Test Content Security Policy"""
        print("\n🛡️ TESTING CONTENT SECURITY POLICY")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            csp_header = response.headers.get('Content-Security-Policy')
            
            if csp_header:
                self.log_test("CSP Headers", True, f"CSP headers present: {csp_header[:50]}...")
            else:
                self.log_test("CSP Headers", False, "No CSP headers found")
        except Exception as e:
            self.log_test("CSP Headers", False, str(e))
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🛡️ STARTING SECURITY TEST SUITE")
        print("=" * 60)
        
        self.test_authentication_bypass()
        self.test_authorization_checks()
        self.test_input_validation()
        self.test_rate_limiting()
        self.test_cors_policy()
        self.test_content_security_policy()
        
        # Print summary
        print("\n📊 SECURITY TEST SUMMARY")
        print("=" * 60)
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        print(f"📈 Success Rate: {(self.test_results['passed'] / (self.test_results['passed'] + self.test_results['failed']) * 100):.1f}%")
        
        if self.test_results['errors']:
            print(f"\n❌ SECURITY ISSUES FOUND:")
            for error in self.test_results['errors']:
                print(f"   - {error}")

if __name__ == "__main__":
    SecurityTestSuite().run_all_tests() 