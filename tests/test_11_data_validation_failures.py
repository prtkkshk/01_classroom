#!/usr/bin/env python3
"""
DATA VALIDATION FAILURES TEST
=============================

This test file specifically targets data validation failures identified in the comprehensive test report.
Category: Data validation failures (input validation, SQL injection)

Failed Test Scenarios:
- Input validation failures
- SQL injection attempts
- Data format validation
- Field length validation
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class DataValidationFailuresTest:
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

    def test_input_validation_failures(self):
        """Test various invalid inputs that should be rejected"""
        print("\n📝 TESTING INPUT VALIDATION FAILURES")
        print("=" * 50)
        
        # Test various invalid inputs that should be rejected
        invalid_inputs = [
            {"name": "123", "roll_number": "12345", "email": "test@test.com", "password": "password123"},
            {"name": "Test\nName", "roll_number": "23BT123", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "12345", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": " test@test.com ", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": "test@test.com", "password": "password"},
            {"name": "Test Name", "roll_number": "23BT123", "email": "invalid-email", "password": "password123"},
            {"name": "", "roll_number": "23BT123", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "", "email": "test@test.com", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": "", "password": "password123"},
            {"name": "Test Name", "roll_number": "23BT123", "email": "test@test.com", "password": ""}
        ]
        
        timestamp = int(time.time())
        
        for i, invalid_input in enumerate(invalid_inputs):
            # Add unique identifiers
            invalid_input["name"] = f"{invalid_input['name']} {timestamp + i}" if invalid_input['name'] else f"Test {timestamp + i}"
            invalid_input["roll_number"] = f"{invalid_input['roll_number']}{timestamp + i}" if invalid_input['roll_number'] else f"23BT{timestamp + i}"
            invalid_input["email"] = f"test{timestamp + i}@test.com" if invalid_input['email'] else f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=invalid_input)
                if response.status_code == 422:
                    self.log_test(f"Input Validation {i+1}", True, f"Correctly rejected invalid input")
                else:
                    self.log_test(f"Input Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Input Validation Test {i+1}", False, str(e))

    def test_sql_injection_validation(self):
        """Test SQL injection attempts that should be blocked"""
        print("\n🔒 TESTING SQL INJECTION VALIDATION")
        print("=" * 50)
        
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
        
        timestamp = int(time.time())
        
        for i, injection in enumerate(sql_injection_attempts):
            # Test in different fields
            test_data = {
                "name": f"Test User {timestamp + i}",
                "roll_number": f"23BT{timestamp + i}",
                "email": injection,
                "password": "SecurePassword123!"
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"SQL Injection Validation {i+1}", True, f"Correctly blocked: {injection[:20]}...")
                else:
                    self.log_test(f"SQL Injection Validation {i+1}", False, f"Expected 422, got {response.status_code} for: {injection[:20]}...")
            except Exception as e:
                self.log_test(f"SQL Injection Validation Test {i+1}", False, str(e))

    def test_data_format_validation(self):
        """Test data format validation"""
        print("\n📋 TESTING DATA FORMAT VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various format violations
        format_tests = [
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "not-an-email",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test..test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@test..com",
                "password": "SecurePassword123!"
            }
        ]
        
        for i, test_data in enumerate(format_tests):
            # Make each test unique
            test_data["roll_number"] = f"23BT{timestamp + i}"
            test_data["email"] = f"test{timestamp + i}@test.com" if "test@test.com" in test_data["email"] else test_data["email"]
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"Data Format Validation {i+1}", True, f"Correctly rejected invalid format")
                else:
                    self.log_test(f"Data Format Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Data Format Validation Test {i+1}", False, str(e))

    def test_field_length_validation(self):
        """Test field length validation"""
        print("\n📏 TESTING FIELD LENGTH VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various length violations
        length_tests = [
            {
                "name": "A" * 256,  # Name too long
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "A" * 51,  # Roll number too long
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "A" * 100 + "@test.com",  # Email too long
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "A" * 1001  # Password too long
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "123"  # Password too short
            }
        ]
        
        for i, test_data in enumerate(length_tests):
            # Make each test unique
            test_data["roll_number"] = f"23BT{timestamp + i}"
            test_data["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"Field Length Validation {i+1}", True, f"Correctly rejected invalid length")
                else:
                    self.log_test(f"Field Length Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Field Length Validation Test {i+1}", False, str(e))

    def test_special_character_validation(self):
        """Test special character validation"""
        print("\n🔤 TESTING SPECIAL CHARACTER VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various special characters
        special_char_tests = [
            {
                "name": "Test\nUser",  # Newline in name
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test\tUser",  # Tab in name
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test\rUser",  # Carriage return in name
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test<script>alert('xss')</script>User",  # XSS attempt
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            }
        ]
        
        for i, test_data in enumerate(special_char_tests):
            # Make each test unique
            test_data["roll_number"] = f"23BT{timestamp + i}"
            test_data["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"Special Character Validation {i+1}", True, f"Correctly rejected special characters")
                else:
                    self.log_test(f"Special Character Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Special Character Validation Test {i+1}", False, str(e))

    def test_whitespace_validation(self):
        """Test whitespace validation"""
        print("\n␣ TESTING WHITESPACE VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various whitespace issues
        whitespace_tests = [
            {
                "name": " Test User",  # Leading space
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User ",  # Trailing space
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test  User",  # Multiple spaces
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": " 23BT123",  # Leading space in roll number
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123 ",
                "email": " test@test.com ",  # Spaces around email
                "password": "SecurePassword123!"
            }
        ]
        
        for i, test_data in enumerate(whitespace_tests):
            # Make each test unique
            test_data["roll_number"] = f"23BT{timestamp + i}"
            test_data["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"Whitespace Validation {i+1}", True, f"Correctly rejected whitespace issues")
                else:
                    self.log_test(f"Whitespace Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Whitespace Validation Test {i+1}", False, str(e))

    def test_null_value_validation(self):
        """Test null value validation"""
        print("\n🚫 TESTING NULL VALUE VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various null value scenarios
        null_tests = [
            {
                "name": None,  # Null name
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": None,  # Null roll number
                "email": "test@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": None,  # Null email
                "password": "SecurePassword123!"
            },
            {
                "name": "Test User",
                "roll_number": "23BT123",
                "email": "test@test.com",
                "password": None  # Null password
            }
        ]
        
        for i, test_data in enumerate(null_tests):
            # Make each test unique
            if test_data["roll_number"]:
                test_data["roll_number"] = f"23BT{timestamp + i}"
            if test_data["email"]:
                test_data["email"] = f"test{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=test_data)
                if response.status_code == 422:
                    self.log_test(f"Null Value Validation {i+1}", True, f"Correctly rejected null value")
                else:
                    self.log_test(f"Null Value Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Null Value Validation Test {i+1}", False, str(e))

    def run_data_validation_tests(self):
        """Run all data validation failure tests"""
        print("📝 RUNNING DATA VALIDATION FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Data validation failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all data validation tests
        self.test_input_validation_failures()
        self.test_sql_injection_validation()
        self.test_data_format_validation()
        self.test_field_length_validation()
        self.test_special_character_validation()
        self.test_whitespace_validation()
        self.test_null_value_validation()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 DATA VALIDATION FAILURE TESTS SUMMARY")
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
    # Run the data validation failure tests
    test_suite = DataValidationFailuresTest()
    results = test_suite.run_data_validation_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 