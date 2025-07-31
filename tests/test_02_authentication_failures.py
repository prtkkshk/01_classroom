#!/usr/bin/env python3
"""
AUTHENTICATION FAILURES TEST
============================

This test file specifically targets authentication failures identified in the comprehensive test report.
Category: Authentication failures (duplicate registrations, login errors)

Failed Test Scenarios:
- Duplicate student registration handling
- Student login with non-existent user
- Professor creation failures
- Login error handling (401 vs 500)
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class AuthenticationFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
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

    def test_duplicate_student_registration(self):
        """Test duplicate student registration scenarios that failed"""
        print("\n🎓 TESTING DUPLICATE STUDENT REGISTRATION")
        print("=" * 50)
        
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

    def test_student_login_nonexistent_user(self):
        """Test student login with non-existent user (should return 401, not 500)"""
        print("\n🔐 TESTING STUDENT LOGIN NON-EXISTENT USER")
        print("=" * 50)
        
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

    def test_student_login_wrong_password(self):
        """Test student login with wrong password"""
        print("\n🔐 TESTING STUDENT LOGIN WRONG PASSWORD")
        print("=" * 50)
        
        # First create a student
        timestamp = int(time.time())
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
                self.cleanup_users.append(data["user"]["id"])
                
                # Now try to login with wrong password
                wrong_password_data = {
                    "email": f"student{timestamp}@test.com",
                    "password": "WrongPassword123!"
                }
                
                response2 = self.session.post(f"{self.base_url}/api/login", json=wrong_password_data)
                if response2.status_code == 401:
                    self.log_test("Wrong Password Login", True, "Correctly returned 401")
                else:
                    self.log_test("Wrong Password Login", False, f"Expected 401, got {response2.status_code}")
            else:
                self.log_test("Student Creation for Login Test", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Wrong Password Login Test", False, str(e))

    def test_professor_creation_duplicate(self):
        """Test professor creation failures identified in the report"""
        print("\n👨‍🏫 TESTING PROFESSOR CREATION DUPLICATE")
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

    def test_professor_login_after_creation(self):
        """Test professor login after creation"""
        print("\n👨‍🏫 TESTING PROFESSOR LOGIN AFTER CREATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Professor Login Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        professor_data = {
            "name": "Test Professor",
            "userid": f"prof{timestamp}",
            "email": f"professor{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Create professor
            response = self.session.post(
                f"{self.base_url}/api/admin/professors",
                json=professor_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                self.cleanup_users.append(data["user"]["id"])
                
                # Try to login as professor
                login_data = {
                    "email": f"professor{timestamp}@test.com",
                    "password": "SecurePassword123!"
                }
                
                response2 = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if response2.status_code == 200:
                    login_data = response2.json()
                    if "access_token" in login_data:
                        self.log_test("Professor Login After Creation", True, "Successfully logged in")
                    else:
                        self.log_test("Professor Login After Creation", False, "No access token in response")
                else:
                    self.log_test("Professor Login After Creation", False, f"Login failed: {response2.status_code}")
            else:
                self.log_test("Professor Creation for Login", False, f"Creation failed: {response.status_code}")
        except Exception as e:
            self.log_test("Professor Login Test", False, str(e))

    def test_invalid_login_format(self):
        """Test login with invalid data format"""
        print("\n🔐 TESTING INVALID LOGIN FORMAT")
        print("=" * 50)
        
        invalid_login_data = [
            {"email": "test@test.com"},  # Missing password
            {"password": "password123"},  # Missing email
            {},  # Empty data
            {"email": "", "password": ""},  # Empty strings
            {"email": "invalid-email", "password": "password123"}  # Invalid email format
        ]
        
        for i, login_data in enumerate(invalid_login_data):
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if response.status_code in [400, 422]:
                    self.log_test(f"Invalid Login Format {i+1}", True, f"Correctly rejected: {response.status_code}")
                else:
                    self.log_test(f"Invalid Login Format {i+1}", False, f"Expected 400/422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Invalid Login Format Test {i+1}", False, str(e))

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

    def run_authentication_tests(self):
        """Run all authentication failure tests"""
        print("🔐 RUNNING AUTHENTICATION FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Authentication failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all authentication tests
        self.test_duplicate_student_registration()
        self.test_student_login_nonexistent_user()
        self.test_student_login_wrong_password()
        self.test_professor_creation_duplicate()
        self.test_professor_login_after_creation()
        self.test_invalid_login_format()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 AUTHENTICATION FAILURE TESTS SUMMARY")
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
    # Run the authentication failure tests
    test_suite = AuthenticationFailuresTest()
    results = test_suite.run_authentication_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 