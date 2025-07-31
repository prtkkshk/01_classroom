#!/usr/bin/env python3
"""
USER MANAGEMENT FAILURES TEST
=============================

This test file specifically targets user management failures identified in the comprehensive test report.
Category: User management failures (registration, login issues)

Failed Test Scenarios:
- User registration validation
- User login issues
- User profile management
- User role management
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class UserManagementFailuresTest:
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

    def test_user_registration_validation(self):
        """Test user registration validation failures"""
        print("\n👤 TESTING USER REGISTRATION VALIDATION")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various invalid registration data
        invalid_registrations = [
            {
                "name": "",  # Empty name
                "roll_number": f"23BT{timestamp}",
                "email": f"student{timestamp}@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test Student",
                "roll_number": "",  # Empty roll number
                "email": f"student{timestamp}@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Test Student",
                "roll_number": f"23BT{timestamp}",
                "email": "",  # Empty email
                "password": "SecurePassword123!"
            },
            {
                "name": "Test Student",
                "roll_number": f"23BT{timestamp}",
                "email": f"student{timestamp}@test.com",
                "password": ""  # Empty password
            },
            {
                "name": "Test Student",
                "roll_number": f"23BT{timestamp}",
                "email": "invalid-email",  # Invalid email format
                "password": "SecurePassword123!"
            },
            {
                "name": "Test Student",
                "roll_number": f"23BT{timestamp}",
                "email": f"student{timestamp}@test.com",
                "password": "123"  # Too short password
            }
        ]
        
        for i, invalid_data in enumerate(invalid_registrations):
            # Make each registration unique
            invalid_data["roll_number"] = f"23BT{timestamp + i}"
            invalid_data["email"] = f"student{timestamp + i}@test.com"
            
            try:
                response = self.session.post(f"{self.base_url}/api/register", json=invalid_data)
                if response.status_code == 422:
                    self.log_test(f"User Registration Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"User Registration Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"User Registration Validation Test {i+1}", False, str(e))

    def test_user_login_issues(self):
        """Test user login issues"""
        print("\n🔐 TESTING USER LOGIN ISSUES")
        print("=" * 50)
        
        # Test login with various invalid credentials
        invalid_logins = [
            {
                "email": "nonexistent@test.com",
                "password": "wrongpassword"
            },
            {
                "email": "",
                "password": "password123"
            },
            {
                "email": "test@test.com",
                "password": ""
            },
            {
                "email": "invalid-email",
                "password": "password123"
            },
            {
                "email": "test@test.com",
                "password": "wrongpassword"
            }
        ]
        
        for i, login_data in enumerate(invalid_logins):
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                if response.status_code in [401, 422]:
                    self.log_test(f"User Login Issue {i+1}", True, f"Correctly handled invalid login: {response.status_code}")
                else:
                    self.log_test(f"User Login Issue {i+1}", False, f"Expected 401/422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"User Login Issue Test {i+1}", False, str(e))

    def test_user_profile_management(self):
        """Test user profile management failures"""
        print("\n👤 TESTING USER PROFILE MANAGEMENT")
        print("=" * 50)
        
        # First create a test user
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
                user_token = data["access_token"]
                self.cleanup_users.append(data["user"]["id"])
                
                # Test getting user profile
                profile_response = self.session.get(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {user_token}"}
                )
                if profile_response.status_code == 200:
                    self.log_test("User Profile Retrieval", True, "Successfully retrieved user profile")
                else:
                    self.log_test("User Profile Retrieval", False, f"Failed to retrieve profile: {profile_response.status_code}")
                
                # Test updating user profile
                update_data = {
                    "name": f"Updated Student {timestamp}",
                    "email": f"updated{timestamp}@test.com"
                }
                
                update_response = self.session.put(
                    f"{self.base_url}/api/profile",
                    json=update_data,
                    headers={"Authorization": f"Bearer {user_token}"}
                )
                if update_response.status_code == 200:
                    self.log_test("User Profile Update", True, "Successfully updated user profile")
                else:
                    self.log_test("User Profile Update", False, f"Failed to update profile: {update_response.status_code}")
            else:
                self.log_test("User Creation for Profile Test", False, f"Failed to create user: {response.status_code}")
        except Exception as e:
            self.log_test("User Profile Management Test", False, str(e))

    def test_user_role_management(self):
        """Test user role management failures"""
        print("\n👥 TESTING USER ROLE MANAGEMENT")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("User Role Management Setup", False, "Moderator login failed")
            return
        
        # Test getting all users (admin function)
        try:
            response = self.session.get(
                f"{self.base_url}/api/admin/users",
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("User List Retrieval", True, f"Successfully retrieved {len(data)} users")
                else:
                    self.log_test("User List Retrieval", False, "Response is not a list")
            else:
                self.log_test("User List Retrieval", False, f"Failed to retrieve users: {response.status_code}")
        except Exception as e:
            self.log_test("User List Retrieval", False, str(e))

    def test_user_deletion(self):
        """Test user deletion functionality"""
        print("\n🗑️ TESTING USER DELETION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("User Deletion Setup", False, "Moderator login failed")
            return
        
        # Create a test user to delete
        timestamp = int(time.time())
        student_data = {
            "name": f"Delete Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"delete{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                user_id = data["user"]["id"]
                
                # Delete the user
                delete_response = self.session.delete(
                    f"{self.base_url}/api/admin/users/{user_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if delete_response.status_code == 200:
                    self.log_test("User Deletion", True, "Successfully deleted user")
                else:
                    self.log_test("User Deletion", False, f"Failed to delete user: {delete_response.status_code}")
            else:
                self.log_test("User Creation for Deletion", False, f"Failed to create user: {response.status_code}")
        except Exception as e:
            self.log_test("User Deletion Test", False, str(e))

    def test_user_authentication_flow(self):
        """Test complete user authentication flow"""
        print("\n🔄 TESTING USER AUTHENTICATION FLOW")
        print("=" * 50)
        
        timestamp = int(time.time())
        student_data = {
            "name": f"Auth Flow Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"authflow{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Step 1: Register user
            register_response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if register_response.status_code == 200:
                register_data = register_response.json()
                user_token = register_data["access_token"]
                self.cleanup_users.append(register_data["user"]["id"])
                
                # Step 2: Login with same credentials
                login_response = self.session.post(f"{self.base_url}/api/login", json={
                    "email": f"authflow{timestamp}@test.com",
                    "password": "SecurePassword123!"
                })
                
                if login_response.status_code == 200:
                    login_data = login_response.json()
                    if "access_token" in login_data:
                        self.log_test("User Authentication Flow", True, "Complete auth flow successful")
                    else:
                        self.log_test("User Authentication Flow", False, "No access token in login response")
                else:
                    self.log_test("User Authentication Flow", False, f"Login failed: {login_response.status_code}")
            else:
                self.log_test("User Authentication Flow", False, f"Registration failed: {register_response.status_code}")
        except Exception as e:
            self.log_test("User Authentication Flow", False, str(e))

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

    def run_user_management_tests(self):
        """Run all user management failure tests"""
        print("👤 RUNNING USER MANAGEMENT FAILURE TESTS")
        print("=" * 60)
        print(f"Target: User management failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all user management tests
        self.test_user_registration_validation()
        self.test_user_login_issues()
        self.test_user_profile_management()
        self.test_user_role_management()
        self.test_user_deletion()
        self.test_user_authentication_flow()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 USER MANAGEMENT FAILURE TESTS SUMMARY")
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
    # Run the user management failure tests
    test_suite = UserManagementFailuresTest()
    results = test_suite.run_user_management_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 