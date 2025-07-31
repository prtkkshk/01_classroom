#!/usr/bin/env python3
"""
ADMIN FAILURES TEST
===================

This test file specifically targets admin failures identified in the comprehensive test report.
Category: Admin failures (unauthorized access, token validation)

Failed Test Scenarios:
- Admin endpoint access without proper authorization
- Admin token validation
- Admin user management
- Admin course management
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class AdminFailuresTest:
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

    def test_admin_endpoint_access_without_token(self):
        """Test admin endpoint access without authentication token"""
        print("\n👑 TESTING ADMIN ENDPOINT ACCESS WITHOUT TOKEN")
        print("=" * 50)
        
        admin_endpoints = [
            "/api/admin/users",
            "/api/admin/courses",
            "/api/admin/professors",
            "/api/admin/students",
            "/api/admin/statistics"
        ]
        
        for endpoint in admin_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code == 401:
                    self.log_test(f"Admin Endpoint Access {endpoint}", True, "Correctly rejected unauthorized access")
                else:
                    self.log_test(f"Admin Endpoint Access {endpoint}", False, f"Expected 401, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Admin Endpoint Access {endpoint}", False, str(e))

    def test_admin_endpoint_access_with_invalid_token(self):
        """Test admin endpoint access with invalid token"""
        print("\n👑 TESTING ADMIN ENDPOINT ACCESS WITH INVALID TOKEN")
        print("=" * 50)
        
        invalid_tokens = [
            "invalid_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "Bearer invalid_token"
        ]
        
        admin_endpoints = [
            "/api/admin/users",
            "/api/admin/courses"
        ]
        
        for i, token in enumerate(invalid_tokens):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            
            for endpoint in admin_endpoints:
                try:
                    response = self.session.get(f"{self.base_url}{endpoint}", headers=headers)
                    if response.status_code in [401, 403]:
                        self.log_test(f"Admin Endpoint Invalid Token {endpoint} {i+1}", True, f"Correctly rejected invalid token")
                    else:
                        self.log_test(f"Admin Endpoint Invalid Token {endpoint} {i+1}", False, f"Expected 401/403, got {response.status_code}")
                except Exception as e:
                    self.log_test(f"Admin Endpoint Invalid Token Test {endpoint} {i+1}", False, str(e))

    def test_admin_user_management(self):
        """Test admin user management functionality"""
        print("\n👑 TESTING ADMIN USER MANAGEMENT")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin User Management Setup", False, "Moderator login failed")
            return
        
        # Test getting all users
        try:
            response = self.session.get(
                f"{self.base_url}/api/admin/users",
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Admin User List", True, f"Successfully retrieved {len(data)} users")
                else:
                    self.log_test("Admin User List", False, "Response is not a list")
            else:
                self.log_test("Admin User List", False, f"Failed to retrieve users: {response.status_code}")
        except Exception as e:
            self.log_test("Admin User List", False, str(e))

    def test_admin_professor_creation(self):
        """Test admin professor creation functionality"""
        print("\n👑 TESTING ADMIN PROFESSOR CREATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin Professor Creation Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        professor_data = {
            "name": f"Admin Test Professor {timestamp}",
            "userid": f"admin_prof{timestamp}",
            "email": f"admin_professor{timestamp}@test.com",
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
                self.log_test("Admin Professor Creation", True, "Successfully created professor")
            else:
                self.log_test("Admin Professor Creation", False, f"Failed to create professor: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Professor Creation", False, str(e))

    def test_admin_user_deletion(self):
        """Test admin user deletion functionality"""
        print("\n👑 TESTING ADMIN USER DELETION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin User Deletion Setup", False, "Moderator login failed")
            return
        
        # Create a test user to delete
        timestamp = int(time.time())
        student_data = {
            "name": f"Admin Delete Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"admin_delete{timestamp}@test.com",
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
                    self.log_test("Admin User Deletion", True, "Successfully deleted user")
                else:
                    self.log_test("Admin User Deletion", False, f"Failed to delete user: {delete_response.status_code}")
            else:
                self.log_test("Admin User Creation for Deletion", False, f"Failed to create user: {response.status_code}")
        except Exception as e:
            self.log_test("Admin User Deletion", False, str(e))

    def test_admin_course_management(self):
        """Test admin course management functionality"""
        print("\n👑 TESTING ADMIN COURSE MANAGEMENT")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin Course Management Setup", False, "Moderator login failed")
            return
        
        # Test getting all courses
        try:
            response = self.session.get(
                f"{self.base_url}/api/admin/courses",
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    self.log_test("Admin Course List", True, f"Successfully retrieved {len(data)} courses")
                else:
                    self.log_test("Admin Course List", False, "Response is not a list")
            else:
                self.log_test("Admin Course List", False, f"Failed to retrieve courses: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Course List", False, str(e))

    def test_admin_statistics(self):
        """Test admin statistics functionality"""
        print("\n👑 TESTING ADMIN STATISTICS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin Statistics Setup", False, "Moderator login failed")
            return
        
        # Test getting admin statistics
        try:
            response = self.session.get(
                f"{self.base_url}/api/admin/statistics",
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    self.log_test("Admin Statistics", True, f"Successfully retrieved statistics: {list(data.keys())}")
                else:
                    self.log_test("Admin Statistics", False, "Response is not a dictionary")
            else:
                self.log_test("Admin Statistics", False, f"Failed to retrieve statistics: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Statistics", False, str(e))

    def test_admin_unauthorized_access(self):
        """Test admin unauthorized access scenarios"""
        print("\n👑 TESTING ADMIN UNAUTHORIZED ACCESS")
        print("=" * 50)
        
        # Test accessing admin endpoints with student token
        timestamp = int(time.time())
        student_data = {
            "name": f"Admin Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"admin_test{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Create a student account
            response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response.status_code == 200:
                data = response.json()
                student_token = data["access_token"]
                self.cleanup_users.append(data["user"]["id"])
                
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
                        if admin_response.status_code in [401, 403]:
                            self.log_test(f"Admin Unauthorized Access {endpoint}", True, "Correctly rejected student access")
                        else:
                            self.log_test(f"Admin Unauthorized Access {endpoint}", False, f"Expected 401/403, got {admin_response.status_code}")
                    except Exception as e:
                        self.log_test(f"Admin Unauthorized Access {endpoint}", False, str(e))
            else:
                self.log_test("Student Creation for Admin Test", False, f"Failed to create student: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Unauthorized Access Test", False, str(e))

    def test_admin_token_validation(self):
        """Test admin token validation"""
        print("\n👑 TESTING ADMIN TOKEN VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Admin Token Validation Setup", False, "Moderator login failed")
            return
        
        # Test token validation endpoint
        try:
            response = self.session.get(
                f"{self.base_url}/api/admin/validate-token",
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if response.status_code == 200:
                data = response.json()
                if "valid" in data and data["valid"]:
                    self.log_test("Admin Token Validation", True, "Token is valid")
                else:
                    self.log_test("Admin Token Validation", False, "Token validation failed")
            else:
                self.log_test("Admin Token Validation", False, f"Token validation endpoint failed: {response.status_code}")
        except Exception as e:
            self.log_test("Admin Token Validation", False, str(e))

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

    def run_admin_tests(self):
        """Run all admin failure tests"""
        print("👑 RUNNING ADMIN FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Admin failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all admin tests
        self.test_admin_endpoint_access_without_token()
        self.test_admin_endpoint_access_with_invalid_token()
        self.test_admin_user_management()
        self.test_admin_professor_creation()
        self.test_admin_user_deletion()
        self.test_admin_course_management()
        self.test_admin_statistics()
        self.test_admin_unauthorized_access()
        self.test_admin_token_validation()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ADMIN FAILURE TESTS SUMMARY")
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
    # Run the admin failure tests
    test_suite = AdminFailuresTest()
    results = test_suite.run_admin_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 