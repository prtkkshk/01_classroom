#!/usr/bin/env python3
"""
COURSE MANAGEMENT FAILURES TEST
===============================

This test file specifically targets course management failures identified in the comprehensive test report.
Category: Course management failures (token issues, access control)

Failed Test Scenarios:
- Course creation with invalid tokens
- Course access control
- Course CRUD operations
- Course enrollment issues
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class CourseManagementFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
        self.cleanup_courses = []
    
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

    def test_course_creation_without_token(self):
        """Test course creation without authentication token"""
        print("\n📚 TESTING COURSE CREATION WITHOUT TOKEN")
        print("=" * 50)
        
        course_data = {
            "name": "Test Course",
            "description": "Test course description",
            "code": "TEST101"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/courses", json=course_data)
            if response.status_code == 401:
                self.log_test("Course Creation Without Token", True, "Correctly rejected unauthorized request")
            else:
                self.log_test("Course Creation Without Token", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Course Creation Without Token", False, str(e))

    def test_course_creation_with_invalid_token(self):
        """Test course creation with invalid token"""
        print("\n📚 TESTING COURSE CREATION WITH INVALID TOKEN")
        print("=" * 50)
        
        course_data = {
            "name": "Test Course",
            "description": "Test course description",
            "code": "TEST101"
        }
        
        invalid_tokens = [
            "invalid_token",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid",
            "",
            "Bearer invalid_token"
        ]
        
        for i, token in enumerate(invalid_tokens):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            
            try:
                response = self.session.post(f"{self.base_url}/api/courses", json=course_data, headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Course Creation Invalid Token {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Course Creation Invalid Token {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Course Creation Invalid Token Test {i+1}", False, str(e))

    def test_course_access_control(self):
        """Test course access control for different user roles"""
        print("\n📚 TESTING COURSE ACCESS CONTROL")
        print("=" * 50)
        
        # Test accessing courses without authentication
        try:
            response = self.session.get(f"{self.base_url}/api/courses")
            if response.status_code == 401:
                self.log_test("Course Access Without Auth", True, "Correctly rejected unauthorized access")
            else:
                self.log_test("Course Access Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Course Access Without Auth", False, str(e))

    def test_course_crud_operations(self):
        """Test course CRUD operations with proper authentication"""
        print("\n📚 TESTING COURSE CRUD OPERATIONS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Course CRUD Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        course_data = {
            "name": f"Test Course {timestamp}",
            "description": f"Test course description {timestamp}",
            "code": f"TEST{timestamp}"
        }
        
        try:
            # Create course
            create_response = self.session.post(
                f"{self.base_url}/api/courses",
                json=course_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if create_response.status_code == 200:
                create_data = create_response.json()
                course_id = create_data["id"]
                self.cleanup_courses.append(course_id)
                
                # Read course
                read_response = self.session.get(
                    f"{self.base_url}/api/courses/{course_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if read_response.status_code == 200:
                    self.log_test("Course Read", True, "Successfully read course")
                else:
                    self.log_test("Course Read", False, f"Failed to read course: {read_response.status_code}")
                
                # Update course
                update_data = {
                    "name": f"Updated Course {timestamp}",
                    "description": f"Updated description {timestamp}"
                }
                update_response = self.session.put(
                    f"{self.base_url}/api/courses/{course_id}",
                    json=update_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if update_response.status_code == 200:
                    self.log_test("Course Update", True, "Successfully updated course")
                else:
                    self.log_test("Course Update", False, f"Failed to update course: {update_response.status_code}")
                
                # Delete course
                delete_response = self.session.delete(
                    f"{self.base_url}/api/courses/{course_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if delete_response.status_code == 200:
                    self.log_test("Course Delete", True, "Successfully deleted course")
                    self.cleanup_courses.remove(course_id)  # Already deleted
                else:
                    self.log_test("Course Delete", False, f"Failed to delete course: {delete_response.status_code}")
            else:
                self.log_test("Course Create", False, f"Failed to create course: {create_response.status_code}")
        except Exception as e:
            self.log_test("Course CRUD Operations", False, str(e))

    def test_course_enrollment_issues(self):
        """Test course enrollment issues"""
        print("\n📚 TESTING COURSE ENROLLMENT ISSUES")
        print("=" * 50)
        
        # Test enrollment without authentication
        try:
            response = self.session.post(f"{self.base_url}/api/courses/123/enroll")
            if response.status_code == 401:
                self.log_test("Course Enrollment Without Auth", True, "Correctly rejected unauthorized enrollment")
            else:
                self.log_test("Course Enrollment Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Course Enrollment Without Auth", False, str(e))

    def test_course_validation(self):
        """Test course data validation"""
        print("\n📚 TESTING COURSE VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Course Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid course data
        invalid_course_data = [
            {
                "name": "",  # Empty name
                "description": "Test description",
                "code": "TEST101"
            },
            {
                "name": "Test Course",
                "description": "",  # Empty description
                "code": "TEST101"
            },
            {
                "name": "Test Course",
                "description": "Test description",
                "code": ""  # Empty code
            },
            {
                "name": "Test Course",
                "description": "Test description",
                "code": "A" * 51  # Code too long
            }
        ]
        
        for i, invalid_data in enumerate(invalid_course_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/courses",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 422:
                    self.log_test(f"Course Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"Course Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Course Validation Test {i+1}", False, str(e))

    def test_course_listing_with_filters(self):
        """Test course listing with various filters"""
        print("\n📚 TESTING COURSE LISTING WITH FILTERS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Course Listing Setup", False, "Moderator login failed")
            return
        
        # Test different filter parameters
        filter_tests = [
            "?limit=10",
            "?offset=0",
            "?search=test",
            "?status=active",
            "?limit=10&offset=0&search=test"
        ]
        
        for i, filter_param in enumerate(filter_tests):
            try:
                response = self.session.get(
                    f"{self.base_url}/api/courses{filter_param}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code in [200, 404]:
                    self.log_test(f"Course Listing Filter {i+1}", True, f"Successfully handled filter: {filter_param}")
                else:
                    self.log_test(f"Course Listing Filter {i+1}", False, f"Failed with filter {filter_param}: {response.status_code}")
            except Exception as e:
                self.log_test(f"Course Listing Filter Test {i+1}", False, str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 CLEANING UP TEST DATA")
        print("=" * 50)
        
        if not self.setup_moderator():
            print("❌ Cannot cleanup - moderator login failed")
            return
        
        for course_id in self.cleanup_courses:
            try:
                response = self.session.delete(
                    f"{self.base_url}/api/courses/{course_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    print(f"✅ Cleaned up course {course_id}")
                else:
                    print(f"❌ Failed to cleanup course {course_id}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error cleaning up course {course_id}: {e}")

    def run_course_management_tests(self):
        """Run all course management failure tests"""
        print("📚 RUNNING COURSE MANAGEMENT FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Course management failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all course management tests
        self.test_course_creation_without_token()
        self.test_course_creation_with_invalid_token()
        self.test_course_access_control()
        self.test_course_crud_operations()
        self.test_course_enrollment_issues()
        self.test_course_validation()
        self.test_course_listing_with_filters()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 COURSE MANAGEMENT FAILURE TESTS SUMMARY")
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
    # Run the course management failure tests
    test_suite = CourseManagementFailuresTest()
    results = test_suite.run_course_management_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 