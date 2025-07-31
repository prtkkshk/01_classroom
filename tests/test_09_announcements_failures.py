#!/usr/bin/env python3
"""
ANNOUNCEMENTS FAILURES TEST
===========================

This test file specifically targets announcements failures identified in the comprehensive test report.
Category: Announcements failures (token/course availability)

Failed Test Scenarios:
- Announcement creation without proper tokens
- Announcement access control
- Announcement validation
- Announcement CRUD operations
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class AnnouncementsFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
        self.cleanup_announcements = []
    
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

    def test_announcement_creation_without_token(self):
        """Test announcement creation without authentication token"""
        print("\n📢 TESTING ANNOUNCEMENT CREATION WITHOUT TOKEN")
        print("=" * 50)
        
        announcement_data = {
            "title": "Test Announcement",
            "content": "Test announcement content",
            "course_id": 1
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/announcements", json=announcement_data)
            if response.status_code == 401:
                self.log_test("Announcement Creation Without Token", True, "Correctly rejected unauthorized request")
            else:
                self.log_test("Announcement Creation Without Token", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Announcement Creation Without Token", False, str(e))

    def test_announcement_creation_with_invalid_token(self):
        """Test announcement creation with invalid token"""
        print("\n📢 TESTING ANNOUNCEMENT CREATION WITH INVALID TOKEN")
        print("=" * 50)
        
        announcement_data = {
            "title": "Test Announcement",
            "content": "Test announcement content",
            "course_id": 1
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
                response = self.session.post(f"{self.base_url}/api/announcements", json=announcement_data, headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Announcement Creation Invalid Token {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Announcement Creation Invalid Token {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Announcement Creation Invalid Token Test {i+1}", False, str(e))

    def test_announcement_access_control(self):
        """Test announcement access control for different user roles"""
        print("\n📢 TESTING ANNOUNCEMENT ACCESS CONTROL")
        print("=" * 50)
        
        # Test accessing announcements without authentication
        try:
            response = self.session.get(f"{self.base_url}/api/announcements")
            if response.status_code == 401:
                self.log_test("Announcement Access Without Auth", True, "Correctly rejected unauthorized access")
            else:
                self.log_test("Announcement Access Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Announcement Access Without Auth", False, str(e))

    def test_announcement_validation(self):
        """Test announcement data validation"""
        print("\n📢 TESTING ANNOUNCEMENT VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Announcement Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid announcement data
        invalid_announcement_data = [
            {
                "title": "",  # Empty title
                "content": "Test announcement content",
                "course_id": 1
            },
            {
                "title": "Test Announcement",
                "content": "",  # Empty content
                "course_id": 1
            },
            {
                "title": "Test Announcement",
                "content": "Test announcement content",
                "course_id": None  # Invalid course_id
            },
            {
                "title": "A" * 256,  # Title too long
                "content": "Test announcement content",
                "course_id": 1
            }
        ]
        
        for i, invalid_data in enumerate(invalid_announcement_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/announcements",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 422:
                    self.log_test(f"Announcement Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"Announcement Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Announcement Validation Test {i+1}", False, str(e))

    def test_announcement_crud_operations(self):
        """Test announcement CRUD operations with proper authentication"""
        print("\n📢 TESTING ANNOUNCEMENT CRUD OPERATIONS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Announcement CRUD Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        announcement_data = {
            "title": f"Test Announcement {timestamp}",
            "content": f"Test announcement content {timestamp}",
            "course_id": 1
        }
        
        try:
            # Create announcement
            create_response = self.session.post(
                f"{self.base_url}/api/announcements",
                json=announcement_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if create_response.status_code == 200:
                create_data = create_response.json()
                announcement_id = create_data["id"]
                self.cleanup_announcements.append(announcement_id)
                
                # Read announcement
                read_response = self.session.get(
                    f"{self.base_url}/api/announcements/{announcement_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if read_response.status_code == 200:
                    self.log_test("Announcement Read", True, "Successfully read announcement")
                else:
                    self.log_test("Announcement Read", False, f"Failed to read announcement: {read_response.status_code}")
                
                # Update announcement
                update_data = {
                    "title": f"Updated Announcement {timestamp}",
                    "content": f"Updated content {timestamp}"
                }
                update_response = self.session.put(
                    f"{self.base_url}/api/announcements/{announcement_id}",
                    json=update_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if update_response.status_code == 200:
                    self.log_test("Announcement Update", True, "Successfully updated announcement")
                else:
                    self.log_test("Announcement Update", False, f"Failed to update announcement: {update_response.status_code}")
                
                # Delete announcement
                delete_response = self.session.delete(
                    f"{self.base_url}/api/announcements/{announcement_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if delete_response.status_code == 200:
                    self.log_test("Announcement Delete", True, "Successfully deleted announcement")
                    self.cleanup_announcements.remove(announcement_id)  # Already deleted
                else:
                    self.log_test("Announcement Delete", False, f"Failed to delete announcement: {delete_response.status_code}")
            else:
                self.log_test("Announcement Create", False, f"Failed to create announcement: {create_response.status_code}")
        except Exception as e:
            self.log_test("Announcement CRUD Operations", False, str(e))

    def test_announcement_listing_with_filters(self):
        """Test announcement listing with various filters"""
        print("\n📢 TESTING ANNOUNCEMENT LISTING WITH FILTERS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Announcement Listing Setup", False, "Moderator login failed")
            return
        
        # Test different filter parameters
        filter_tests = [
            "?limit=10",
            "?offset=0",
            "?course_id=1",
            "?search=test",
            "?limit=10&offset=0&course_id=1"
        ]
        
        for i, filter_param in enumerate(filter_tests):
            try:
                response = self.session.get(
                    f"{self.base_url}/api/announcements{filter_param}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code in [200, 404]:
                    self.log_test(f"Announcement Listing Filter {i+1}", True, f"Successfully handled filter: {filter_param}")
                else:
                    self.log_test(f"Announcement Listing Filter {i+1}", False, f"Failed with filter {filter_param}: {response.status_code}")
            except Exception as e:
                self.log_test(f"Announcement Listing Filter Test {i+1}", False, str(e))

    def test_announcement_priority_levels(self):
        """Test announcement priority levels"""
        print("\n📢 TESTING ANNOUNCEMENT PRIORITY LEVELS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Announcement Priority Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        
        # Test different priority levels
        priority_levels = ["low", "medium", "high", "urgent"]
        
        for i, priority in enumerate(priority_levels):
            announcement_data = {
                "title": f"Priority Test {priority} {timestamp + i}",
                "content": f"Test content for {priority} priority",
                "course_id": 1,
                "priority": priority
            }
            
            try:
                response = self.session.post(
                    f"{self.base_url}/api/announcements",
                    json=announcement_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    data = response.json()
                    self.cleanup_announcements.append(data["id"])
                    self.log_test(f"Announcement Priority {priority}", True, f"Successfully created {priority} priority announcement")
                else:
                    self.log_test(f"Announcement Priority {priority}", False, f"Failed to create {priority} priority announcement: {response.status_code}")
            except Exception as e:
                self.log_test(f"Announcement Priority Test {priority}", False, str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 CLEANING UP TEST DATA")
        print("=" * 50)
        
        if not self.setup_moderator():
            print("❌ Cannot cleanup - moderator login failed")
            return
        
        for announcement_id in self.cleanup_announcements:
            try:
                response = self.session.delete(
                    f"{self.base_url}/api/announcements/{announcement_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    print(f"✅ Cleaned up announcement {announcement_id}")
                else:
                    print(f"❌ Failed to cleanup announcement {announcement_id}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error cleaning up announcement {announcement_id}: {e}")

    def run_announcements_tests(self):
        """Run all announcements failure tests"""
        print("📢 RUNNING ANNOUNCEMENTS FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Announcements failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all announcements tests
        self.test_announcement_creation_without_token()
        self.test_announcement_creation_with_invalid_token()
        self.test_announcement_access_control()
        self.test_announcement_validation()
        self.test_announcement_crud_operations()
        self.test_announcement_listing_with_filters()
        self.test_announcement_priority_levels()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 ANNOUNCEMENTS FAILURE TESTS SUMMARY")
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
    # Run the announcements failure tests
    test_suite = AnnouncementsFailuresTest()
    results = test_suite.run_announcements_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 