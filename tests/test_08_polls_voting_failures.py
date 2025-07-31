#!/usr/bin/env python3
"""
POLLS & VOTING FAILURES TEST
============================

This test file specifically targets polls and voting failures identified in the comprehensive test report.
Category: Polls & Voting failures (token/course availability)

Failed Test Scenarios:
- Poll creation without proper tokens
- Voting issues
- Poll access control
- Poll validation
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class PollsVotingFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
        self.cleanup_polls = []
    
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

    def test_poll_creation_without_token(self):
        """Test poll creation without authentication token"""
        print("\n📊 TESTING POLL CREATION WITHOUT TOKEN")
        print("=" * 50)
        
        poll_data = {
            "question": "Test Poll Question",
            "options": ["Option 1", "Option 2", "Option 3"],
            "course_id": 1
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/polls", json=poll_data)
            if response.status_code == 401:
                self.log_test("Poll Creation Without Token", True, "Correctly rejected unauthorized request")
            else:
                self.log_test("Poll Creation Without Token", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Poll Creation Without Token", False, str(e))

    def test_poll_creation_with_invalid_token(self):
        """Test poll creation with invalid token"""
        print("\n📊 TESTING POLL CREATION WITH INVALID TOKEN")
        print("=" * 50)
        
        poll_data = {
            "question": "Test Poll Question",
            "options": ["Option 1", "Option 2", "Option 3"],
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
                response = self.session.post(f"{self.base_url}/api/polls", json=poll_data, headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Poll Creation Invalid Token {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Poll Creation Invalid Token {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Poll Creation Invalid Token Test {i+1}", False, str(e))

    def test_poll_access_control(self):
        """Test poll access control for different user roles"""
        print("\n📊 TESTING POLL ACCESS CONTROL")
        print("=" * 50)
        
        # Test accessing polls without authentication
        try:
            response = self.session.get(f"{self.base_url}/api/polls")
            if response.status_code == 401:
                self.log_test("Poll Access Without Auth", True, "Correctly rejected unauthorized access")
            else:
                self.log_test("Poll Access Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Poll Access Without Auth", False, str(e))

    def test_poll_validation(self):
        """Test poll data validation"""
        print("\n📊 TESTING POLL VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Poll Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid poll data
        invalid_poll_data = [
            {
                "question": "",  # Empty question
                "options": ["Option 1", "Option 2", "Option 3"],
                "course_id": 1
            },
            {
                "question": "Test Poll Question",
                "options": [],  # Empty options
                "course_id": 1
            },
            {
                "question": "Test Poll Question",
                "options": ["Option 1"],  # Only one option
                "course_id": 1
            },
            {
                "question": "Test Poll Question",
                "options": ["Option 1", "Option 2", "Option 3"],
                "course_id": None  # Invalid course_id
            }
        ]
        
        for i, invalid_data in enumerate(invalid_poll_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/polls",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 422:
                    self.log_test(f"Poll Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"Poll Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Poll Validation Test {i+1}", False, str(e))

    def test_voting_issues(self):
        """Test voting issues"""
        print("\n🗳️ TESTING VOTING ISSUES")
        print("=" * 50)
        
        # Test voting without authentication
        vote_data = {
            "poll_id": 1,
            "option_id": 1
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/polls/1/vote", json=vote_data)
            if response.status_code == 401:
                self.log_test("Voting Without Auth", True, "Correctly rejected unauthorized voting")
            else:
                self.log_test("Voting Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Voting Without Auth", False, str(e))

    def test_vote_validation(self):
        """Test vote data validation"""
        print("\n🗳️ TESTING VOTE VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Vote Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid vote data
        invalid_vote_data = [
            {
                "poll_id": None,  # Invalid poll_id
                "option_id": 1
            },
            {
                "poll_id": 1,
                "option_id": None  # Invalid option_id
            },
            {
                "poll_id": 1,
                "option_id": 999  # Non-existent option_id
            }
        ]
        
        for i, invalid_data in enumerate(invalid_vote_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/polls/1/vote",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code in [400, 422, 404]:
                    self.log_test(f"Vote Validation {i+1}", True, f"Correctly rejected invalid vote data")
                else:
                    self.log_test(f"Vote Validation {i+1}", False, f"Expected 400/422/404, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Vote Validation Test {i+1}", False, str(e))

    def test_poll_crud_operations(self):
        """Test poll CRUD operations with proper authentication"""
        print("\n📊 TESTING POLL CRUD OPERATIONS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Poll CRUD Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        poll_data = {
            "question": f"Test Poll Question {timestamp}",
            "options": [f"Option 1 {timestamp}", f"Option 2 {timestamp}", f"Option 3 {timestamp}"],
            "course_id": 1
        }
        
        try:
            # Create poll
            create_response = self.session.post(
                f"{self.base_url}/api/polls",
                json=poll_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if create_response.status_code == 200:
                create_data = create_response.json()
                poll_id = create_data["id"]
                self.cleanup_polls.append(poll_id)
                
                # Read poll
                read_response = self.session.get(
                    f"{self.base_url}/api/polls/{poll_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if read_response.status_code == 200:
                    self.log_test("Poll Read", True, "Successfully read poll")
                else:
                    self.log_test("Poll Read", False, f"Failed to read poll: {read_response.status_code}")
                
                # Update poll
                update_data = {
                    "question": f"Updated Poll Question {timestamp}",
                    "options": [f"Updated Option 1 {timestamp}", f"Updated Option 2 {timestamp}"]
                }
                update_response = self.session.put(
                    f"{self.base_url}/api/polls/{poll_id}",
                    json=update_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if update_response.status_code == 200:
                    self.log_test("Poll Update", True, "Successfully updated poll")
                else:
                    self.log_test("Poll Update", False, f"Failed to update poll: {update_response.status_code}")
                
                # Delete poll
                delete_response = self.session.delete(
                    f"{self.base_url}/api/polls/{poll_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if delete_response.status_code == 200:
                    self.log_test("Poll Delete", True, "Successfully deleted poll")
                    self.cleanup_polls.remove(poll_id)  # Already deleted
                else:
                    self.log_test("Poll Delete", False, f"Failed to delete poll: {delete_response.status_code}")
            else:
                self.log_test("Poll Create", False, f"Failed to create poll: {create_response.status_code}")
        except Exception as e:
            self.log_test("Poll CRUD Operations", False, str(e))

    def test_poll_listing_with_filters(self):
        """Test poll listing with various filters"""
        print("\n📊 TESTING POLL LISTING WITH FILTERS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Poll Listing Setup", False, "Moderator login failed")
            return
        
        # Test different filter parameters
        filter_tests = [
            "?limit=10",
            "?offset=0",
            "?course_id=1",
            "?status=active",
            "?limit=10&offset=0&course_id=1"
        ]
        
        for i, filter_param in enumerate(filter_tests):
            try:
                response = self.session.get(
                    f"{self.base_url}/api/polls{filter_param}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code in [200, 404]:
                    self.log_test(f"Poll Listing Filter {i+1}", True, f"Successfully handled filter: {filter_param}")
                else:
                    self.log_test(f"Poll Listing Filter {i+1}", False, f"Failed with filter {filter_param}: {response.status_code}")
            except Exception as e:
                self.log_test(f"Poll Listing Filter Test {i+1}", False, str(e))

    def test_duplicate_voting(self):
        """Test duplicate voting prevention"""
        print("\n🗳️ TESTING DUPLICATE VOTING")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Duplicate Voting Setup", False, "Moderator login failed")
            return
        
        # Create a test poll first
        timestamp = int(time.time())
        poll_data = {
            "question": f"Duplicate Vote Test {timestamp}",
            "options": ["Option 1", "Option 2"],
            "course_id": 1
        }
        
        try:
            create_response = self.session.post(
                f"{self.base_url}/api/polls",
                json=poll_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if create_response.status_code == 200:
                create_data = create_response.json()
                poll_id = create_data["id"]
                self.cleanup_polls.append(poll_id)
                
                # First vote
                vote_data = {"option_id": 1}
                vote1_response = self.session.post(
                    f"{self.base_url}/api/polls/{poll_id}/vote",
                    json=vote_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                
                if vote1_response.status_code == 200:
                    # Second vote (should be rejected)
                    vote2_response = self.session.post(
                        f"{self.base_url}/api/polls/{poll_id}/vote",
                        json=vote_data,
                        headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                    )
                    
                    if vote2_response.status_code == 400:
                        self.log_test("Duplicate Voting Prevention", True, "Correctly prevented duplicate vote")
                    else:
                        self.log_test("Duplicate Voting Prevention", False, f"Expected 400, got {vote2_response.status_code}")
                else:
                    self.log_test("First Vote", False, f"Failed to cast first vote: {vote1_response.status_code}")
            else:
                self.log_test("Poll Creation for Duplicate Vote", False, f"Failed to create poll: {create_response.status_code}")
        except Exception as e:
            self.log_test("Duplicate Voting Test", False, str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 CLEANING UP TEST DATA")
        print("=" * 50)
        
        if not self.setup_moderator():
            print("❌ Cannot cleanup - moderator login failed")
            return
        
        for poll_id in self.cleanup_polls:
            try:
                response = self.session.delete(
                    f"{self.base_url}/api/polls/{poll_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    print(f"✅ Cleaned up poll {poll_id}")
                else:
                    print(f"❌ Failed to cleanup poll {poll_id}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error cleaning up poll {poll_id}: {e}")

    def run_polls_voting_tests(self):
        """Run all polls and voting failure tests"""
        print("📊 RUNNING POLLS & VOTING FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Polls & Voting failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all polls and voting tests
        self.test_poll_creation_without_token()
        self.test_poll_creation_with_invalid_token()
        self.test_poll_access_control()
        self.test_poll_validation()
        self.test_voting_issues()
        self.test_vote_validation()
        self.test_poll_crud_operations()
        self.test_poll_listing_with_filters()
        self.test_duplicate_voting()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 POLLS & VOTING FAILURE TESTS SUMMARY")
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
    # Run the polls and voting failure tests
    test_suite = PollsVotingFailuresTest()
    results = test_suite.run_polls_voting_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 