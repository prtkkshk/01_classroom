#!/usr/bin/env python3
"""
QUESTIONS & ANSWERS FAILURES TEST
=================================

This test file specifically targets questions and answers failures identified in the comprehensive test report.
Category: Questions & Answers failures (token/course availability)

Failed Test Scenarios:
- Question creation without proper tokens
- Answer submission issues
- Question access control
- Question validation
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class QuestionsAnswersFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
        self.cleanup_questions = []
    
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

    def test_question_creation_without_token(self):
        """Test question creation without authentication token"""
        print("\n❓ TESTING QUESTION CREATION WITHOUT TOKEN")
        print("=" * 50)
        
        question_data = {
            "title": "Test Question",
            "content": "Test question content",
            "course_id": 1
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/questions", json=question_data)
            if response.status_code == 401:
                self.log_test("Question Creation Without Token", True, "Correctly rejected unauthorized request")
            else:
                self.log_test("Question Creation Without Token", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Question Creation Without Token", False, str(e))

    def test_question_creation_with_invalid_token(self):
        """Test question creation with invalid token"""
        print("\n❓ TESTING QUESTION CREATION WITH INVALID TOKEN")
        print("=" * 50)
        
        question_data = {
            "title": "Test Question",
            "content": "Test question content",
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
                response = self.session.post(f"{self.base_url}/api/questions", json=question_data, headers=headers)
                if response.status_code in [401, 403]:
                    self.log_test(f"Question Creation Invalid Token {i+1}", True, f"Correctly rejected invalid token")
                else:
                    self.log_test(f"Question Creation Invalid Token {i+1}", False, f"Expected 401/403, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Question Creation Invalid Token Test {i+1}", False, str(e))

    def test_question_access_control(self):
        """Test question access control for different user roles"""
        print("\n❓ TESTING QUESTION ACCESS CONTROL")
        print("=" * 50)
        
        # Test accessing questions without authentication
        try:
            response = self.session.get(f"{self.base_url}/api/questions")
            if response.status_code == 401:
                self.log_test("Question Access Without Auth", True, "Correctly rejected unauthorized access")
            else:
                self.log_test("Question Access Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Question Access Without Auth", False, str(e))

    def test_question_validation(self):
        """Test question data validation"""
        print("\n❓ TESTING QUESTION VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Question Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid question data
        invalid_question_data = [
            {
                "title": "",  # Empty title
                "content": "Test question content",
                "course_id": 1
            },
            {
                "title": "Test Question",
                "content": "",  # Empty content
                "course_id": 1
            },
            {
                "title": "Test Question",
                "content": "Test question content",
                "course_id": None  # Invalid course_id
            },
            {
                "title": "A" * 256,  # Title too long
                "content": "Test question content",
                "course_id": 1
            }
        ]
        
        for i, invalid_data in enumerate(invalid_question_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/questions",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 422:
                    self.log_test(f"Question Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"Question Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Question Validation Test {i+1}", False, str(e))

    def test_answer_submission_issues(self):
        """Test answer submission issues"""
        print("\n💬 TESTING ANSWER SUBMISSION ISSUES")
        print("=" * 50)
        
        # Test answer submission without authentication
        answer_data = {
            "content": "Test answer content",
            "question_id": 1
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/answers", json=answer_data)
            if response.status_code == 401:
                self.log_test("Answer Submission Without Auth", True, "Correctly rejected unauthorized submission")
            else:
                self.log_test("Answer Submission Without Auth", False, f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Answer Submission Without Auth", False, str(e))

    def test_answer_validation(self):
        """Test answer data validation"""
        print("\n💬 TESTING ANSWER VALIDATION")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Answer Validation Setup", False, "Moderator login failed")
            return
        
        # Test invalid answer data
        invalid_answer_data = [
            {
                "content": "",  # Empty content
                "question_id": 1
            },
            {
                "content": "Test answer content",
                "question_id": None  # Invalid question_id
            },
            {
                "content": "A" * 1001,  # Content too long
                "question_id": 1
            }
        ]
        
        for i, invalid_data in enumerate(invalid_answer_data):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/answers",
                    json=invalid_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 422:
                    self.log_test(f"Answer Validation {i+1}", True, f"Correctly rejected invalid data")
                else:
                    self.log_test(f"Answer Validation {i+1}", False, f"Expected 422, got {response.status_code}")
            except Exception as e:
                self.log_test(f"Answer Validation Test {i+1}", False, str(e))

    def test_question_crud_operations(self):
        """Test question CRUD operations with proper authentication"""
        print("\n❓ TESTING QUESTION CRUD OPERATIONS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Question CRUD Setup", False, "Moderator login failed")
            return
        
        timestamp = int(time.time())
        question_data = {
            "title": f"Test Question {timestamp}",
            "content": f"Test question content {timestamp}",
            "course_id": 1
        }
        
        try:
            # Create question
            create_response = self.session.post(
                f"{self.base_url}/api/questions",
                json=question_data,
                headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
            )
            if create_response.status_code == 200:
                create_data = create_response.json()
                question_id = create_data["id"]
                self.cleanup_questions.append(question_id)
                
                # Read question
                read_response = self.session.get(
                    f"{self.base_url}/api/questions/{question_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if read_response.status_code == 200:
                    self.log_test("Question Read", True, "Successfully read question")
                else:
                    self.log_test("Question Read", False, f"Failed to read question: {read_response.status_code}")
                
                # Update question
                update_data = {
                    "title": f"Updated Question {timestamp}",
                    "content": f"Updated content {timestamp}"
                }
                update_response = self.session.put(
                    f"{self.base_url}/api/questions/{question_id}",
                    json=update_data,
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if update_response.status_code == 200:
                    self.log_test("Question Update", True, "Successfully updated question")
                else:
                    self.log_test("Question Update", False, f"Failed to update question: {update_response.status_code}")
                
                # Delete question
                delete_response = self.session.delete(
                    f"{self.base_url}/api/questions/{question_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if delete_response.status_code == 200:
                    self.log_test("Question Delete", True, "Successfully deleted question")
                    self.cleanup_questions.remove(question_id)  # Already deleted
                else:
                    self.log_test("Question Delete", False, f"Failed to delete question: {delete_response.status_code}")
            else:
                self.log_test("Question Create", False, f"Failed to create question: {create_response.status_code}")
        except Exception as e:
            self.log_test("Question CRUD Operations", False, str(e))

    def test_question_listing_with_filters(self):
        """Test question listing with various filters"""
        print("\n❓ TESTING QUESTION LISTING WITH FILTERS")
        print("=" * 50)
        
        if not self.setup_moderator():
            self.log_test("Question Listing Setup", False, "Moderator login failed")
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
                    f"{self.base_url}/api/questions{filter_param}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code in [200, 404]:
                    self.log_test(f"Question Listing Filter {i+1}", True, f"Successfully handled filter: {filter_param}")
                else:
                    self.log_test(f"Question Listing Filter {i+1}", False, f"Failed with filter {filter_param}: {response.status_code}")
            except Exception as e:
                self.log_test(f"Question Listing Filter Test {i+1}", False, str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 CLEANING UP TEST DATA")
        print("=" * 50)
        
        if not self.setup_moderator():
            print("❌ Cannot cleanup - moderator login failed")
            return
        
        for question_id in self.cleanup_questions:
            try:
                response = self.session.delete(
                    f"{self.base_url}/api/questions/{question_id}",
                    headers={"Authorization": f"Bearer {self.tokens['moderator']}"}
                )
                if response.status_code == 200:
                    print(f"✅ Cleaned up question {question_id}")
                else:
                    print(f"❌ Failed to cleanup question {question_id}: {response.status_code}")
            except Exception as e:
                print(f"❌ Error cleaning up question {question_id}: {e}")

    def run_questions_answers_tests(self):
        """Run all questions and answers failure tests"""
        print("❓ RUNNING QUESTIONS & ANSWERS FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Questions & Answers failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all questions and answers tests
        self.test_question_creation_without_token()
        self.test_question_creation_with_invalid_token()
        self.test_question_access_control()
        self.test_question_validation()
        self.test_answer_submission_issues()
        self.test_answer_validation()
        self.test_question_crud_operations()
        self.test_question_listing_with_filters()
        
        # Cleanup
        self.cleanup_test_data()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 QUESTIONS & ANSWERS FAILURE TESTS SUMMARY")
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
    # Run the questions and answers failure tests
    test_suite = QuestionsAnswersFailuresTest()
    results = test_suite.run_questions_answers_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 