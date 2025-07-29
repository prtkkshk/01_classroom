#!/usr/bin/env python3
"""
SIMPLE TEST RUNNER FOR CLASSROOM LIVE APP
=========================================

A simplified test runner that focuses on core API functionality
without WebSocket dependencies.
"""

import requests
import json
import time
from datetime import datetime

class SimpleTestRunner:
    def __init__(self, base_url: str = "https://zero1-classroom-1.onrender.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.tokens = {}
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
    
    def log_test(self, test_name: str, success: bool, details: str = ""):
        status = "PASS" if success else "FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        
        if success:
            self.test_results["passed"] += 1
        else:
            self.test_results["failed"] += 1
            self.test_results["errors"].append(f"{test_name}: {details}")
    
    def test_health_check(self):
        """Test basic health and info endpoints"""
        print("\nHEALTH CHECK TESTS")
        print("=" * 50)
        
        # Test health endpoint
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                self.log_test("Health Check", True, f"Status: {data.get('status', 'unknown')}")
            else:
                self.log_test("Health Check", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Health Check", False, str(e))
        
        # Test info endpoint
        try:
            response = self.session.get(f"{self.base_url}/api/info")
            if response.status_code == 200:
                data = response.json()
                self.log_test("API Info", True, f"Version: {data.get('version', 'unknown')}")
            else:
                self.log_test("API Info", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("API Info", False, str(e))
    
    def test_authentication(self):
        """Test authentication"""
        print("\nAUTHENTICATION TESTS")
        print("=" * 50)
        
        # Test moderator login
        login_data = {
            "username": "pepper_moderator",
            "password": "pepper_14627912"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/login", json=login_data)
            if response.status_code == 200:
                data = response.json()
                self.tokens["moderator"] = data["access_token"]
                self.log_test("Moderator Login", True, f"User: {data['user']['name']}")
            else:
                self.log_test("Moderator Login", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Moderator Login", False, str(e))
        
        # Test invalid login
        try:
            response = self.session.post(f"{self.base_url}/api/login", 
                                       json={"username": "invalid", "password": "wrong"})
            self.log_test("Invalid Login", response.status_code == 401, 
                         f"Expected 401, got {response.status_code}")
        except Exception as e:
            self.log_test("Invalid Login", False, str(e))
    
    def test_user_management(self):
        """Test user management features"""
        print("\nUSER MANAGEMENT TESTS")
        print("=" * 50)
        
        if "moderator" not in self.tokens:
            self.log_test("User Management", False, "No moderator token available")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['moderator']}"}
        
        # Test get all users
        try:
            response = self.session.get(f"{self.base_url}/api/admin/users", headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Get All Users", True, f"Found {data['total_count']} users")
            else:
                self.log_test("Get All Users", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Get All Users", False, str(e))
        
        # Test create professor
        timestamp = int(time.time())
        professor_data = {
            "name": f"Test Professor {timestamp}",
            "userid": f"testprof{timestamp}",
            "email": f"testprof{timestamp}@university.edu",
            "password": "password123"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/admin/create-professor", 
                                       json=professor_data, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.tokens["test_professor"] = data["access_token"]
                self.log_test("Create Professor", True, f"Professor: {data['user']['name']}")
            else:
                self.log_test("Create Professor", False, f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            self.log_test("Create Professor", False, str(e))
    
    def test_course_management(self):
        """Test course management"""
        print("\nCOURSE MANAGEMENT TESTS")
        print("=" * 50)
        
        if "test_professor" not in self.tokens:
            self.log_test("Course Management", False, "No professor token available")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['test_professor']}"}
        
        # Test create course
        course_data = {"name": "Test Course - Advanced Mathematics"}
        
        try:
            response = self.session.post(f"{self.base_url}/api/courses", 
                                       json=course_data, headers=headers)
            if response.status_code == 200:
                data = response.json()
                self.log_test("Create Course", True, f"Course: {data['name']}, Code: {data['code']}")
            else:
                self.log_test("Create Course", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Create Course", False, str(e))
        
        # Test get courses
        try:
            response = self.session.get(f"{self.base_url}/api/courses", headers=headers)
            if response.status_code == 200:
                courses = response.json()
                self.log_test("Get Courses", True, f"Found {len(courses)} courses")
            else:
                self.log_test("Get Courses", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Get Courses", False, str(e))
    
    def test_questions(self):
        """Test questions functionality"""
        print("\nQUESTIONS TESTS")
        print("=" * 50)
        
        if "test_professor" not in self.tokens:
            self.log_test("Questions", False, "No professor token available")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['test_professor']}"}
        
        # First get a course to use for questions
        try:
            response = self.session.get(f"{self.base_url}/api/courses", headers=headers)
            if response.status_code == 200:
                courses = response.json()
                if courses:
                    course_id = courses[0]["id"]
                    
                    # Test create question
                    question_data = {
                        "question_text": "What is the derivative of x²?",
                        "course_id": course_id,
                        "is_anonymous": False,
                        "tags": ["calculus", "derivatives"]
                    }
                    
                    try:
                        response = self.session.post(f"{self.base_url}/api/questions", 
                                                   json=question_data, headers=headers)
                        if response.status_code == 200:
                            data = response.json()
                            self.log_test("Create Question", True, f"Question ID: {data['id']}")
                        else:
                            self.log_test("Create Question", False, f"Status: {response.status_code}")
                    except Exception as e:
                        self.log_test("Create Question", False, str(e))
                    
                    # Test get questions
                    try:
                        response = self.session.get(f"{self.base_url}/api/questions?course_id={course_id}", 
                                                  headers=headers)
                        if response.status_code == 200:
                            questions = response.json()
                            self.log_test("Get Questions", True, f"Found {len(questions)} questions")
                        else:
                            self.log_test("Get Questions", False, f"Status: {response.status_code}")
                    except Exception as e:
                        self.log_test("Get Questions", False, str(e))
                else:
                    self.log_test("Questions", False, "No courses available for testing")
            else:
                self.log_test("Questions", False, "Failed to get courses")
        except Exception as e:
            self.log_test("Questions", False, str(e))
    
    def test_polls(self):
        """Test polls functionality"""
        print("\nPOLLS TESTS")
        print("=" * 50)
        
        if "test_professor" not in self.tokens:
            self.log_test("Polls", False, "No professor token available")
            return
        
        headers = {"Authorization": f"Bearer {self.tokens['test_professor']}"}
        
        # Get a course for polls
        try:
            response = self.session.get(f"{self.base_url}/api/courses", headers=headers)
            if response.status_code == 200:
                courses = response.json()
                if courses:
                    course_id = courses[0]["id"]
                    
                    # Test create poll
                    poll_data = {
                        "question": "What is your preferred exam format?",
                        "options": ["Multiple Choice", "Essay", "Open Book", "Take Home"],
                        "course_id": course_id,
                        "is_anonymous": False,
                        "allow_multiple": False,
                        "expires_minutes": 60
                    }
                    
                    try:
                        response = self.session.post(f"{self.base_url}/api/polls", 
                                                   json=poll_data, headers=headers)
                        if response.status_code == 200:
                            data = response.json()
                            self.log_test("Create Poll", True, f"Poll ID: {data['id']}")
                        else:
                            self.log_test("Create Poll", False, f"Status: {response.status_code}")
                    except Exception as e:
                        self.log_test("Create Poll", False, str(e))
                    
                    # Test get polls
                    try:
                        response = self.session.get(f"{self.base_url}/api/polls?course_id={course_id}", 
                                                  headers=headers)
                        if response.status_code == 200:
                            polls = response.json()
                            self.log_test("Get Polls", True, f"Found {len(polls)} polls")
                        else:
                            self.log_test("Get Polls", False, f"Status: {response.status_code}")
                    except Exception as e:
                        self.log_test("Get Polls", False, str(e))
                else:
                    self.log_test("Polls", False, "No courses available for testing")
            else:
                self.log_test("Polls", False, "Failed to get courses")
        except Exception as e:
            self.log_test("Polls", False, str(e))
    
    def run_all_tests(self):
        """Run all tests"""
        print("STARTING SIMPLE TEST SUITE FOR CLASSROOM LIVE APP")
        print("=" * 60)
        print(f"Started at: {datetime.now()}")
        print(f"Testing: {self.base_url}")
        print("=" * 60)
        
        self.test_health_check()
        self.test_authentication()
        self.test_user_management()
        self.test_course_management()
        self.test_questions()
        self.test_polls()
        
        # Print summary
        print("\nTEST SUMMARY")
        print("=" * 60)
        print(f"Passed: {self.test_results['passed']}")
        print(f"Failed: {self.test_results['failed']}")
        total = self.test_results['passed'] + self.test_results['failed']
        if total > 0:
            success_rate = (self.test_results['passed'] / total * 100)
            print(f"Success Rate: {success_rate:.1f}%")
        
        if self.test_results['errors']:
            print(f"\nErrors:")
            for error in self.test_results['errors']:
                print(f"  - {error}")
        
        print(f"\nTest completed at: {datetime.now()}")

if __name__ == "__main__":
    SimpleTestRunner().run_all_tests() 