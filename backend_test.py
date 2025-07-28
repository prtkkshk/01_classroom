#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Classroom Application
Tests all backend APIs including authentication, questions, and polls
"""

import requests
import json
import uuid
from datetime import datetime
import time

# Configuration
BACKEND_URL = "https://123660c7-3383-48f2-abdb-5d93cf8eb20e.preview.emergentagent.com/api"
PROFESSOR_USERNAME = "professor60201"
PROFESSOR_PASSWORD = "60201professor"
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

class ClassroomAPITester:
    def __init__(self):
        self.session = requests.Session()
        self.student_token = None
        self.professor_token = None
        self.moderator_token = None
        self.test_student_username = f"teststudent_{uuid.uuid4().hex[:8]}"
        self.test_student_email = f"test_{uuid.uuid4().hex[:8]}@student.com"
        self.test_student_password = "TestPassword123!"
        self.created_question_id = None
        self.created_poll_id = None
        self.test_user_id = None
        self.test_vote_id = None
        self.admin_test_question_id = None
        
    def log_test(self, test_name, success, message=""):
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        return success
    
    def test_student_registration(self):
        """Test student registration functionality"""
        try:
            payload = {
                "username": self.test_student_username,
                "email": self.test_student_email,
                "password": self.test_student_password
            }
            
            response = self.session.post(f"{BACKEND_URL}/register", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.student_token = data["access_token"]
                    user = data["user"]
                    if user["role"] == "student" and user["username"] == self.test_student_username:
                        return self.log_test("Student Registration", True, f"Successfully registered student: {user['username']}")
                    else:
                        return self.log_test("Student Registration", False, f"Invalid user data returned: {user}")
                else:
                    return self.log_test("Student Registration", False, f"Missing token or user in response: {data}")
            else:
                return self.log_test("Student Registration", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Student Registration", False, f"Exception: {str(e)}")
    
    def test_student_login(self):
        """Test student login functionality"""
        try:
            payload = {
                "username": self.test_student_username,
                "password": self.test_student_password
            }
            
            response = self.session.post(f"{BACKEND_URL}/login", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.student_token = data["access_token"]
                    user = data["user"]
                    if user["role"] == "student":
                        return self.log_test("Student Login", True, f"Successfully logged in student: {user['username']}")
                    else:
                        return self.log_test("Student Login", False, f"Invalid role: {user['role']}")
                else:
                    return self.log_test("Student Login", False, f"Missing token or user in response")
            else:
                return self.log_test("Student Login", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Student Login", False, f"Exception: {str(e)}")
    
    def test_professor_login(self):
        """Test professor login with hardcoded credentials"""
        try:
            payload = {
                "username": PROFESSOR_USERNAME,
                "password": PROFESSOR_PASSWORD
            }
            
            response = self.session.post(f"{BACKEND_URL}/login", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.professor_token = data["access_token"]
                    user = data["user"]
                    if user["role"] == "professor" and user["username"] == PROFESSOR_USERNAME:
                        return self.log_test("Professor Login", True, f"Successfully logged in professor: {user['username']}")
                    else:
                        return self.log_test("Professor Login", False, f"Invalid professor data: {user}")
                else:
                    return self.log_test("Professor Login", False, f"Missing token or user in response")
            else:
                return self.log_test("Professor Login", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Professor Login", False, f"Exception: {str(e)}")
    
    def test_moderator_login(self):
        """Test moderator login with hardcoded credentials"""
        try:
            payload = {
                "username": MODERATOR_USERNAME,
                "password": MODERATOR_PASSWORD
            }
            
            response = self.session.post(f"{BACKEND_URL}/login", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                if "access_token" in data and "user" in data:
                    self.moderator_token = data["access_token"]
                    user = data["user"]
                    if user["role"] == "moderator" and user["username"] == MODERATOR_USERNAME:
                        return self.log_test("Moderator Login", True, f"Successfully logged in moderator: {user['username']}")
                    else:
                        return self.log_test("Moderator Login", False, f"Invalid moderator data: {user}")
                else:
                    return self.log_test("Moderator Login", False, f"Missing token or user in response")
            else:
                return self.log_test("Moderator Login", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Moderator Login", False, f"Exception: {str(e)}")
    
    def test_admin_get_all_users(self):
        """Test moderator getting all users"""
        try:
            if not self.moderator_token:
                return self.log_test("Admin Get All Users", False, "No moderator token available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.get(f"{BACKEND_URL}/admin/users", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) >= 3:  # Should have student, professor, moderator
                    # Store a test user ID for deletion test (not moderator's own)
                    for user in data:
                        if user["role"] == "student":
                            self.test_user_id = user["id"]
                            break
                    return self.log_test("Admin Get All Users", True, f"Retrieved {len(data)} users")
                else:
                    return self.log_test("Admin Get All Users", False, f"Expected list with users, got: {data}")
            else:
                return self.log_test("Admin Get All Users", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Get All Users", False, f"Exception: {str(e)}")
    
    def test_admin_get_stats(self):
        """Test moderator getting system statistics"""
        try:
            if not self.moderator_token:
                return self.log_test("Admin Get Stats", False, "No moderator token available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.get(f"{BACKEND_URL}/admin/stats", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["total_users", "students", "professors", "moderators", 
                                 "total_questions", "answered_questions", "unanswered_questions",
                                 "total_polls", "total_votes"]
                
                if all(field in data for field in required_fields):
                    return self.log_test("Admin Get Stats", True, f"Retrieved system stats: {data['total_users']} users, {data['total_questions']} questions")
                else:
                    return self.log_test("Admin Get Stats", False, f"Missing required fields in stats: {data}")
            else:
                return self.log_test("Admin Get Stats", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Get Stats", False, f"Exception: {str(e)}")
    
    def test_admin_update_any_question(self):
        """Test moderator updating any question"""
        try:
            if not self.moderator_token or not self.admin_test_question_id:
                return self.log_test("Admin Update Any Question", False, "No moderator token or admin test question ID available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            payload = {
                "question_text": "MODERATOR UPDATED: What is the difference between machine learning and deep learning?",
                "is_answered": True
            }
            
            response = self.session.put(f"{BACKEND_URL}/admin/questions/{self.admin_test_question_id}", 
                                      json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data["question_text"] == payload["question_text"] and data["is_answered"] == True:
                    return self.log_test("Admin Update Any Question", True, f"Moderator successfully updated any question")
                else:
                    return self.log_test("Admin Update Any Question", False, f"Question not updated properly: {data}")
            else:
                return self.log_test("Admin Update Any Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Update Any Question", False, f"Exception: {str(e)}")
    
    def test_admin_delete_any_question(self):
        """Test moderator deleting any question"""
        try:
            if not self.moderator_token or not self.admin_test_question_id:
                return self.log_test("Admin Delete Any Question", False, "No moderator token or admin test question ID available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.delete(f"{BACKEND_URL}/admin/questions/{self.admin_test_question_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "deleted" in data["message"].lower():
                    # Clear the question ID since it's deleted
                    self.admin_test_question_id = None
                    return self.log_test("Admin Delete Any Question", True, f"Moderator successfully deleted any question")
                else:
                    return self.log_test("Admin Delete Any Question", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Admin Delete Any Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Delete Any Question", False, f"Exception: {str(e)}")
    
    def test_admin_get_all_votes(self):
        """Test moderator getting all votes"""
        try:
            if not self.moderator_token:
                return self.log_test("Admin Get All Votes", False, "No moderator token available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.get(f"{BACKEND_URL}/admin/votes", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    # Store a vote ID for deletion test if votes exist
                    if len(data) > 0:
                        self.test_vote_id = data[0]["id"]
                    return self.log_test("Admin Get All Votes", True, f"Retrieved {len(data)} votes")
                else:
                    return self.log_test("Admin Get All Votes", False, f"Expected list of votes, got: {data}")
            else:
                return self.log_test("Admin Get All Votes", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Get All Votes", False, f"Exception: {str(e)}")
    
    def test_admin_delete_vote(self):
        """Test moderator deleting specific votes"""
        try:
            if not self.moderator_token or not self.test_vote_id:
                return self.log_test("Admin Delete Vote", False, "No moderator token or vote ID available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.delete(f"{BACKEND_URL}/admin/votes/{self.test_vote_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "deleted" in data["message"].lower():
                    return self.log_test("Admin Delete Vote", True, f"Moderator successfully deleted vote")
                else:
                    return self.log_test("Admin Delete Vote", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Admin Delete Vote", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Delete Vote", False, f"Exception: {str(e)}")
    
    def test_admin_delete_poll_and_votes(self):
        """Test moderator deleting any poll and associated votes"""
        try:
            if not self.moderator_token or not self.created_poll_id:
                return self.log_test("Admin Delete Poll and Votes", False, "No moderator token or poll ID available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.delete(f"{BACKEND_URL}/admin/polls/{self.created_poll_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "deleted" in data["message"].lower():
                    # Clear the poll ID since it's deleted
                    self.created_poll_id = None
                    return self.log_test("Admin Delete Poll and Votes", True, f"Moderator successfully deleted poll and associated votes")
                else:
                    return self.log_test("Admin Delete Poll and Votes", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Admin Delete Poll and Votes", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Delete Poll and Votes", False, f"Exception: {str(e)}")
    
    def test_admin_delete_user(self):
        """Test moderator deleting any user (except own account)"""
        try:
            if not self.moderator_token or not self.test_user_id:
                return self.log_test("Admin Delete User", False, "No moderator token or user ID available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.delete(f"{BACKEND_URL}/admin/users/{self.test_user_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "deleted" in data["message"].lower():
                    return self.log_test("Admin Delete User", True, f"Moderator successfully deleted user")
                else:
                    return self.log_test("Admin Delete User", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Admin Delete User", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Delete User", False, f"Exception: {str(e)}")
    
    def test_admin_cannot_delete_own_account(self):
        """Test that moderator cannot delete their own account"""
        try:
            if not self.moderator_token:
                return self.log_test("Admin Cannot Delete Own Account", False, "No moderator token available")
            
            # First get moderator's own user ID
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            response = self.session.get(f"{BACKEND_URL}/admin/users", headers=headers)
            
            if response.status_code != 200:
                return self.log_test("Admin Cannot Delete Own Account", False, "Could not get user list")
            
            users = response.json()
            moderator_id = None
            for user in users:
                if user["username"] == MODERATOR_USERNAME:
                    moderator_id = user["id"]
                    break
            
            if not moderator_id:
                return self.log_test("Admin Cannot Delete Own Account", False, "Could not find moderator's user ID")
            
            # Try to delete own account
            response = self.session.delete(f"{BACKEND_URL}/admin/users/{moderator_id}", headers=headers)
            
            if response.status_code == 400:
                data = response.json()
                if "cannot delete your own account" in data.get("detail", "").lower():
                    return self.log_test("Admin Cannot Delete Own Account", True, f"Correctly prevented moderator from deleting own account")
                else:
                    return self.log_test("Admin Cannot Delete Own Account", False, f"Wrong error message: {data}")
            else:
                return self.log_test("Admin Cannot Delete Own Account", False, f"Expected HTTP 400, got {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Admin Cannot Delete Own Account", False, f"Exception: {str(e)}")
    
    def test_admin_unauthorized_access(self):
        """Test that only moderators can access admin endpoints"""
        try:
            # Test student trying to access admin endpoints
            student_unauthorized = True
            if self.student_token:
                headers = {"Authorization": f"Bearer {self.student_token}"}
                response = self.session.get(f"{BACKEND_URL}/admin/users", headers=headers)
                if response.status_code != 403:
                    student_unauthorized = False
            
            # Test professor trying to access admin endpoints
            professor_unauthorized = True
            if self.professor_token:
                headers = {"Authorization": f"Bearer {self.professor_token}"}
                response = self.session.get(f"{BACKEND_URL}/admin/stats", headers=headers)
                if response.status_code != 403:
                    professor_unauthorized = False
            
            # Test accessing admin endpoints without token
            no_token_unauthorized = True
            response = self.session.get(f"{BACKEND_URL}/admin/users")
            if response.status_code not in [401, 403]:
                no_token_unauthorized = False
            
            if student_unauthorized and professor_unauthorized and no_token_unauthorized:
                return self.log_test("Admin Unauthorized Access", True, "All unauthorized admin access attempts properly blocked")
            else:
                return self.log_test("Admin Unauthorized Access", False, f"Some unauthorized admin access not blocked: student={student_unauthorized}, professor={professor_unauthorized}, no_token={no_token_unauthorized}")
                
        except Exception as e:
            return self.log_test("Admin Unauthorized Access", False, f"Exception: {str(e)}")
    
    def test_admin_edge_cases(self):
        """Test admin endpoints with non-existent entities"""
        try:
            if not self.moderator_token:
                return self.log_test("Admin Edge Cases", False, "No moderator token available")
            
            headers = {"Authorization": f"Bearer {self.moderator_token}"}
            fake_id = str(uuid.uuid4())
            
            # Test deleting non-existent user
            response1 = self.session.delete(f"{BACKEND_URL}/admin/users/{fake_id}", headers=headers)
            test1_pass = response1.status_code == 404
            
            # Test deleting non-existent question
            response2 = self.session.delete(f"{BACKEND_URL}/admin/questions/{fake_id}", headers=headers)
            test2_pass = response2.status_code == 404
            
            # Test deleting non-existent poll
            response3 = self.session.delete(f"{BACKEND_URL}/admin/polls/{fake_id}", headers=headers)
            test3_pass = response3.status_code == 404
            
            # Test deleting non-existent vote
            response4 = self.session.delete(f"{BACKEND_URL}/admin/votes/{fake_id}", headers=headers)
            test4_pass = response4.status_code == 404
            
            # Test updating non-existent question
            response5 = self.session.put(f"{BACKEND_URL}/admin/questions/{fake_id}", 
                                       json={"question_text": "test"}, headers=headers)
            test5_pass = response5.status_code == 404
            
            if all([test1_pass, test2_pass, test3_pass, test4_pass, test5_pass]):
                return self.log_test("Admin Edge Cases", True, "All non-existent entity operations correctly return 404")
            else:
                return self.log_test("Admin Edge Cases", False, f"Some edge cases failed: user={test1_pass}, question={test2_pass}, poll={test3_pass}, vote={test4_pass}, update={test5_pass}")
                
        except Exception as e:
            return self.log_test("Admin Edge Cases", False, f"Exception: {str(e)}")
    
    def test_create_question_for_admin_tests(self):
        """Create a separate question for admin testing"""
        try:
            if not self.student_token:
                return self.log_test("Create Question for Admin Tests", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "question_text": "This question will be used for admin testing purposes",
                "is_anonymous": False
            }
            
            response = self.session.post(f"{BACKEND_URL}/questions", json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data:
                    # Store this as a separate ID for admin tests
                    self.admin_test_question_id = data["id"]
                    return self.log_test("Create Question for Admin Tests", True, f"Created admin test question with ID: {data['id']}")
                else:
                    return self.log_test("Create Question for Admin Tests", False, f"Invalid question data: {data}")
            else:
                return self.log_test("Create Question for Admin Tests", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Create Question for Admin Tests", False, f"Exception: {str(e)}")
    
    
        except Exception as e:
            return self.log_test("Admin Edge Cases", False, f"Exception: {str(e)}")
    
    
    def test_create_named_question(self):
        """Test creating a named question as student"""
        try:
            if not self.student_token:
                return self.log_test("Create Named Question", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "question_text": "What is the difference between machine learning and deep learning?",
                "is_anonymous": False
            }
            
            response = self.session.post(f"{BACKEND_URL}/questions", json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data and data["question_text"] == payload["question_text"]:
                    self.created_question_id = data["id"]
                    return self.log_test("Create Named Question", True, f"Created question with ID: {data['id']}")
                else:
                    return self.log_test("Create Named Question", False, f"Invalid question data: {data}")
            else:
                return self.log_test("Create Named Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Create Named Question", False, f"Exception: {str(e)}")
    
    def test_create_anonymous_question(self):
        """Test creating an anonymous question as student"""
        try:
            if not self.student_token:
                return self.log_test("Create Anonymous Question", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "question_text": "How do I prepare for technical interviews?",
                "is_anonymous": True
            }
            
            response = self.session.post(f"{BACKEND_URL}/questions", json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data and data["username"] == "Anonymous":
                    return self.log_test("Create Anonymous Question", True, f"Created anonymous question with ID: {data['id']}")
                else:
                    return self.log_test("Create Anonymous Question", False, f"Question not properly anonymized: {data}")
            else:
                return self.log_test("Create Anonymous Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Create Anonymous Question", False, f"Exception: {str(e)}")
    
    def test_get_all_questions(self):
        """Test retrieving all questions"""
        try:
            if not self.student_token:
                return self.log_test("Get All Questions", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            response = self.session.get(f"{BACKEND_URL}/questions", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) >= 2:  # Should have at least our 2 test questions
                    return self.log_test("Get All Questions", True, f"Retrieved {len(data)} questions")
                else:
                    return self.log_test("Get All Questions", False, f"Expected list with questions, got: {data}")
            else:
                return self.log_test("Get All Questions", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Get All Questions", False, f"Exception: {str(e)}")
    
    def test_get_my_questions(self):
        """Test retrieving student's own questions"""
        try:
            if not self.student_token:
                return self.log_test("Get My Questions", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            response = self.session.get(f"{BACKEND_URL}/questions/my", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) >= 2:  # Should have our 2 test questions
                    return self.log_test("Get My Questions", True, f"Retrieved {len(data)} own questions")
                else:
                    return self.log_test("Get My Questions", False, f"Expected list with own questions, got: {data}")
            else:
                return self.log_test("Get My Questions", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Get My Questions", False, f"Exception: {str(e)}")
    
    def test_update_question(self):
        """Test updating a question as student"""
        try:
            if not self.student_token or not self.created_question_id:
                return self.log_test("Update Question", False, "No student token or question ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "question_text": "What is the difference between machine learning, deep learning, and AI?"
            }
            
            response = self.session.put(f"{BACKEND_URL}/questions/{self.created_question_id}", 
                                      json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data["question_text"] == payload["question_text"]:
                    return self.log_test("Update Question", True, f"Successfully updated question")
                else:
                    return self.log_test("Update Question", False, f"Question not updated properly: {data}")
            else:
                return self.log_test("Update Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Update Question", False, f"Exception: {str(e)}")
    
    def test_mark_question_answered_by_student(self):
        """Test marking question as answered by student (own question)"""
        try:
            if not self.student_token or not self.created_question_id:
                return self.log_test("Mark Question Answered (Student)", False, "No student token or question ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "is_answered": True
            }
            
            response = self.session.put(f"{BACKEND_URL}/questions/{self.created_question_id}", 
                                      json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data["is_answered"] == True:
                    return self.log_test("Mark Question Answered (Student)", True, f"Student marked own question as answered")
                else:
                    return self.log_test("Mark Question Answered (Student)", False, f"Question not marked as answered: {data}")
            else:
                return self.log_test("Mark Question Answered (Student)", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Mark Question Answered (Student)", False, f"Exception: {str(e)}")
    
    def test_mark_question_answered_by_professor(self):
        """Test marking question as answered by professor"""
        try:
            if not self.professor_token or not self.created_question_id:
                return self.log_test("Mark Question Answered (Professor)", False, "No professor token or question ID available")
            
            headers = {"Authorization": f"Bearer {self.professor_token}"}
            payload = {
                "is_answered": False  # Reset to test professor marking
            }
            
            # First reset the question
            response = self.session.put(f"{BACKEND_URL}/questions/{self.created_question_id}", 
                                      json=payload, headers=headers)
            
            if response.status_code == 200:
                # Now mark as answered by professor
                payload["is_answered"] = True
                response = self.session.put(f"{BACKEND_URL}/questions/{self.created_question_id}", 
                                          json=payload, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    if data["is_answered"] == True:
                        return self.log_test("Mark Question Answered (Professor)", True, f"Professor marked question as answered")
                    else:
                        return self.log_test("Mark Question Answered (Professor)", False, f"Question not marked as answered: {data}")
                else:
                    return self.log_test("Mark Question Answered (Professor)", False, f"HTTP {response.status_code}: {response.text}")
            else:
                return self.log_test("Mark Question Answered (Professor)", False, f"Failed to reset question: HTTP {response.status_code}")
                
        except Exception as e:
            return self.log_test("Mark Question Answered (Professor)", False, f"Exception: {str(e)}")
    
    def test_delete_question(self):
        """Test deleting a question as student"""
        try:
            if not self.student_token or not self.created_question_id:
                return self.log_test("Delete Question", False, "No student token or question ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            response = self.session.delete(f"{BACKEND_URL}/questions/{self.created_question_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "deleted" in data["message"].lower():
                    return self.log_test("Delete Question", True, f"Successfully deleted question")
                else:
                    return self.log_test("Delete Question", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Delete Question", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Delete Question", False, f"Exception: {str(e)}")
    
    def test_create_poll(self):
        """Test creating a poll as professor"""
        try:
            if not self.professor_token:
                return self.log_test("Create Poll", False, "No professor token available")
            
            headers = {"Authorization": f"Bearer {self.professor_token}"}
            payload = {
                "question": "Which programming language do you prefer for data science?",
                "options": ["Python", "R", "Julia", "Scala"]
            }
            
            response = self.session.post(f"{BACKEND_URL}/polls", json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "id" in data and data["question"] == payload["question"]:
                    self.created_poll_id = data["id"]
                    return self.log_test("Create Poll", True, f"Created poll with ID: {data['id']}")
                else:
                    return self.log_test("Create Poll", False, f"Invalid poll data: {data}")
            else:
                return self.log_test("Create Poll", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Create Poll", False, f"Exception: {str(e)}")
    
    def test_get_polls(self):
        """Test retrieving all polls"""
        try:
            if not self.student_token:
                return self.log_test("Get Polls", False, "No student token available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            response = self.session.get(f"{BACKEND_URL}/polls", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) >= 1:  # Should have at least our test poll
                    return self.log_test("Get Polls", True, f"Retrieved {len(data)} polls")
                else:
                    return self.log_test("Get Polls", False, f"Expected list with polls, got: {data}")
            else:
                return self.log_test("Get Polls", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Get Polls", False, f"Exception: {str(e)}")
    
    def test_vote_on_poll(self):
        """Test voting on a poll as student"""
        try:
            if not self.student_token or not self.created_poll_id:
                return self.log_test("Vote on Poll", False, "No student token or poll ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "poll_id": self.created_poll_id,
                "option_selected": "Python"
            }
            
            response = self.session.post(f"{BACKEND_URL}/polls/{self.created_poll_id}/vote", 
                                       json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data and "recorded" in data["message"].lower():
                    return self.log_test("Vote on Poll", True, f"Successfully voted on poll")
                else:
                    return self.log_test("Vote on Poll", False, f"Unexpected response: {data}")
            else:
                return self.log_test("Vote on Poll", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Vote on Poll", False, f"Exception: {str(e)}")
    
    def test_duplicate_vote_prevention(self):
        """Test that duplicate voting is prevented"""
        try:
            if not self.student_token or not self.created_poll_id:
                return self.log_test("Duplicate Vote Prevention", False, "No student token or poll ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            payload = {
                "poll_id": self.created_poll_id,
                "option_selected": "R"  # Try to vote again with different option
            }
            
            response = self.session.post(f"{BACKEND_URL}/polls/{self.created_poll_id}/vote", 
                                       json=payload, headers=headers)
            
            if response.status_code == 400:
                data = response.json()
                if "already voted" in data.get("detail", "").lower():
                    return self.log_test("Duplicate Vote Prevention", True, f"Correctly prevented duplicate vote")
                else:
                    return self.log_test("Duplicate Vote Prevention", False, f"Wrong error message: {data}")
            else:
                return self.log_test("Duplicate Vote Prevention", False, f"Expected HTTP 400, got {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Duplicate Vote Prevention", False, f"Exception: {str(e)}")
    
    def test_get_user_vote(self):
        """Test checking user's vote on a poll"""
        try:
            if not self.student_token or not self.created_poll_id:
                return self.log_test("Get User Vote", False, "No student token or poll ID available")
            
            headers = {"Authorization": f"Bearer {self.student_token}"}
            response = self.session.get(f"{BACKEND_URL}/polls/{self.created_poll_id}/user-vote", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("voted") == True and data.get("option") == "Python":
                    return self.log_test("Get User Vote", True, f"Correctly retrieved user vote: {data['option']}")
                else:
                    return self.log_test("Get User Vote", False, f"Unexpected vote data: {data}")
            else:
                return self.log_test("Get User Vote", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Get User Vote", False, f"Exception: {str(e)}")
    
    def test_get_poll_results(self):
        """Test getting poll results as professor"""
        try:
            if not self.professor_token or not self.created_poll_id:
                return self.log_test("Get Poll Results", False, "No professor token or poll ID available")
            
            headers = {"Authorization": f"Bearer {self.professor_token}"}
            response = self.session.get(f"{BACKEND_URL}/polls/{self.created_poll_id}/results", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if "poll" in data and "votes" in data and "total_votes" in data:
                    if data["total_votes"] >= 1 and data["votes"].get("Python", 0) >= 1:
                        return self.log_test("Get Poll Results", True, f"Retrieved poll results: {data['total_votes']} total votes")
                    else:
                        return self.log_test("Get Poll Results", False, f"Vote counts don't match expected: {data}")
                else:
                    return self.log_test("Get Poll Results", False, f"Missing required fields in response: {data}")
            else:
                return self.log_test("Get Poll Results", False, f"HTTP {response.status_code}: {response.text}")
                
        except Exception as e:
            return self.log_test("Get Poll Results", False, f"Exception: {str(e)}")
    
    def test_unauthorized_access(self):
        """Test unauthorized access scenarios"""
        try:
            # Test accessing questions without token
            response = self.session.get(f"{BACKEND_URL}/questions")
            if response.status_code in [401, 403]:  # Both are valid for unauthorized access
                unauthorized_test_1 = True
            else:
                unauthorized_test_1 = False
            
            # Test student trying to create poll
            if self.student_token:
                headers = {"Authorization": f"Bearer {self.student_token}"}
                payload = {
                    "question": "Unauthorized poll",
                    "options": ["Option 1", "Option 2"]
                }
                response = self.session.post(f"{BACKEND_URL}/polls", json=payload, headers=headers)
                if response.status_code == 403:
                    unauthorized_test_2 = True
                else:
                    unauthorized_test_2 = False
            else:
                unauthorized_test_2 = False
            
            # Test professor trying to ask question
            if self.professor_token:
                headers = {"Authorization": f"Bearer {self.professor_token}"}
                payload = {
                    "question_text": "Unauthorized question",
                    "is_anonymous": False
                }
                response = self.session.post(f"{BACKEND_URL}/questions", json=payload, headers=headers)
                if response.status_code == 403:
                    unauthorized_test_3 = True
                else:
                    unauthorized_test_3 = False
            else:
                unauthorized_test_3 = False
            
            if unauthorized_test_1 and unauthorized_test_2 and unauthorized_test_3:
                return self.log_test("Unauthorized Access", True, "All unauthorized access attempts properly blocked")
            else:
                return self.log_test("Unauthorized Access", False, f"Some unauthorized access not blocked: {unauthorized_test_1}, {unauthorized_test_2}, {unauthorized_test_3}")
                
        except Exception as e:
            return self.log_test("Unauthorized Access", False, f"Exception: {str(e)}")
    
    def run_all_tests(self):
        """Run all backend tests in sequence"""
        print("=" * 80)
        print("CLASSROOM APPLICATION BACKEND TESTING - INCLUDING MODERATOR FUNCTIONALITY")
        print("=" * 80)
        print(f"Backend URL: {BACKEND_URL}")
        print(f"Test Student: {self.test_student_username}")
        print(f"Professor Credentials: {PROFESSOR_USERNAME}/{PROFESSOR_PASSWORD}")
        print(f"Moderator Credentials: {MODERATOR_USERNAME}/{MODERATOR_PASSWORD}")
        print("=" * 80)
        
        test_results = []
        
        # Authentication Tests
        print("\n🔐 AUTHENTICATION TESTS")
        print("-" * 40)
        test_results.append(self.test_student_registration())
        test_results.append(self.test_student_login())
        test_results.append(self.test_professor_login())
        test_results.append(self.test_moderator_login())
        
        # Admin/Moderator Tests
        print("\n👑 MODERATOR ADMIN TESTS")
        print("-" * 40)
        test_results.append(self.test_admin_get_all_users())
        test_results.append(self.test_admin_get_stats())
        test_results.append(self.test_admin_unauthorized_access())
        test_results.append(self.test_admin_cannot_delete_own_account())
        test_results.append(self.test_admin_edge_cases())
        
        # Questions CRUD Tests
        print("\n❓ QUESTIONS CRUD TESTS")
        print("-" * 40)
        test_results.append(self.test_create_named_question())
        test_results.append(self.test_create_anonymous_question())
        test_results.append(self.test_get_all_questions())
        test_results.append(self.test_get_my_questions())
        test_results.append(self.test_update_question())
        test_results.append(self.test_mark_question_answered_by_student())
        test_results.append(self.test_mark_question_answered_by_professor())
        test_results.append(self.test_delete_question())
        
        # Admin Question Management Tests
        print("\n👑 ADMIN QUESTION MANAGEMENT")
        print("-" * 40)
        test_results.append(self.test_create_question_for_admin_tests())
        test_results.append(self.test_admin_update_any_question())
        test_results.append(self.test_admin_delete_any_question())
        
        # Polls Management Tests
        print("\n📊 POLLS MANAGEMENT TESTS")
        print("-" * 40)
        test_results.append(self.test_create_poll())
        test_results.append(self.test_get_polls())
        test_results.append(self.test_vote_on_poll())
        test_results.append(self.test_duplicate_vote_prevention())
        test_results.append(self.test_get_user_vote())
        test_results.append(self.test_get_poll_results())
        
        # Admin Polls and Votes Management Tests
        print("\n👑 ADMIN POLLS & VOTES MANAGEMENT")
        print("-" * 40)
        test_results.append(self.test_admin_get_all_votes())
        test_results.append(self.test_admin_delete_vote())
        test_results.append(self.test_admin_delete_poll_and_votes())
        
        # Admin User Management Tests
        print("\n👑 ADMIN USER MANAGEMENT")
        print("-" * 40)
        test_results.append(self.test_admin_delete_user())
        
        # Security Tests
        print("\n🔒 SECURITY TESTS")
        print("-" * 40)
        test_results.append(self.test_unauthorized_access())
        
        # Summary
        print("\n" + "=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        passed = sum(test_results)
        total = len(test_results)
        print(f"Tests Passed: {passed}/{total}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 ALL TESTS PASSED! Backend including moderator functionality is working correctly.")
        else:
            print(f"⚠️  {total-passed} tests failed. Please check the issues above.")
        
        return passed == total

if __name__ == "__main__":
    tester = ClassroomAPITester()
    success = tester.run_all_tests()
    exit(0 if success else 1)