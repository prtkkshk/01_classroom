#!/usr/bin/env python3
"""
Test script for student approval functionality
Tests that students can request to join courses and professors can approve/reject them
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api"

def print_test_result(test_name, success, message=""):
    """Print test result with formatting"""
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} {test_name}")
    if message:
        print(f"   {message}")
    print()

def test_student_approval_functionality():
    """Test the student approval functionality"""
    print("🧪 Testing Student Approval Functionality")
    print("=" * 50)
    
    # Test 1: Student requests to join course
    print("Test 1: Student requesting to join course")
    try:
        # Login as professor
        professor_login = {
            "email": "professor@test.com",
            "password": "testpass123"
        }
        
        response = requests.post(f"{API_BASE}/login", json=professor_login)
        if response.status_code != 200:
            print_test_result("Professor Login", False, f"Login failed: {response.text}")
            return
        
        professor_token = response.json()["access_token"]
        professor_headers = {"Authorization": f"Bearer {professor_token}"}
        
        # Create a course for the professor
        course_data = {"name": "Test Course for Student Approval"}
        response = requests.post(f"{API_BASE}/courses", json=course_data, headers=professor_headers)
        if response.status_code != 200:
            print_test_result("Course Creation", False, f"Course creation failed: {response.text}")
            return
        
        course = response.json()
        course_id = course["id"]
        course_code = course["code"]
        print_test_result("Course Creation", True, f"Created course: {course['name']} with code: {course_code}")
        
        # Register a student
        student_data = {
            "name": "Test Student",
            "roll_number": "STU001",
            "email": "student@test.com",
            "password": "testpass123"
        }
        
        response = requests.post(f"{API_BASE}/register", json=student_data)
        if response.status_code != 200:
            print_test_result("Student Registration", False, f"Student registration failed: {response.text}")
            return
        
        student_token = response.json()["access_token"]
        student_headers = {"Authorization": f"Bearer {student_token}"}
        
        # Student requests to join course
        join_data = {"code": course_code}
        response = requests.post(f"{API_BASE}/courses/join", json=join_data, headers=student_headers)
        if response.status_code == 200:
            print_test_result("Student Join Request", True, "Student successfully requested to join course")
        else:
            print_test_result("Student Join Request", False, f"Join request failed: {response.text}")
            return
        
    except Exception as e:
        print_test_result("Student Join Request", False, f"Exception: {str(e)}")
        return
    
    # Test 2: Professor can see pending students
    print("Test 2: Professor can see pending students")
    try:
        response = requests.get(f"{API_BASE}/courses/{course_id}/students", headers=professor_headers)
        if response.status_code == 200:
            data = response.json()
            pending_count = data.get("total_pending", 0)
            if pending_count > 0:
                print_test_result("Professor See Pending Students", True, f"Found {pending_count} pending students")
            else:
                print_test_result("Professor See Pending Students", False, "No pending students found")
        else:
            print_test_result("Professor See Pending Students", False, f"Failed to get students: {response.text}")
    except Exception as e:
        print_test_result("Professor See Pending Students", False, f"Exception: {str(e)}")
    
    # Test 3: Professor approves student
    print("Test 3: Professor approves student")
    try:
        # Get student info from pending list
        response = requests.get(f"{API_BASE}/courses/{course_id}/students", headers=professor_headers)
        if response.status_code == 200:
            data = response.json()
            pending_students = data.get("pending_students", [])
            if pending_students:
                student_id = pending_students[0]["id"]
                
                # Approve the student
                response = requests.post(f"{API_BASE}/courses/{course_id}/students/{student_id}/approve", headers=professor_headers)
                if response.status_code == 200:
                    print_test_result("Professor Approve Student", True, "Student approved successfully")
                else:
                    print_test_result("Professor Approve Student", False, f"Approval failed: {response.text}")
            else:
                print_test_result("Professor Approve Student", False, "No pending students to approve")
        else:
            print_test_result("Professor Approve Student", False, f"Failed to get students: {response.text}")
    except Exception as e:
        print_test_result("Professor Approve Student", False, f"Exception: {str(e)}")
    
    # Test 4: Verify student is now enrolled
    print("Test 4: Verify student is now enrolled")
    try:
        response = requests.get(f"{API_BASE}/courses/{course_id}/students", headers=professor_headers)
        if response.status_code == 200:
            data = response.json()
            enrolled_count = data.get("total_enrolled", 0)
            pending_count = data.get("total_pending", 0)
            
            if enrolled_count > 0 and pending_count == 0:
                print_test_result("Student Enrollment Verification", True, f"Student enrolled: {enrolled_count} enrolled, {pending_count} pending")
            else:
                print_test_result("Student Enrollment Verification", False, f"Enrollment verification failed: {enrolled_count} enrolled, {pending_count} pending")
        else:
            print_test_result("Student Enrollment Verification", False, f"Failed to get students: {response.text}")
    except Exception as e:
        print_test_result("Student Enrollment Verification", False, f"Exception: {str(e)}")
    
    # Test 5: Professor can remove enrolled student
    print("Test 5: Professor can remove enrolled student")
    try:
        response = requests.get(f"{API_BASE}/courses/{course_id}/students", headers=professor_headers)
        if response.status_code == 200:
            data = response.json()
            enrolled_students = data.get("enrolled_students", [])
            if enrolled_students:
                student_id = enrolled_students[0]["id"]
                
                # Remove the student
                response = requests.delete(f"{API_BASE}/courses/{course_id}/students/{student_id}", headers=professor_headers)
                if response.status_code == 200:
                    print_test_result("Professor Remove Student", True, "Student removed successfully")
                else:
                    print_test_result("Professor Remove Student", False, f"Removal failed: {response.text}")
            else:
                print_test_result("Professor Remove Student", False, "No enrolled students to remove")
        else:
            print_test_result("Professor Remove Student", False, f"Failed to get students: {response.text}")
    except Exception as e:
        print_test_result("Professor Remove Student", False, f"Exception: {str(e)}")
    
    # Test 6: Student cannot approve themselves
    print("Test 6: Student cannot approve themselves")
    try:
        # Student tries to approve themselves (should fail)
        response = requests.post(f"{API_BASE}/courses/{course_id}/students/{student_id}/approve", headers=student_headers)
        if response.status_code == 403:
            print_test_result("Student Cannot Approve", True, "Correctly prevented student from approving")
        else:
            print_test_result("Student Cannot Approve", False, f"Should have been forbidden but got: {response.status_code}")
    except Exception as e:
        print_test_result("Student Cannot Approve", False, f"Exception: {str(e)}")
    
    print("=" * 50)
    print("🎉 Student Approval Functionality Tests Complete!")

if __name__ == "__main__":
    test_student_approval_functionality() 