#!/usr/bin/env python3
"""
Test script for announcement delete functionality
Tests that professors can only delete their own announcements
Tests that moderators can delete any announcement
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

def test_announcement_delete_functionality():
    """Test the announcement delete functionality"""
    print("🧪 Testing Announcement Delete Functionality")
    print("=" * 50)
    
    # Test 1: Professor can delete their own announcement
    print("Test 1: Professor deleting their own announcement")
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
        course_data = {"name": "Test Course for Announcement Delete"}
        response = requests.post(f"{API_BASE}/courses", json=course_data, headers=professor_headers)
        if response.status_code != 200:
            print_test_result("Course Creation", False, f"Course creation failed: {response.text}")
            return
        
        course_id = response.json()["id"]
        
        # Create an announcement
        announcement_data = {
            "title": "Test Announcement for Delete",
            "content": "This announcement will be deleted",
            "course_id": course_id,
            "priority": "normal"
        }
        
        response = requests.post(f"{API_BASE}/announcements", json=announcement_data, headers=professor_headers)
        if response.status_code != 200:
            print_test_result("Announcement Creation", False, f"Announcement creation failed: {response.text}")
            return
        
        announcement_id = response.json()["id"]
        print_test_result("Announcement Creation", True, f"Created announcement: {announcement_id}")
        
        # Delete the announcement
        response = requests.delete(f"{API_BASE}/announcements/{announcement_id}", headers=professor_headers)
        if response.status_code == 200:
            print_test_result("Professor Delete Own Announcement", True, "Professor successfully deleted their own announcement")
        else:
            print_test_result("Professor Delete Own Announcement", False, f"Delete failed: {response.text}")
        
    except Exception as e:
        print_test_result("Professor Delete Own Announcement", False, f"Exception: {str(e)}")
    
    # Test 2: Professor cannot delete another professor's announcement
    print("Test 2: Professor cannot delete another professor's announcement")
    try:
        # Create another professor account
        professor2_data = {
            "name": "Professor 2",
            "userid": "prof2",
            "email": "professor2@test.com",
            "password": "testpass123"
        }
        
        response = requests.post(f"{API_BASE}/admin/professors", json=professor2_data, headers=professor_headers)
        if response.status_code != 200:
            print_test_result("Second Professor Creation", False, f"Professor creation failed: {response.text}")
            return
        
        professor2_token = response.json()["access_token"]
        professor2_headers = {"Authorization": f"Bearer {professor2_token}"}
        
        # Create a course for professor 2
        course2_data = {"name": "Test Course 2"}
        response = requests.post(f"{API_BASE}/courses", json=course2_data, headers=professor2_headers)
        if response.status_code != 200:
            print_test_result("Second Course Creation", False, f"Course creation failed: {response.text}")
            return
        
        course2_id = response.json()["id"]
        
        # Create an announcement by professor 2
        announcement2_data = {
            "title": "Professor 2's Announcement",
            "content": "This announcement belongs to professor 2",
            "course_id": course2_id,
            "priority": "normal"
        }
        
        response = requests.post(f"{API_BASE}/announcements", json=announcement2_data, headers=professor2_headers)
        if response.status_code != 200:
            print_test_result("Second Announcement Creation", False, f"Announcement creation failed: {response.text}")
            return
        
        announcement2_id = response.json()["id"]
        print_test_result("Second Announcement Creation", True, f"Created announcement: {announcement2_id}")
        
        # Try to delete professor 2's announcement with professor 1's token
        response = requests.delete(f"{API_BASE}/announcements/{announcement2_id}", headers=professor_headers)
        if response.status_code == 403:
            print_test_result("Professor Cannot Delete Other's Announcement", True, "Correctly prevented professor from deleting another's announcement")
        else:
            print_test_result("Professor Cannot Delete Other's Announcement", False, f"Should have been forbidden but got: {response.status_code}")
        
    except Exception as e:
        print_test_result("Professor Cannot Delete Other's Announcement", False, f"Exception: {str(e)}")
    
    # Test 3: Moderator can delete any announcement
    print("Test 3: Moderator can delete any announcement")
    try:
        # Login as moderator (assuming moderator account exists)
        moderator_login = {
            "email": "moderator@test.com",
            "password": "testpass123"
        }
        
        response = requests.post(f"{API_BASE}/login", json=moderator_login)
        if response.status_code != 200:
            print_test_result("Moderator Login", False, f"Moderator login failed: {response.text}")
            return
        
        moderator_token = response.json()["access_token"]
        moderator_headers = {"Authorization": f"Bearer {moderator_token}"}
        
        # Create an announcement by professor 2
        announcement3_data = {
            "title": "Announcement for Moderator Delete Test",
            "content": "This announcement will be deleted by moderator",
            "course_id": course2_id,
            "priority": "high"
        }
        
        response = requests.post(f"{API_BASE}/announcements", json=announcement3_data, headers=professor2_headers)
        if response.status_code != 200:
            print_test_result("Third Announcement Creation", False, f"Announcement creation failed: {response.text}")
            return
        
        announcement3_id = response.json()["id"]
        print_test_result("Third Announcement Creation", True, f"Created announcement: {announcement3_id}")
        
        # Delete the announcement using moderator privileges
        response = requests.delete(f"{API_BASE}/admin/announcements/{announcement3_id}", headers=moderator_headers)
        if response.status_code == 200:
            print_test_result("Moderator Delete Any Announcement", True, "Moderator successfully deleted announcement using admin endpoint")
        else:
            print_test_result("Moderator Delete Any Announcement", False, f"Delete failed: {response.text}")
        
    except Exception as e:
        print_test_result("Moderator Delete Any Announcement", False, f"Exception: {str(e)}")
    
    # Test 4: Student cannot delete announcements
    print("Test 4: Student cannot delete announcements")
    try:
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
        
        # Create an announcement by professor 2
        announcement4_data = {
            "title": "Announcement for Student Delete Test",
            "content": "This announcement should not be deletable by student",
            "course_id": course2_id,
            "priority": "normal"
        }
        
        response = requests.post(f"{API_BASE}/announcements", json=announcement4_data, headers=professor2_headers)
        if response.status_code != 200:
            print_test_result("Fourth Announcement Creation", False, f"Announcement creation failed: {response.text}")
            return
        
        announcement4_id = response.json()["id"]
        print_test_result("Fourth Announcement Creation", True, f"Created announcement: {announcement4_id}")
        
        # Try to delete the announcement as a student
        response = requests.delete(f"{API_BASE}/announcements/{announcement4_id}", headers=student_headers)
        if response.status_code == 403:
            print_test_result("Student Cannot Delete Announcement", True, "Correctly prevented student from deleting announcement")
        else:
            print_test_result("Student Cannot Delete Announcement", False, f"Should have been forbidden but got: {response.status_code}")
        
    except Exception as e:
        print_test_result("Student Cannot Delete Announcement", False, f"Exception: {str(e)}")
    
    print("=" * 50)
    print("🎉 Announcement Delete Functionality Tests Complete!")

if __name__ == "__main__":
    test_announcement_delete_functionality() 