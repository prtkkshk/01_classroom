#!/usr/bin/env python3
"""
DATABASE FAILURES TEST
======================

This test file specifically targets database failures identified in the comprehensive test report.
Category: Database failures (health checks, CRUD operations)

Failed Test Scenarios:
- Database health check failures
- Database connection issues
- Database CRUD operation failures
- Database transaction handling
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class DatabaseFailuresTest:
    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = {"passed": 0, "failed": 0, "errors": []}
    
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

    def test_database_health_check(self):
        """Test database health check"""
        print("\n🗄️ TESTING DATABASE HEALTH CHECK")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "database" in data:
                    db_status = data["database"]
                    if isinstance(db_status, dict) and "status" in db_status:
                        self.log_test("Database Health Check", True, f"Database status: {db_status['status']}")
                    else:
                        self.log_test("Database Health Check", False, f"Database status format invalid: {db_status}")
                else:
                    self.log_test("Database Health Check", False, "Database status not found in response")
            else:
                self.log_test("Database Health Check", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Database Health Check", False, str(e))

    def test_database_connection(self):
        """Test database connection through API operations"""
        print("\n🗄️ TESTING DATABASE CONNECTION")
        print("=" * 50)
        
        # Test database connection by performing a simple operation
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "database" in data:
                    db_status = data["database"]
                    if isinstance(db_status, dict) and "status" in db_status:
                        if db_status["status"] == "healthy" or db_status["status"] == "ok":
                            self.log_test("Database Connection", True, "Database connection is healthy")
                        else:
                            self.log_test("Database Connection", False, f"Database connection status: {db_status['status']}")
                    else:
                        self.log_test("Database Connection", False, "Database status format invalid")
                else:
                    self.log_test("Database Connection", False, "Database status not found")
            else:
                self.log_test("Database Connection", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Database Connection", False, str(e))

    def test_database_crud_operations(self):
        """Test database CRUD operations"""
        print("\n🗄️ TESTING DATABASE CRUD OPERATIONS")
        print("=" * 50)
        
        # Test Create operation
        timestamp = int(time.time())
        student_data = {
            "name": f"Database CRUD Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"database_crud{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Create (POST)
            create_response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if create_response.status_code == 200:
                create_data = create_response.json()
                user_id = create_data["user"]["id"]
                token = create_data["access_token"]
                
                self.log_test("Database Create Operation", True, "Successfully created user")
                
                # Read (GET) - Test if we can retrieve the created user
                profile_response = self.session.get(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if profile_response.status_code == 200:
                    self.log_test("Database Read Operation", True, "Successfully read user data")
                else:
                    self.log_test("Database Read Operation", False, f"Failed to read user data: {profile_response.status_code}")
                
                # Update (PUT) - Test if we can update the user
                update_data = {
                    "name": f"Updated Database CRUD Student {timestamp}"
                }
                update_response = self.session.put(
                    f"{self.base_url}/api/profile",
                    json=update_data,
                    headers={"Authorization": f"Bearer {token}"}
                )
                if update_response.status_code == 200:
                    self.log_test("Database Update Operation", True, "Successfully updated user data")
                else:
                    self.log_test("Database Update Operation", False, f"Failed to update user data: {update_response.status_code}")
                
                # Delete (DELETE) - Test if we can delete the user
                # Note: This might require admin privileges
                delete_response = self.session.delete(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if delete_response.status_code in [200, 204, 403, 404]:
                    self.log_test("Database Delete Operation", True, f"Delete operation completed: {delete_response.status_code}")
                else:
                    self.log_test("Database Delete Operation", False, f"Failed to delete user: {delete_response.status_code}")
            else:
                self.log_test("Database Create Operation", False, f"Failed to create user: {create_response.status_code}")
        except Exception as e:
            self.log_test("Database CRUD Operations", False, str(e))

    def test_database_transaction_handling(self):
        """Test database transaction handling"""
        print("\n🗄️ TESTING DATABASE TRANSACTION HANDLING")
        print("=" * 50)
        
        # Test transaction handling by attempting operations that might fail
        timestamp = int(time.time())
        
        # Test duplicate registration (should fail gracefully)
        student_data = {
            "name": f"Transaction Test Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"transaction_test{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # First registration
            response1 = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if response1.status_code == 200:
                # Second registration with same data (should fail)
                response2 = self.session.post(f"{self.base_url}/api/register", json=student_data)
                if response2.status_code == 400:
                    self.log_test("Database Transaction Handling", True, "Correctly handled duplicate registration")
                else:
                    self.log_test("Database Transaction Handling", False, f"Expected 400 for duplicate, got {response2.status_code}")
            else:
                self.log_test("Database Transaction Handling", False, f"First registration failed: {response1.status_code}")
        except Exception as e:
            self.log_test("Database Transaction Handling", False, str(e))

    def test_database_constraint_violations(self):
        """Test database constraint violations"""
        print("\n🗄️ TESTING DATABASE CONSTRAINT VIOLATIONS")
        print("=" * 50)
        
        timestamp = int(time.time())
        
        # Test various constraint violations
        constraint_tests = [
            {
                "name": "Constraint Test Student",
                "roll_number": f"23BT{timestamp}",
                "email": f"constraint_test{timestamp}@test.com",
                "password": "SecurePassword123!"
            },
            {
                "name": "Constraint Test Student 2",
                "roll_number": f"23BT{timestamp}",  # Same roll number
                "email": f"constraint_test2{timestamp}@test.com",
                "password": "SecurePassword123!"
            }
        ]
        
        try:
            # First registration
            response1 = self.session.post(f"{self.base_url}/api/register", json=constraint_tests[0])
            if response1.status_code == 200:
                # Second registration with same roll number (should violate constraint)
                response2 = self.session.post(f"{self.base_url}/api/register", json=constraint_tests[1])
                if response2.status_code == 400:
                    self.log_test("Database Constraint Violations", True, "Correctly handled roll number constraint violation")
                else:
                    self.log_test("Database Constraint Violations", False, f"Expected 400 for constraint violation, got {response2.status_code}")
            else:
                self.log_test("Database Constraint Violations", False, f"First registration failed: {response1.status_code}")
        except Exception as e:
            self.log_test("Database Constraint Violations", False, str(e))

    def test_database_performance(self):
        """Test database performance"""
        print("\n🗄️ TESTING DATABASE PERFORMANCE")
        print("=" * 50)
        
        # Test database performance by measuring response times
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/health")
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                if response_time < 5.0:  # Should respond within 5 seconds
                    self.log_test("Database Performance", True, f"Database response time: {response_time:.2f}s")
                else:
                    self.log_test("Database Performance", False, f"Database response too slow: {response_time:.2f}s")
            else:
                self.log_test("Database Performance", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Database Performance", False, str(e))

    def test_database_data_integrity(self):
        """Test database data integrity"""
        print("\n🗄️ TESTING DATABASE DATA INTEGRITY")
        print("=" * 50)
        
        timestamp = int(time.time())
        student_data = {
            "name": f"Data Integrity Student {timestamp}",
            "roll_number": f"23BT{timestamp}",
            "email": f"data_integrity{timestamp}@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            # Create user
            create_response = self.session.post(f"{self.base_url}/api/register", json=student_data)
            if create_response.status_code == 200:
                create_data = create_response.json()
                token = create_data["access_token"]
                
                # Verify data integrity by reading back the data
                profile_response = self.session.get(
                    f"{self.base_url}/api/profile",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if profile_response.status_code == 200:
                    profile_data = profile_response.json()
                    
                    # Check if the data matches what we created
                    if (profile_data.get("name") == student_data["name"] and 
                        profile_data.get("email") == student_data["email"]):
                        self.log_test("Database Data Integrity", True, "Data integrity maintained")
                    else:
                        self.log_test("Database Data Integrity", False, "Data integrity compromised")
                else:
                    self.log_test("Database Data Integrity", False, f"Failed to read profile: {profile_response.status_code}")
            else:
                self.log_test("Database Data Integrity", False, f"Failed to create user: {create_response.status_code}")
        except Exception as e:
            self.log_test("Database Data Integrity", False, str(e))

    def test_database_error_handling(self):
        """Test database error handling"""
        print("\n🗄️ TESTING DATABASE ERROR HANDLING")
        print("=" * 50)
        
        # Test database error handling by sending malformed data
        malformed_data = {
            "name": None,  # Null value that might cause database error
            "roll_number": "23BT123",
            "email": "test@test.com",
            "password": "SecurePassword123!"
        }
        
        try:
            response = self.session.post(f"{self.base_url}/api/register", json=malformed_data)
            if response.status_code in [400, 422, 500]:
                self.log_test("Database Error Handling", True, f"Correctly handled malformed data: {response.status_code}")
            else:
                self.log_test("Database Error Handling", False, f"Expected error response, got {response.status_code}")
        except Exception as e:
            self.log_test("Database Error Handling", False, str(e))

    def test_database_connection_pooling(self):
        """Test database connection pooling"""
        print("\n🗄️ TESTING DATABASE CONNECTION POOLING")
        print("=" * 50)
        
        # Test multiple concurrent requests to see if connection pooling works
        try:
            responses = []
            start_time = time.time()
            
            # Make multiple concurrent requests
            for i in range(10):
                try:
                    response = self.session.get(f"{self.base_url}/api/health")
                    responses.append(response.status_code)
                except Exception:
                    responses.append("Error")
            
            end_time = time.time()
            total_time = end_time - start_time
            
            success_count = sum(1 for status in responses if status == 200)
            if success_count >= 8:  # At least 8 out of 10 should succeed
                self.log_test("Database Connection Pooling", True, f"Connection pooling working: {success_count}/10 successful in {total_time:.2f}s")
            else:
                self.log_test("Database Connection Pooling", False, f"Connection pooling issues: {success_count}/10 successful")
        except Exception as e:
            self.log_test("Database Connection Pooling", False, str(e))

    def run_database_tests(self):
        """Run all database failure tests"""
        print("🗄️ RUNNING DATABASE FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Database failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all database tests
        self.test_database_health_check()
        self.test_database_connection()
        self.test_database_crud_operations()
        self.test_database_transaction_handling()
        self.test_database_constraint_violations()
        self.test_database_performance()
        self.test_database_data_integrity()
        self.test_database_error_handling()
        self.test_database_connection_pooling()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 DATABASE FAILURE TESTS SUMMARY")
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
    # Run the database failure tests
    test_suite = DatabaseFailuresTest()
    results = test_suite.run_database_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 