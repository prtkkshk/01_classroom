#!/usr/bin/env python3
"""
HEALTH CHECK FAILURES TEST
==========================

This test file specifically targets health check failures identified in the comprehensive test report.
Category: Health check failures (detailed health check, missing components)

Failed Test Scenarios:
- Detailed health check missing components
- Database health status not found
- Health check endpoint failures
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class HealthCheckFailuresTest:
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

    def test_detailed_health_check_components(self):
        """Test detailed health check that failed - missing components"""
        print("\n🏥 TESTING DETAILED HEALTH CHECK COMPONENTS")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                # Check if all health components are present
                health_components = ["database", "redis", "api", "uptime"]
                missing_components = [comp for comp in health_components if comp not in data]
                if missing_components:
                    self.log_test("Detailed Health Check Components", False, f"Missing components: {missing_components}")
                else:
                    self.log_test("Detailed Health Check Components", True, f"All components present: {list(data.keys())}")
            else:
                self.log_test("Detailed Health Check Components", False, f"Status: {response.status_code}")
        except Exception as e:
            self.log_test("Detailed Health Check Components", False, str(e))

    def test_database_health_status(self):
        """Test database health status that failed"""
        print("\n🗄️ TESTING DATABASE HEALTH STATUS")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "database" in data:
                    db_status = data["database"]
                    if isinstance(db_status, dict) and "status" in db_status:
                        self.log_test("Database Health Status", True, f"Database status: {db_status['status']}")
                    else:
                        self.log_test("Database Health Status", False, f"Database status format invalid: {db_status}")
                else:
                    self.log_test("Database Health Status", False, "Database status not found in response")
            else:
                self.log_test("Database Health Status", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Database Health Status", False, str(e))

    def test_redis_health_status(self):
        """Test Redis health status that failed"""
        print("\n🔴 TESTING REDIS HEALTH STATUS")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "redis" in data:
                    redis_status = data["redis"]
                    if isinstance(redis_status, dict) and "status" in redis_status:
                        self.log_test("Redis Health Status", True, f"Redis status: {redis_status['status']}")
                    else:
                        self.log_test("Redis Health Status", False, f"Redis status format invalid: {redis_status}")
                else:
                    self.log_test("Redis Health Status", False, "Redis status not found in response")
            else:
                self.log_test("Redis Health Status", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Redis Health Status", False, str(e))

    def test_api_health_status(self):
        """Test API health status that failed"""
        print("\n🔌 TESTING API HEALTH STATUS")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "api" in data:
                    api_status = data["api"]
                    if isinstance(api_status, dict) and "status" in api_status:
                        self.log_test("API Health Status", True, f"API status: {api_status['status']}")
                    else:
                        self.log_test("API Health Status", False, f"API status format invalid: {api_status}")
                else:
                    self.log_test("API Health Status", False, "API status not found in response")
            else:
                self.log_test("API Health Status", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("API Health Status", False, str(e))

    def test_uptime_health_status(self):
        """Test uptime health status that failed"""
        print("\n⏱️ TESTING UPTIME HEALTH STATUS")
        print("=" * 50)
        
        try:
            response = self.session.get(f"{self.base_url}/api/health")
            if response.status_code == 200:
                data = response.json()
                if "uptime" in data:
                    uptime_status = data["uptime"]
                    if isinstance(uptime_status, dict) and "status" in uptime_status:
                        self.log_test("Uptime Health Status", True, f"Uptime status: {uptime_status['status']}")
                    else:
                        self.log_test("Uptime Health Status", False, f"Uptime status format invalid: {uptime_status}")
                else:
                    self.log_test("Uptime Health Status", False, "Uptime status not found in response")
            else:
                self.log_test("Uptime Health Status", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Uptime Health Status", False, str(e))

    def test_health_check_response_time(self):
        """Test health check response time"""
        print("\n⚡ TESTING HEALTH CHECK RESPONSE TIME")
        print("=" * 50)
        
        try:
            start_time = time.time()
            response = self.session.get(f"{self.base_url}/api/health")
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                if response_time < 5.0:  # Should respond within 5 seconds
                    self.log_test("Health Check Response Time", True, f"Response time: {response_time:.2f}s")
                else:
                    self.log_test("Health Check Response Time", False, f"Response too slow: {response_time:.2f}s")
            else:
                self.log_test("Health Check Response Time", False, f"Health check failed: {response.status_code}")
        except Exception as e:
            self.log_test("Health Check Response Time", False, str(e))

    def run_health_check_tests(self):
        """Run all health check failure tests"""
        print("🏥 RUNNING HEALTH CHECK FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Health check failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all health check tests
        self.test_detailed_health_check_components()
        self.test_database_health_status()
        self.test_redis_health_status()
        self.test_api_health_status()
        self.test_uptime_health_status()
        self.test_health_check_response_time()
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 HEALTH CHECK FAILURE TESTS SUMMARY")
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
    # Run the health check failure tests
    test_suite = HealthCheckFailuresTest()
    results = test_suite.run_health_check_tests()
    
    # Exit with appropriate code
    exit(0 if results['failed'] == 0 else 1) 