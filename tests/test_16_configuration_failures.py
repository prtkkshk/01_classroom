#!/usr/bin/env python3
"""
CONFIGURATION FAILURES TEST
===========================

This test file specifically targets configuration failures identified in the comprehensive test report.
Category: Configuration failures (environment detection, validation)

Failed Test Scenarios:
- Environment detection failures
- Configuration validation errors
- Info endpoint issues
"""

import requests
from datetime import datetime

class ConfigurationFailuresTest:
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

    def test_environment_detection(self):
        """Test environment detection via /api/info endpoint"""
        print("\n⚙️ TESTING ENVIRONMENT DETECTION")
        print("=" * 50)
        try:
            response = self.session.get(f"{self.base_url}/api/info")
            if response.status_code == 200:
                data = response.json()
                if "environment" in data:
                    self.log_test("Environment Detection", True, f"Environment: {data['environment']}")
                else:
                    self.log_test("Environment Detection", False, "Environment not detected in response")
            else:
                self.log_test("Environment Detection", False, f"Info endpoint failed: {response.status_code}")
        except Exception as e:
            self.log_test("Environment Detection", False, str(e))

    def test_configuration_validation(self):
        """Test configuration validation via /api/info endpoint"""
        print("\n⚙️ TESTING CONFIGURATION VALIDATION")
        print("=" * 50)
        try:
            response = self.session.get(f"{self.base_url}/api/info")
            if response.status_code == 200:
                data = response.json()
                config_keys = ["environment", "version", "debug", "database_url"]
                missing = [k for k in config_keys if k not in data]
                if not missing:
                    self.log_test("Configuration Validation", True, "All config keys present")
                else:
                    self.log_test("Configuration Validation", False, f"Missing config keys: {missing}")
            else:
                self.log_test("Configuration Validation", False, f"Info endpoint failed: {response.status_code}")
        except Exception as e:
            self.log_test("Configuration Validation", False, str(e))

    def test_info_endpoint(self):
        """Test /api/info endpoint for expected structure"""
        print("\n⚙️ TESTING INFO ENDPOINT STRUCTURE")
        print("=" * 50)
        try:
            response = self.session.get(f"{self.base_url}/api/info")
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict) and len(data) > 0:
                    self.log_test("Info Endpoint Structure", True, f"Info keys: {list(data.keys())}")
                else:
                    self.log_test("Info Endpoint Structure", False, "Info endpoint returned empty or invalid structure")
            else:
                self.log_test("Info Endpoint Structure", False, f"Info endpoint failed: {response.status_code}")
        except Exception as e:
            self.log_test("Info Endpoint Structure", False, str(e))

    def run_configuration_tests(self):
        print("⚙️ RUNNING CONFIGURATION FAILURE TESTS")
        print("=" * 60)
        print(f"Target: Configuration failures from comprehensive test report")
        print(f"Base URL: {self.base_url}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        self.test_environment_detection()
        self.test_configuration_validation()
        self.test_info_endpoint()
        print("\n" + "=" * 60)
        print("📊 CONFIGURATION FAILURE TESTS SUMMARY")
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
    test_suite = ConfigurationFailuresTest()
    results = test_suite.run_configuration_tests()
    exit(0 if results['failed'] == 0 else 1) 