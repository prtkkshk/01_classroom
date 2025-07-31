#!/usr/bin/env python3
"""
MASTER TEST RUNNER FOR CLASSROOM LIVE APP
=========================================

This script runs all test suites in sequence:
1. Comprehensive Test Suite (API endpoints, business logic)
2. WebSocket Tests (Real-time features)
3. Security Tests (Authentication, authorization, input validation)
4. User Management Tests (Student, Professor, Moderator workflows)
5. Course Management Tests (CRUD operations, enrollments)
6. Questions & Answers Tests (Q&A functionality)
7. Polls & Voting Tests (Interactive polls)
8. Announcements Tests (Course announcements)
9. Admin Tests (Moderator functionality)
10. Performance Tests (Load testing, stress testing)
11. Integration Tests (End-to-end workflows)

Usage:
    python run_all_tests.py
"""

import asyncio
import time
import sys
import os
from datetime import datetime

def run_comprehensive_tests():
    """Run the comprehensive test suite"""
    print("🚀 Running Comprehensive Test Suite...")
    try:
        from comprehensive_test_suite import ComprehensiveTestSuite
        test_suite = ComprehensiveTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running comprehensive tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

async def run_websocket_tests():
    """Run the WebSocket test suite"""
    print("\n🔌 Running WebSocket Test Suite...")
    try:
        from websocket_tests import WebSocketTestSuite
        test_suite = WebSocketTestSuite()
        await test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running WebSocket tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_security_tests():
    """Run the security test suite"""
    print("\n🛡️ Running Security Test Suite...")
    try:
        from security_tests import SecurityTestSuite
        test_suite = SecurityTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running security tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_user_management_tests():
    """Run the user management test suite"""
    print("\n👥 Running User Management Test Suite...")
    try:
        from user_management_tests import UserManagementTestSuite
        test_suite = UserManagementTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running user management tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_course_management_tests():
    """Run the course management test suite"""
    print("\n📚 Running Course Management Test Suite...")
    try:
        from course_management_tests import CourseManagementTestSuite
        test_suite = CourseManagementTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running course management tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_questions_tests():
    """Run the questions and answers test suite"""
    print("\n❓ Running Questions & Answers Test Suite...")
    try:
        from questions_tests import QuestionsTestSuite
        test_suite = QuestionsTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running questions tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_polls_tests():
    """Run the polls and voting test suite"""
    print("\n🗳️ Running Polls & Voting Test Suite...")
    try:
        from polls_tests import PollsTestSuite
        test_suite = PollsTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running polls tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_announcements_tests():
    """Run the announcements test suite"""
    print("\n📢 Running Announcements Test Suite...")
    try:
        from announcements_tests import AnnouncementsTestSuite
        test_suite = AnnouncementsTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running announcements tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_admin_tests():
    """Run the admin functionality test suite"""
    print("\n👨‍💼 Running Admin Test Suite...")
    try:
        from admin_tests import AdminTestSuite
        test_suite = AdminTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running admin tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_performance_tests():
    """Run the performance test suite"""
    print("\n⚡ Running Performance Test Suite...")
    try:
        from performance_tests import PerformanceTestSuite
        test_suite = PerformanceTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running performance tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_integration_tests():
    """Run the integration test suite"""
    print("\n🔗 Running Integration Test Suite...")
    try:
        from integration_tests import IntegrationTestSuite
        test_suite = IntegrationTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running integration tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_authentication_tests():
    """Run the authentication test suite"""
    print("\n🔐 Running Authentication Test Suite...")
    try:
        from authentication_tests import ComprehensiveAuthenticationTestSuite
        test_suite = ComprehensiveAuthenticationTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running authentication tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_data_validation_tests():
    """Run the data validation test suite"""
    print("\n📝 Running Data Validation Test Suite...")
    try:
        from data_validation_tests import ComprehensiveDataValidationTestSuite
        test_suite = ComprehensiveDataValidationTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running data validation tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_error_handling_tests():
    """Run the error handling test suite"""
    print("\n🚨 Running Error Handling Test Suite...")
    try:
        from error_handling_tests import ComprehensiveErrorHandlingTestSuite
        test_suite = ComprehensiveErrorHandlingTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running error handling tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_session_management_tests():
    """Run the session management test suite"""
    print("\n⏰ Running Session Management Test Suite...")
    try:
        from session_management_tests import ComprehensiveSessionManagementTestSuite
        test_suite = ComprehensiveSessionManagementTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running session management tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_database_tests():
    """Run the database test suite"""
    print("\n🗄️ Running Database Test Suite...")
    try:
        from database_tests import ComprehensiveDatabaseTestSuite
        test_suite = ComprehensiveDatabaseTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running database tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_middleware_tests():
    """Run the middleware test suite"""
    print("\n🔧 Running Middleware Test Suite...")
    try:
        from middleware_tests import ComprehensiveMiddlewareTestSuite
        test_suite = ComprehensiveMiddlewareTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running middleware tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def run_configuration_tests():
    """Run the configuration test suite"""
    print("\n⚙️ Running Configuration Test Suite...")
    try:
        from configuration_tests import ComprehensiveConfigurationTestSuite
        test_suite = ComprehensiveConfigurationTestSuite()
        test_suite.run_all_tests()
        return test_suite.test_results
    except Exception as e:
        print(f"❌ Error running configuration tests: {e}")
        return {"passed": 0, "failed": 1, "errors": [str(e)]}

def print_test_summary(all_results):
    """Print comprehensive test summary"""
    print("\n" + "=" * 80)
    print("🎯 COMPREHENSIVE TEST SUMMARY")
    print("=" * 80)
    
    total_passed = sum(result["passed"] for result in all_results.values())
    total_failed = sum(result["failed"] for result in all_results.values())
    total_tests = total_passed + total_failed
    
    print(f"📊 OVERALL RESULTS:")
    print(f"   ✅ Total Passed: {total_passed}")
    print(f"   ❌ Total Failed: {total_failed}")
    print(f"   📈 Success Rate: {(total_passed / total_tests * 100):.1f}%")
    print(f"   🧪 Total Tests: {total_tests}")
    
    print(f"\n📋 BREAKDOWN BY TEST SUITE:")
    for suite_name, results in all_results.items():
        suite_total = results["passed"] + results["failed"]
        success_rate = (results["passed"] / suite_total * 100) if suite_total > 0 else 0
        print(f"   {suite_name}:")
        print(f"     ✅ Passed: {results['passed']}")
        print(f"     ❌ Failed: {results['failed']}")
        print(f"     📈 Success Rate: {success_rate:.1f}%")
        
        if results["errors"]:
            print(f"     ⚠️  Errors: {len(results['errors'])}")
    
    # Collect all errors
    all_errors = []
    for suite_name, results in all_results.items():
        for error in results["errors"]:
            all_errors.append(f"[{suite_name}] {error}")
    
    if all_errors:
        print(f"\n❌ ALL ERRORS FOUND:")
        for error in all_errors:
            print(f"   - {error}")
    
    # Overall assessment
    print(f"\n🎯 OVERALL ASSESSMENT:")
    if total_failed == 0:
        print("   🎉 EXCELLENT! All tests passed!")
    elif success_rate >= 90:
        print("   ✅ GOOD! Most tests passed with minor issues.")
    elif success_rate >= 75:
        print("   ⚠️  FAIR! Several issues need attention.")
    else:
        print("   ❌ POOR! Many critical issues found.")
    
    return total_passed, total_failed, success_rate

def generate_test_report(all_results, total_passed, total_failed, success_rate):
    """Generate a detailed test report"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"test_report_{timestamp}.md"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write("# Classroom Live App - Comprehensive Test Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Tests:** {total_passed + total_failed}\n")
        f.write(f"- **Passed:** {total_passed}\n")
        f.write(f"- **Failed:** {total_failed}\n")
        f.write(f"- **Success Rate:** {success_rate:.1f}%\n\n")
        
        f.write("## Test Suite Results\n\n")
        for suite_name, results in all_results.items():
            suite_total = results["passed"] + results["failed"]
            suite_success_rate = (results["passed"] / suite_total * 100) if suite_total > 0 else 0
            
            f.write(f"### {suite_name}\n\n")
            f.write(f"- **Passed:** {results['passed']}\n")
            f.write(f"- **Failed:** {results['failed']}\n")
            f.write(f"- **Success Rate:** {suite_success_rate:.1f}%\n\n")
            
            if results["errors"]:
                f.write("**Errors:**\n")
                for error in results["errors"]:
                    f.write(f"- {error}\n")
                f.write("\n")
        
        f.write("## Recommendations\n\n")
        if total_failed == 0:
            f.write("Excellent! All tests passed. The application is ready for production.\n\n")
        elif success_rate >= 90:
            f.write("Good! Most tests passed. Address the few remaining issues before production.\n\n")
        elif success_rate >= 75:
            f.write("Fair! Several issues need attention. Review and fix before production.\n\n")
        else:
            f.write("Poor! Many critical issues found. Extensive fixes needed before production.\n\n")
    
    print(f"\nTest report generated: {report_filename}")

async def main():
    """Main test runner"""
    print("🚀 STARTING COMPREHENSIVE TEST SUITE FOR CLASSROOM LIVE APP")
    print("=" * 80)
    print(f"⏰ Started at: {datetime.now()}")
    print(f"🔗 Testing: https://zero1-classroom-1.onrender.com")
    print("=" * 80)
    
    start_time = time.time()
    
    # Run all test suites
    all_results = {}
    
    # 1. Comprehensive tests
    comprehensive_results = run_comprehensive_tests()
    all_results["Comprehensive Tests"] = comprehensive_results
    
    # 2. WebSocket tests
    websocket_results = await run_websocket_tests()
    all_results["WebSocket Tests"] = websocket_results
    
    # 3. Security tests
    security_results = run_security_tests()
    all_results["Security Tests"] = security_results
    
    # 4. User Management tests
    user_management_results = run_user_management_tests()
    all_results["User Management Tests"] = user_management_results
    
    # 5. Course Management tests
    course_management_results = run_course_management_tests()
    all_results["Course Management Tests"] = course_management_results
    
    # 6. Questions tests
    questions_results = run_questions_tests()
    all_results["Questions & Answers Tests"] = questions_results
    
    # 7. Polls tests
    polls_results = run_polls_tests()
    all_results["Polls & Voting Tests"] = polls_results
    
    # 8. Announcements tests
    announcements_results = run_announcements_tests()
    all_results["Announcements Tests"] = announcements_results
    
    # 9. Admin tests
    admin_results = run_admin_tests()
    all_results["Admin Tests"] = admin_results
    
    # 10. Performance tests
    performance_results = run_performance_tests()
    all_results["Performance Tests"] = performance_results
    
    # 11. Integration tests
    integration_results = run_integration_tests()
    all_results["Integration Tests"] = integration_results
    
    # 12. Authentication tests
    authentication_results = run_authentication_tests()
    all_results["Authentication Tests"] = authentication_results
    
    # 13. Data Validation tests
    data_validation_results = run_data_validation_tests()
    all_results["Data Validation Tests"] = data_validation_results
    
    # 14. Error Handling tests
    error_handling_results = run_error_handling_tests()
    all_results["Error Handling Tests"] = error_handling_results
    
    # 15. Session Management tests
    session_management_results = run_session_management_tests()
    all_results["Session Management Tests"] = session_management_results
    
    # 16. Database tests
    database_results = run_database_tests()
    all_results["Database Tests"] = database_results
    
    # 17. Middleware tests
    middleware_results = run_middleware_tests()
    all_results["Middleware Tests"] = middleware_results
    
    # 18. Configuration tests
    configuration_results = run_configuration_tests()
    all_results["Configuration Tests"] = configuration_results
    
    # Calculate totals and print summary
    total_passed, total_failed, success_rate = print_test_summary(all_results)
    
    # Generate report
    generate_test_report(all_results, total_passed, total_failed, success_rate)
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n⏱️  Total test duration: {duration:.2f} seconds")
    print(f"🎯 Test completed at: {datetime.now()}")
    
    # Exit with appropriate code
    if total_failed == 0:
        print("🎉 All tests passed! Exiting with code 0.")
        sys.exit(0)
    else:
        print(f"⚠️  {total_failed} tests failed. Exiting with code 1.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test execution interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1) 