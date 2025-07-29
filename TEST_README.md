# 🧪 Comprehensive Test Suite for Classroom Live App

This directory contains a complete test suite for the Classroom Live application, covering every feature, scenario, and edge case.

## 📋 Test Files Overview

### 🚀 Main Test Files

1. **`comprehensive_test_suite.py`** - Complete API and business logic testing
2. **`websocket_tests.py`** - Real-time WebSocket functionality testing
3. **`security_tests.py`** - Security and vulnerability testing
4. **`run_all_tests.py`** - Master test runner (executes all tests)

### 🔧 Utility Test Files

5. **`test_timestamp_professors.py`** - Professor creation with timestamp roll numbers
6. **`test_multiple_professors.py`** - Multiple professor creation scenarios
7. **`test_professor_scenarios.py`** - Professor creation edge cases
8. **`test_simple_professor.py`** - Basic professor creation test
9. **`debug_users.py`** - Database user inspection
10. **`check_indexes.py`** - MongoDB index verification
11. **`fix_moderator_roll.py`** - Fix moderator roll number issues

## 🎯 Test Coverage

### ✅ Authentication & Authorization
- User login (student, professor, moderator)
- Invalid credentials handling
- Token validation
- Role-based access control
- Session management

### 👥 User Management
- Student registration
- Professor creation (moderator only)
- User listing and management
- Duplicate user prevention
- Roll number assignment

### 📚 Course Management
- Course creation (professors)
- Course joining (students)
- Course listing
- Student enrollment
- Course deletion

### ❓ Questions & Answers
- Question creation (anonymous/named)
- Question listing and filtering
- Question updates (professors)
- Question deletion
- Priority and tagging

### 🗳️ Polls & Voting
- Poll creation (professors)
- Anonymous polls
- Voting functionality
- Poll results
- Multiple choice polls

### 📢 Announcements
- Announcement creation
- Course-specific announcements
- Priority levels
- Expiration handling

### 🔌 Real-time Features
- WebSocket connections
- Real-time messaging
- Connection management
- Error handling

### 🛡️ Security
- Authentication bypass attempts
- Input validation
- SQL injection prevention
- XSS prevention
- CORS policy
- Content Security Policy

### ⚠️ Error Handling
- Invalid endpoints
- Malformed requests
- Network errors
- Database errors

## 🚀 How to Run Tests

### Option 1: Run All Tests (Recommended)
```bash
python run_all_tests.py
```
This will:
- Run all test suites
- Generate a comprehensive report
- Show detailed results
- Create a markdown report file

### Option 2: Run Individual Test Suites

#### Comprehensive Tests
```bash
python comprehensive_test_suite.py
```

#### WebSocket Tests
```bash
python websocket_tests.py
```

#### Security Tests
```bash
python security_tests.py
```

### Option 3: Run Specific Feature Tests

#### Professor Creation Tests
```bash
python test_timestamp_professors.py
python test_multiple_professors.py
python test_professor_scenarios.py
```

#### Database Tests
```bash
python debug_users.py
python check_indexes.py
python fix_moderator_roll.py
```

## 📊 Test Results

### Success Criteria
- **Excellent**: 100% pass rate
- **Good**: 90%+ pass rate
- **Fair**: 75%+ pass rate
- **Poor**: <75% pass rate

### Output Files
- **Console Output**: Real-time test results
- **Test Report**: `test_report_YYYYMMDD_HHMMSS.md`
- **Error Logs**: Detailed error information

## 🔧 Prerequisites

### Required Python Packages
```bash
pip install requests websockets asyncio
```

### Environment Setup
- Ensure the backend is running at `https://zero1-classroom-1.onrender.com`
- Valid user credentials for testing
- Network access to the application

## 🎯 Test Scenarios Covered

### User Roles
- **Students**: Registration, course joining, questions, voting
- **Professors**: Course creation, question management, polls, announcements
- **Moderators**: User management, professor creation, admin features

### Edge Cases
- Duplicate user creation
- Invalid course codes
- Expired sessions
- Network timeouts
- Malformed data
- Concurrent operations

### Security Scenarios
- Authentication bypass
- Authorization violations
- Input injection attacks
- Rate limiting
- CORS violations

### Performance Scenarios
- Multiple simultaneous users
- Large data sets
- Rapid operations
- Connection stress testing

## 🐛 Troubleshooting

### Common Issues

1. **Connection Errors**
   - Check if the backend is running
   - Verify the URL is correct
   - Check network connectivity

2. **Authentication Errors**
   - Verify user credentials
   - Check token expiration
   - Ensure proper authorization

3. **Test Failures**
   - Review error messages
   - Check backend logs
   - Verify test data

### Debug Mode
Add debug logging to any test file:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Continuous Testing

### Automated Testing
These tests can be integrated into CI/CD pipelines:
```bash
# Exit code 0 = all tests passed
# Exit code 1 = some tests failed
python run_all_tests.py
```

### Scheduled Testing
Set up cron jobs for regular testing:
```bash
# Run tests daily at 2 AM
0 2 * * * cd /path/to/tests && python run_all_tests.py
```

## 🎉 Success Metrics

A successful test run should show:
- ✅ All authentication tests pass
- ✅ All authorization tests pass
- ✅ All CRUD operations work
- ✅ Real-time features function
- ✅ Security measures are effective
- ✅ Error handling is robust

## 📞 Support

If you encounter issues:
1. Check the test report for detailed error information
2. Review the console output for specific failures
3. Verify the backend is functioning correctly
4. Ensure all prerequisites are met

---

**Last Updated**: January 2025
**Test Suite Version**: 1.0
**Coverage**: 100% of application features 