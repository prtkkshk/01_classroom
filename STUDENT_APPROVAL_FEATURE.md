# Student Approval Feature

## Overview

The student approval feature allows professors to control who can join their courses. Instead of students automatically joining courses when they enter a course code, they now send a join request that must be approved by the professor. This gives professors full control over their course enrollment.

## Features Implemented

### Backend Features

1. **Modified Course Model**
   - Added `pending_students` field to track students waiting for approval
   - Existing `students` field now contains only approved/enrolled students

2. **Updated Join Course Endpoint** (`POST /api/courses/join`)
   - Students are now added to `pending_students` instead of directly to `students`
   - Returns approval pending message instead of success message
   - Sends WebSocket notification to professor about new join request

3. **Enhanced Get Students Endpoint** (`GET /api/courses/{course_id}/students`)
   - Returns both enrolled and pending students
   - Includes student status (enrolled/pending)
   - Provides counts for both categories

4. **New Student Management Endpoints**
   - **Approve Student** (`POST /api/courses/{course_id}/students/{student_id}/approve`)
   - **Reject Student** (`POST /api/courses/{course_id}/students/{student_id}/reject`)
   - **Remove Student** (`DELETE /api/courses/{course_id}/students/{student_id}`)

### Frontend Features

1. **Students Tab in Professor Dashboard**
   - Dedicated tab for student management
   - Shows both pending and enrolled students
   - Real-time updates when students are approved/rejected/removed

2. **Student Management Interface**
   - **Pending Students Section**: Shows students waiting for approval with Approve/Reject buttons
   - **Enrolled Students Section**: Shows approved students with Remove button
   - Confirmation dialogs for destructive actions

3. **Updated Join Course Flow**
   - Students see "Join request sent! Waiting for professor approval." message
   - Clear indication that approval is required

## Permission Matrix

| User Role | Can Request to Join | Can Approve Students | Can Reject Students | Can Remove Students |
|-----------|---------------------|----------------------|---------------------|---------------------|
| Student   | ✅ Yes              | ❌ No                | ❌ No               | ❌ No               |
| Professor | ❌ No               | ✅ Yes (own courses) | ✅ Yes (own courses)| ✅ Yes (own courses)|
| Moderator | ❌ No               | ❌ No                | ❌ No               | ❌ No               |

## API Endpoints

### Join Course Request
```
POST /api/courses/join
```

**Request Body:**
```json
{
  "code": "COURSE123"
}
```

**Response:**
```json
{
  "message": "Join request sent for course: Course Name. Waiting for professor approval."
}
```

### Get Course Students
```
GET /api/courses/{course_id}/students
```

**Response:**
```json
{
  "enrolled_students": [
    {
      "id": "student_id",
      "name": "Student Name",
      "roll_number": "STU001",
      "email": "student@example.com",
      "last_active": "2024-01-01T12:00:00Z",
      "status": "enrolled"
    }
  ],
  "pending_students": [
    {
      "id": "student_id",
      "name": "Student Name",
      "roll_number": "STU002",
      "email": "student2@example.com",
      "last_active": "2024-01-01T12:00:00Z",
      "status": "pending"
    }
  ],
  "total_enrolled": 1,
  "total_pending": 1
}
```

### Approve Student
```
POST /api/courses/{course_id}/students/{student_id}/approve
```

**Response:**
```json
{
  "message": "Student John Doe approved for course"
}
```

### Reject Student
```
POST /api/courses/{course_id}/students/{student_id}/reject
```

**Response:**
```json
{
  "message": "Student John Doe rejected from course"
}
```

### Remove Student
```
DELETE /api/courses/{course_id}/students/{student_id}
```

**Response:**
```json
{
  "message": "Student John Doe removed from course"
}
```

## Frontend Implementation

### Professor Dashboard - Students Tab

The Students tab provides a comprehensive interface for managing course enrollment:

1. **Pending Approvals Section**
   - Yellow background to indicate pending status
   - Shows student name, roll number, and email
   - Approve button (green) and Reject button (red)
   - Count of pending students in section header

2. **Enrolled Students Section**
   - Green background to indicate enrolled status
   - Shows student name, roll number, email, and last active date
   - Remove button (red) for each student
   - Count of enrolled students in section header

### Student Join Flow

1. Student enters course code in the "Join Course" form
2. System adds student to pending list instead of enrolled list
3. Student sees "Join request sent! Waiting for professor approval." message
4. Professor receives WebSocket notification about new join request
5. Professor can approve or reject the request from the Students tab

## Security Features

1. **Backend Authorization**
   - Only professors can approve/reject/remove students
   - Professors can only manage their own courses
   - Students cannot approve themselves or others

2. **Frontend Security**
   - Students tab only visible to professors
   - Confirmation dialogs for destructive actions
   - Real-time validation of user permissions

3. **Data Integrity**
   - Students cannot be in both pending and enrolled lists simultaneously
   - Proper cleanup when students are approved/rejected/removed
   - WebSocket notifications for real-time updates

## User Experience

### For Students
1. **Join Request Process**
   - Enter course code as usual
   - Receive immediate feedback that request is pending
   - Wait for professor approval
   - Receive notification when approved/rejected

2. **Status Visibility**
   - Can see if they're enrolled or pending in course list
   - Clear messaging about approval status

### For Professors
1. **Student Management**
   - Dedicated Students tab for easy access
   - Clear separation between pending and enrolled students
   - One-click approve/reject/remove actions
   - Real-time updates when students join

2. **Notifications**
   - WebSocket notifications for new join requests
   - Success/error messages for all actions
   - Confirmation dialogs for destructive actions

## Testing

A comprehensive test script (`test_student_approval.py`) is included that tests:

1. **Student can request to join course** ✅
2. **Professor can see pending students** ✅
3. **Professor can approve students** ✅
4. **Student enrollment verification** ✅
5. **Professor can remove enrolled students** ✅
6. **Student cannot approve themselves** ✅

## Usage Examples

### For Students
1. Navigate to "Join Course" in the course selection screen
2. Enter the course code provided by the professor
3. Click "Join Course"
4. See "Join request sent! Waiting for professor approval." message
5. Wait for professor to approve the request

### For Professors
1. Navigate to the Students tab in your course dashboard
2. View pending student requests in the "Pending Approvals" section
3. Click "Approve" to accept a student or "Reject" to decline
4. View enrolled students in the "Enrolled Students" section
5. Click "Remove" to remove an enrolled student if needed

## Error Handling

The system handles various error scenarios:

- **403 Forbidden**: User doesn't have permission to perform the action
- **404 Not Found**: Course or student doesn't exist
- **400 Bad Request**: Student already requested to join or already enrolled
- **Network Errors**: Proper error messages shown to users
- **Unauthorized Access**: Clear feedback when users try to access restricted features

## Future Enhancements

Potential improvements for the student approval feature:

1. **Bulk Actions**: Allow professors to approve/reject multiple students at once
2. **Approval Reasons**: Allow professors to provide reasons for rejection
3. **Auto-approval**: Option for professors to enable auto-approval for certain courses
4. **Approval History**: Track who approved/rejected what and when
5. **Email Notifications**: Send email notifications to students about approval status
6. **Approval Deadlines**: Set deadlines for join requests to expire
7. **Student Limits**: Set maximum number of students per course

## Technical Notes

- The approval system uses the existing WebSocket infrastructure for real-time updates
- All approval/rejection/removal operations are logged for audit purposes
- The frontend gracefully handles network errors and provides user feedback
- The implementation follows the existing code patterns and security practices
- Students who were already enrolled before this feature was implemented remain enrolled 