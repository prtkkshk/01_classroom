# Announcement Delete Feature

## Overview

The announcement delete feature allows professors and moderators to delete announcements from the classroom system. This feature includes proper authorization controls to ensure users can only delete announcements they have permission to delete.

## Features Implemented

### Backend Features

1. **Regular Delete Endpoint** (`DELETE /api/announcements/{announcement_id}`)
   - Professors can only delete their own announcements
   - Moderators can delete any announcement
   - Students cannot delete announcements
   - Includes real-time broadcast to course participants when announcement is deleted

2. **Admin Delete Endpoint** (`DELETE /api/admin/announcements/{announcement_id}`)
   - Only moderators can access this endpoint
   - Allows moderators to delete any announcement regardless of who created it
   - Includes real-time broadcast to course participants when announcement is deleted

### Frontend Features

1. **Delete Buttons**
   - Delete buttons appear on announcement cards for professors and moderators
   - Students do not see delete buttons
   - Confirmation dialog before deletion

2. **Role-Based Access Control**
   - **Students**: Cannot see delete buttons, cannot delete announcements
   - **Professors**: Can see delete buttons, can only delete their own announcements
   - **Moderators**: Can see delete buttons, can delete any announcement

3. **User Experience**
   - Confirmation dialog prevents accidental deletions
   - Success/error messages provide feedback
   - Real-time updates when announcements are deleted

## Permission Matrix

| User Role | Can Delete Own Announcements | Can Delete Others' Announcements | Can Access Admin Endpoint |
|-----------|------------------------------|----------------------------------|---------------------------|
| Student   | ❌ No                        | ❌ No                            | ❌ No                     |
| Professor | ✅ Yes                       | ❌ No                            | ❌ No                     |
| Moderator | ✅ Yes                       | ✅ Yes                           | ✅ Yes                    |

## API Endpoints

### Regular Delete Endpoint
```
DELETE /api/announcements/{announcement_id}
```

**Authorization:**
- Requires authentication
- Professors can only delete their own announcements
- Moderators can delete any announcement
- Students cannot delete announcements

**Response:**
```json
{
  "message": "Announcement deleted successfully"
}
```

### Admin Delete Endpoint
```
DELETE /api/admin/announcements/{announcement_id}
```

**Authorization:**
- Requires moderator role
- Can delete any announcement regardless of creator

**Response:**
```json
{
  "message": "Announcement deleted successfully"
}
```

## Frontend Implementation

### Components Updated

1. **AnnouncementList Component**
   - Added `onDelete` prop for delete handler
   - Added `showDeleteButton` prop to control button visibility
   - Delete buttons only show for professors and moderators

2. **Dashboard Components**
   - **StudentDashboard**: Shows delete buttons for professors/moderators
   - **ProfessorDashboard**: Shows delete buttons for all announcements
   - **ModeratorDashboard**: Shows delete buttons for all announcements

### Delete Handlers

Each dashboard has a `handleDeleteAnnouncement` function that:
1. Shows confirmation dialog
2. Calls appropriate API endpoint
3. Refreshes announcements list
4. Shows success/error messages

## Security Features

1. **Backend Authorization**
   - Role-based access control at API level
   - Professor ownership verification
   - Moderator privilege checks

2. **Frontend Security**
   - Delete buttons only shown to authorized users
   - Confirmation dialogs prevent accidental deletions
   - Error handling for unauthorized attempts

3. **Real-time Updates**
   - WebSocket broadcasts when announcements are deleted
   - All course participants are notified of deletions

## Testing

A comprehensive test script (`test_announcement_delete.py`) is included that tests:

1. **Professor can delete their own announcements** ✅
2. **Professor cannot delete other professors' announcements** ✅
3. **Moderator can delete any announcement** ✅
4. **Student cannot delete announcements** ✅

## Usage Examples

### For Professors
1. Navigate to the Announcements tab in your course
2. Find an announcement you created
3. Click the "Delete" button
4. Confirm the deletion in the dialog
5. Announcement is removed and all students are notified

### For Moderators
1. Navigate to the Announcements section in the moderator dashboard
2. Find any announcement (yours or others')
3. Click the "Delete" button
4. Confirm the deletion in the dialog
5. Announcement is removed and all course participants are notified

## Error Handling

The system handles various error scenarios:

- **403 Forbidden**: User doesn't have permission to delete the announcement
- **404 Not Found**: Announcement doesn't exist
- **Network Errors**: Proper error messages shown to users
- **Unauthorized Access**: Clear feedback when users try to access restricted features

## Future Enhancements

Potential improvements for the announcement delete feature:

1. **Soft Delete**: Instead of permanently removing announcements, mark them as deleted
2. **Bulk Delete**: Allow moderators to delete multiple announcements at once
3. **Delete History**: Track who deleted what and when
4. **Restore Functionality**: Allow moderators to restore accidentally deleted announcements
5. **Delete Notifications**: Send email notifications to course participants when important announcements are deleted

## Technical Notes

- The delete functionality uses the existing WebSocket infrastructure for real-time updates
- All delete operations are logged for audit purposes
- The frontend gracefully handles network errors and provides user feedback
- The implementation follows the existing code patterns and security practices 