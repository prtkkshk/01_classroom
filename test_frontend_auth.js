// Test script to check frontend authentication
// Run this in your browser console after logging in

console.log('🔍 Testing frontend authentication...');

// Check if token exists
const token = localStorage.getItem('token');
const user = localStorage.getItem('user');

console.log('Token exists:', !!token);
console.log('User data exists:', !!user);

if (token) {
    console.log('Token preview:', token.substring(0, 20) + '...');
    
    // Test if token is valid by making a simple API call
    fetch('https://zero1-classroom-1.onrender.com/api/admin/stats', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => {
        console.log('Token validation status:', response.status);
        if (response.status === 200) {
            console.log('✅ Token is valid!');
            return response.json();
        } else if (response.status === 401) {
            console.log('❌ Token is invalid or expired');
        } else if (response.status === 403) {
            console.log('❌ Token is valid but user is not a moderator');
        } else {
            console.log('❌ Unexpected status:', response.status);
        }
    })
    .then(data => {
        if (data) {
            console.log('User role:', data.user?.role);
            console.log('User name:', data.user?.name);
        }
    })
    .catch(error => {
        console.error('Error testing token:', error);
    });
} else {
    console.log('❌ No token found in localStorage');
}

if (user) {
    try {
        const userData = JSON.parse(user);
        console.log('User data:', userData);
        console.log('User role:', userData.role);
        console.log('User name:', userData.name);
    } catch (error) {
        console.error('Error parsing user data:', error);
    }
}

// Test the create-professor endpoint specifically
if (token) {
    console.log('\n🧪 Testing create-professor endpoint...');
    
    const testData = {
        name: 'Test Professor',
        userid: 'testprof' + Date.now(),
        email: 'test' + Date.now() + '@example.com',
        password: 'password123'
    };
    
    fetch('https://zero1-classroom-1.onrender.com/api/admin/create-professor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(testData)
    })
    .then(response => {
        console.log('Create professor status:', response.status);
        return response.text();
    })
    .then(data => {
        console.log('Create professor response:', data);
        if (response.status === 200) {
            console.log('✅ Professor created successfully!');
        } else if (response.status === 400) {
            console.log('❌ Business logic error (probably duplicate user)');
        } else if (response.status === 403) {
            console.log('❌ Access denied - need moderator privileges');
        } else if (response.status === 401) {
            console.log('❌ Authentication failed');
        }
    })
    .catch(error => {
        console.error('Error creating professor:', error);
    });
} 