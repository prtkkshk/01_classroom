// Test script to debug the 400 error when creating professor
// Run this in your browser console after logging in as moderator

console.log('🔍 Testing create-professor with proper validation...');

// Get token
const token = localStorage.getItem('token');
if (!token) {
    console.log('❌ No token found. Please log in as moderator first.');
} else {
    console.log('Token found:', token.substring(0, 20) + '...');

    // Test with unique data to avoid conflicts
    const timestamp = Date.now();
    const data = {
        name: 'Test Professor ' + Date.now(),
        userid: 'prof' + Date.now(),
        email: 'professor' + Date.now() + '@testdomain.com',
        password: 'password123'
    };

    console.log('Test data:', data);

    // Test the endpoint
    fetch('https://zero1-classroom-1.onrender.com/api/admin/create-professor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log('Status:', response.status);
        console.log('Status text:', response.statusText);
        console.log('Headers:', Object.fromEntries(response.headers.entries()));
        return response.text();
    })
    .then(data => {
        console.log('Response:', data);
        
        // Check if it was successful
        if (data.includes('access_token')) {
            console.log('✅ Professor created successfully!');
        } else if (data.includes('already exists')) {
            console.log('❌ User already exists - try with different data');
        } else if (data.includes('validation')) {
            console.log('❌ Validation error - check the response for details');
        } else {
            console.log('❌ Unexpected response');
        }
    })
    .catch(error => {
        console.error('Network error:', error);
    });

    // Also test with the exact same data as the Python script
    console.log('\n🧪 Testing with Python script data...');
    const pythonTestData = {
        name: 'Test Professor',
        userid: 'testprof' + timestamp,
        email: 'test' + timestamp + '@example.com',
        password: 'password123'
    };

    fetch('https://zero1-classroom-1.onrender.com/api/admin/create-professor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(pythonTestData)
    })
    .then(response => {
        console.log('Python test status:', response.status);
        return response.text();
    })
    .then(data => {
        console.log('Python test response:', data);
    })
    .catch(error => {
        console.error('Python test error:', error);
    });
} 