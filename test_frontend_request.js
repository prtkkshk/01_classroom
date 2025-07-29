// Test script to simulate the frontend request
// Run this in your browser's developer console

const API_BASE = 'https://zero1-classroom-1.onrender.com';
const ENDPOINT = '/api/admin/create-professor';

// Test data
const testData = {
    name: 'Test Professor',
    userid: 'testprof123',
    email: 'test@example.com',
    password: 'password123'
};

// Get your moderator token from localStorage or wherever it's stored
const token = localStorage.getItem('token') || 'YOUR_MODERATOR_TOKEN_HERE';

console.log('🔍 Testing create-professor endpoint...');
console.log('URL:', API_BASE + ENDPOINT);
console.log('Token:', token ? token.substring(0, 20) + '...' : 'No token');

// Test 1: Check if endpoint exists
console.log('\n1️⃣ Testing OPTIONS request...');
fetch(API_BASE + ENDPOINT, {
    method: 'OPTIONS'
})
.then(response => {
    console.log('Status:', response.status);
    console.log('Allow header:', response.headers.get('Allow'));
    return response.text();
})
.then(data => console.log('Response:', data))
.catch(error => console.error('Error:', error));

// Test 2: Test POST without auth
console.log('\n2️⃣ Testing POST without authentication...');
fetch(API_BASE + ENDPOINT, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify(testData)
})
.then(response => {
    console.log('Status:', response.status);
    console.log('Status text:', response.statusText);
    return response.text();
})
.then(data => console.log('Response:', data))
.catch(error => console.error('Error:', error));

// Test 3: Test POST with auth
if (token && token !== 'YOUR_MODERATOR_TOKEN_HERE') {
    console.log('\n3️⃣ Testing POST with authentication...');
    fetch(API_BASE + ENDPOINT, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(testData)
    })
    .then(response => {
        console.log('Status:', response.status);
        console.log('Status text:', response.statusText);
        return response.text();
    })
    .then(data => console.log('Response:', data))
    .catch(error => console.error('Error:', error));
} else {
    console.log('\n3️⃣ Skipping authenticated test (no valid token)');
}

// Test 4: Check API info
console.log('\n4️⃣ Checking API info...');
fetch(API_BASE + '/api/info')
.then(response => response.json())
.then(data => {
    console.log('API Info:', data);
    const adminEndpoints = data.endpoints?.admin || [];
    console.log('Admin endpoints:', adminEndpoints);
    if (adminEndpoints.includes('/api/admin/create-professor')) {
        console.log('✅ create-professor endpoint is registered');
    } else {
        console.log('❌ create-professor endpoint is NOT registered');
    }
})
.catch(error => console.error('Error:', error));

// Test 5: Check health endpoint
console.log('\n5️⃣ Checking health endpoint...');
fetch(API_BASE + '/health')
.then(response => response.text())
.then(data => console.log('Health:', data))
.catch(error => console.error('Error:', error)); 