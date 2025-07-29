// Simple test script - copy and paste this in your browser console

const token = localStorage.getItem('token');
console.log('Token exists:', !!token);

if (token) {
    const timestamp = Date.now();
    const data = {
        name: 'Test Professor ' + timestamp,
        userid: 'testprof' + timestamp,
        email: 'test' + timestamp + '@example.com',
        password: 'password123'
    };
    
    console.log('Testing with data:', data);
    
    fetch('https://zero1-classroom-1.onrender.com/api/admin/create-professor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(data)
    })
    .then(r => r.text())
    .then(result => {
        console.log('Response:', result);
        if (result.includes('access_token')) {
            console.log('✅ Success!');
        } else {
            console.log('❌ Error occurred');
        }
    })
    .catch(e => console.error('Error:', e));
} else {
    console.log('Please log in as moderator first');
} 