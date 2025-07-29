import requests
import json

# Test configuration
BASE_URL = "https://zero1-classroom-1.onrender.com"
API_URL = f"{BASE_URL}/api"

# Hardcoded credentials
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

def test_moderator_login():
    """Test moderator login"""
    login_data = {
        "username": MODERATOR_USERNAME,
        "password": MODERATOR_PASSWORD
    }
    
    try:
        response = requests.post(f"{API_URL}/login", json=login_data)
        print(f"Moderator login test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Moderator login successful!")
            print(f"User data: {json.dumps(data.get('user', {}), indent=2)}")
            return data.get('access_token')
        else:
            print(f"Moderator login failed: {response.text}")
            return None
    except Exception as e:
        print(f"Moderator login test failed: {e}")
        return None

def test_get_all_users(token):
    """Test getting all users as moderator"""
    if not token:
        print("No token provided for get all users test")
        return False
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(f"{API_URL}/admin/users", headers=headers)
        print(f"Get all users test: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Found {len(data)} users")
            for user in data:
                print(f"  - {user.get('name', 'No name')} ({user.get('role', 'No role')}) - {user.get('roll_number', user.get('userid', 'No ID'))}")
            return True
        else:
            print(f"Get all users failed: {response.text}")
            return False
    except Exception as e:
        print(f"Get all users test failed: {e}")
        return False

def main():
    print("=== Moderator Fix Test ===")
    
    # Test 1: Moderator login
    print("\n1. Testing moderator login...")
    moderator_token = test_moderator_login()
    
    if moderator_token:
        # Test 2: Get all users
        print("\n2. Testing get all users...")
        test_get_all_users(moderator_token)
    else:
        print("Moderator login failed")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main() 