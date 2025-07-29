#!/usr/bin/env python3
"""
Script to check all MongoDB indexes and identify potential conflicts
"""

import os
import asyncio
import sys
from pathlib import Path
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Add backend directory to path and load environment
backend_dir = Path(__file__).parent / "backend"
if backend_dir.exists():
    sys.path.append(str(backend_dir))
    os.chdir(backend_dir)

# Load environment variables
load_dotenv()

def load_env_manually():
    """Manually load environment variables from .env file"""
    env_file = Path("backend/.env") if Path("backend/.env").exists() else Path(".env")
    if env_file.exists():
        print(f"🔍 Loading from .env file: {env_file}")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")  # Remove quotes
                    os.environ[key] = value
                    if 'MONGO' in key.upper():
                        print(f"  ✅ Loaded {key}: {value[:30]}...")

async def check_indexes():
    # Load environment variables manually if needed
    mongo_url = os.getenv('MONGO_URL') or os.getenv('MONGODB_URL')
    if not mongo_url:
        load_env_manually()
        mongo_url = os.getenv('MONGO_URL') or os.getenv('MONGODB_URL')
    
    if not mongo_url:
        print("❌ No MongoDB URL found in environment variables")
        print("Available env vars:", [k for k in os.environ.keys() if 'MONGO' in k.upper()])
        return
    
    print(f"🔗 Connecting to MongoDB...")
    print(f"URL: {mongo_url[:20]}...")
    
    try:
        # Connect to MongoDB
        client = AsyncIOMotorClient(mongo_url)
        db_name = os.getenv('DB_NAME', 'v1_database')
        db = client[db_name]
        
        print(f"✅ Connected to database: {db_name}")
        
        # Check all indexes in users collection
        print(f"\n📋 All indexes in users collection:")
        indexes = await db.users.list_indexes().to_list(None)
        
        for index in indexes:
            print(f"  - {index['name']}: {index['key']}")
            if 'unique' in index:
                print(f"    Unique: {index['unique']}")
            if 'sparse' in index:
                print(f"    Sparse: {index['sparse']}")
        
        # Check for potential conflicts
        print(f"\n🔍 Analyzing potential conflicts...")
        
        # Check if there are multiple unique indexes that might conflict
        unique_indexes = [idx for idx in indexes if idx.get('unique', False)]
        print(f"Found {len(unique_indexes)} unique indexes:")
        
        for idx in unique_indexes:
            print(f"  - {idx['name']}: {idx['key']}")
        
        # Check existing users for null values
        print(f"\n👥 Checking existing users for null values...")
        users = await db.users.find().to_list(None)
        
        for user in users:
            print(f"  User: {user.get('name', 'Unknown')}")
            print(f"    Email: {user.get('email', 'None')}")
            print(f"    UserID: {user.get('userid', 'None')}")
            print(f"    Roll Number: {user.get('roll_number', 'None')}")
            print(f"    Role: {user.get('role', 'Unknown')}")
            print()
        
        # Test inserting a document to see what error we get
        print(f"\n🧪 Testing document insertion...")
        test_doc = {
            "name": "Test User",
            "email": "test@example.com",
            "userid": "testuser",
            "roll_number": None,
            "role": "professor",
            "password_hash": "test_hash"
        }
        
        try:
            result = await db.users.insert_one(test_doc)
            print(f"✅ Test insertion successful: {result.inserted_id}")
            # Clean up
            await db.users.delete_one({"_id": result.inserted_id})
            print(f"✅ Test document cleaned up")
        except Exception as e:
            print(f"❌ Test insertion failed: {e}")
            print(f"Error type: {type(e)}")
            if hasattr(e, 'code'):
                print(f"Error code: {e.code}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(check_indexes()) 