#!/usr/bin/env python3
"""
Script to fix the moderator's roll number to avoid duplicate key issues
"""

import asyncio
import os
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

async def fix_moderator_roll():
    """Fix the moderator's roll number to avoid duplicate key issues."""
    
    # Load environment variables manually if needed
    mongo_url = os.getenv('MONGO_URL') or os.getenv('MONGODB_URL')
    if not mongo_url:
        load_env_manually()
        mongo_url = os.getenv('MONGO_URL') or os.getenv('MONGODB_URL')
    
    if not mongo_url:
        print("❌ No MongoDB URL found in environment variables")
        return
    
    print(f"🔗 Connecting to MongoDB...")
    
    try:
        # Connect to MongoDB
        client = AsyncIOMotorClient(mongo_url)
        db_name = os.getenv('DB_NAME', 'v1_database')
        db = client[db_name]
        
        print(f"✅ Connected to database: {db_name}")
        
        # Find the moderator user
        moderator = await db.users.find_one({"role": "moderator"})
        if not moderator:
            print("❌ No moderator user found")
            return
        
        print(f"👤 Found moderator: {moderator.get('name', 'Unknown')}")
        print(f"   Current roll_number: {moderator.get('roll_number', 'None')}")
        
        # Update moderator's roll number to a unique value
        new_roll_number = "MODERATOR_001"
        result = await db.users.update_one(
            {"_id": moderator["_id"]},
            {"$set": {"roll_number": new_roll_number}}
        )
        
        if result.modified_count > 0:
            print(f"✅ Updated moderator roll_number to: {new_roll_number}")
        else:
            print("❌ Failed to update moderator roll_number")
            return
        
        # Verify the update
        updated_moderator = await db.users.find_one({"role": "moderator"})
        print(f"✅ Verification - New roll_number: {updated_moderator.get('roll_number', 'None')}")
        
        # Test inserting a professor with null roll_number
        print(f"\n🧪 Testing professor creation with null roll_number...")
        test_doc = {
            "name": "Test Professor",
            "email": "test@example.com",
            "userid": "testprof",
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
            print(f"🎉 Professor creation should now work!")
        except Exception as e:
            print(f"❌ Test insertion still failed: {e}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(fix_moderator_roll()) 