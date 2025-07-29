#!/usr/bin/env python3
"""
Script to fix the roll_number index issue in the users collection.
This script should be run once to clean up the problematic index.
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

async def fix_database_indexes():
    """Fix the roll_number index in the users collection."""
    
    # Load environment variables manually if needed
    mongodb_url = os.getenv("MONGO_URL")
    if not mongodb_url:
        load_env_manually()
        mongodb_url = os.getenv("MONGO_URL")
    
    if not mongodb_url:
        print("❌ MONGO_URL environment variable not found")
        return
    
    print(f"✅ Found MONGO_URL: {mongodb_url[:30]}...")
    
    try:
        # Connect to MongoDB
        client = AsyncIOMotorClient(mongodb_url)
        
        # Get database name from environment or use default
        db_name = os.getenv("DB_NAME", "v1_database")
        db = client[db_name]
        
        print(f"🔗 Connected to MongoDB")
        print(f"📊 Database: {db_name}")
        
        # List current indexes
        print("\n📋 Current indexes in users collection:")
        indexes = await db.users.list_indexes().to_list(None)
        for index in indexes:
            print(f"  - {index['name']}: {index['key']}")
        
        # Drop the problematic roll_number index if it exists
        try:
            await db.users.drop_index("roll_number_1")
            print("✅ Dropped problematic roll_number_1 index")
        except Exception as e:
            print(f"ℹ️  roll_number_1 index doesn't exist or couldn't be dropped: {e}")
        
        # Create the proper sparse unique index
        await db.users.create_index("roll_number", unique=True, sparse=True)
        print("✅ Created proper roll_number index (unique, sparse)")
        
        # Verify the new index
        print("\n📋 Updated indexes in users collection:")
        indexes = await db.users.list_indexes().to_list(None)
        for index in indexes:
            print(f"  - {index['name']}: {index['key']}")
        
        print("\n🎉 Database indexes fixed successfully!")
        print("💡 You can now create professor accounts without errors!")
        
    except Exception as e:
        print(f"❌ Error fixing database indexes: {e}")
        print("\n💡 Make sure your MongoDB connection string is correct.")
    finally:
        if 'client' in locals():
            client.close()

if __name__ == "__main__":
    asyncio.run(fix_database_indexes()) 