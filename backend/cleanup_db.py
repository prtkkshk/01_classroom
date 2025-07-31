#!/usr/bin/env python3
"""
Database cleanup script to remove existing users and reset indexes
"""

import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'classroom_live')]

async def cleanup_database():
    """Clean up the database by removing all users and recreating indexes"""
    print("🧹 Starting database cleanup...")
    
    try:
        # Drop all users
        result = await db.users.delete_many({})
        print(f"✅ Deleted {result.deleted_count} users")
        
        # Drop all indexes except _id
        try:
            await db.users.drop_indexes()
            print("✅ Dropped all user indexes")
        except Exception as e:
            print(f"⚠️ Warning: Could not drop all indexes: {e}")
        
        # Recreate indexes with proper sparse settings
        await db.users.create_index("email", unique=True)
        print("✅ Recreated email index")
        
        # Skip roll_number and userid unique indexes to avoid null value conflicts
        print("✅ Skipped roll_number and userid unique indexes to avoid conflicts")
        
        print("🎉 Database cleanup completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(cleanup_database()) 