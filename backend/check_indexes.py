#!/usr/bin/env python3
"""
Script to check and remove problematic database indexes
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

async def check_and_fix_indexes():
    """Check and fix database indexes"""
    print("🔍 Checking database indexes...")
    
    try:
        # List all indexes
        indexes = await db.users.list_indexes().to_list(10)
        print(f"Found {len(indexes)} indexes:")
        
        for index in indexes:
            print(f"  - {index['name']}: {index['key']}")
            if 'unique' in index:
                print(f"    Unique: {index['unique']}")
            if 'sparse' in index:
                print(f"    Sparse: {index['sparse']}")
        
        # Remove problematic indexes
        print("\n🗑️ Removing problematic indexes...")
        
        indexes_to_remove = ['roll_number_1', 'userid_1']
        
        for index_name in indexes_to_remove:
            try:
                await db.users.drop_index(index_name)
                print(f"✅ Removed index: {index_name}")
            except Exception as e:
                print(f"⚠️ Could not remove {index_name}: {e}")
        
        # Recreate only the email index
        print("\n🔧 Recreating email index...")
        try:
            await db.users.create_index("email", unique=True)
            print("✅ Created email unique index")
        except Exception as e:
            print(f"❌ Failed to create email index: {e}")
        
        # List indexes again
        print("\n📋 Final index list:")
        indexes = await db.users.list_indexes().to_list(10)
        for index in indexes:
            print(f"  - {index['name']}: {index['key']}")
        
        print("\n🎉 Index check and fix completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(check_and_fix_indexes()) 