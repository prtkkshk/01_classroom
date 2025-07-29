# fix_users_db.py
import os
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio

MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'classroom_live')

async def reset_database():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    collections = [
        'users',
        'courses',
        'questions',
        'polls',
        'votes',
        'sessions',
    ]
    for col in collections:
        print(f"Dropping collection: {col}")
        await db[col].drop()
        # Optionally, recreate the collection (MongoDB will auto-create on first insert)
        await db.create_collection(col)
        print(f"Created empty collection: {col}")
    print("All collections dropped and recreated. Database is now empty.")
    client.close()

if __name__ == "__main__":
    asyncio.run(reset_database())
