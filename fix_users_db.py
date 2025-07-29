# fix_users_db.py
import os
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
import uuid

MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
DB_NAME = os.environ.get('DB_NAME', 'classroom_live')

async def fix_users():
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    users = db.users

    async for user in users.find({}):
        update = {}
        # Ensure id
        if "id" not in user:
            update["id"] = str(uuid.uuid4())
        # Ensure created_at
        if "created_at" not in user:
            update["created_at"] = datetime.utcnow()
        # Ensure password_hash
        if "password_hash" not in user:
            update["password_hash"] = ""
        # Ensure role
        if "role" not in user:
            update["role"] = "student"  # Default to student if unknown
        # Ensure name
        if "name" not in user:
            update["name"] = "Unknown"
        # Ensure roll_number or userid
        if user.get("role") == "student" and "roll_number" not in user:
            update["roll_number"] = f"unknown_{user.get('id', str(uuid.uuid4()))[:8]}"
        if user.get("role") in ("professor", "moderator") and "userid" not in user:
            update["userid"] = f"unknown_{user.get('id', str(uuid.uuid4()))[:8]}"

        if update:
            print(f"Updating user {user.get('email', user.get('id'))}: {update}")
            await users.update_one({"_id": user["_id"]}, {"$set": update})

    print("User database migration complete.")
    client.close()

if __name__ == "__main__":
    asyncio.run(fix_users())
