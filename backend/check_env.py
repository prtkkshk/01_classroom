#!/usr/bin/env python3
"""
Script to check available environment variables.
"""

import os
from dotenv import load_dotenv

load_dotenv()

print("🔍 Checking environment variables...")
print("=" * 50)

# Check for MongoDB-related variables
mongo_vars = []
for key, value in os.environ.items():
    if any(mongo_key in key.upper() for mongo_key in ['MONGO', 'DATABASE', 'DB']):
        mongo_vars.append((key, value))

if mongo_vars:
    print("✅ Found MongoDB-related environment variables:")
    for key, value in mongo_vars:
        # Mask sensitive parts of the URL
        if 'mongodb' in value.lower():
            # Show only the first part of the URL for security
            parts = value.split('@')
            if len(parts) > 1:
                masked_value = f"{parts[0].split('://')[0]}://***:***@{parts[1]}"
            else:
                masked_value = value[:20] + "..." if len(value) > 20 else value
        else:
            masked_value = value[:20] + "..." if len(value) > 20 else value
        
        print(f"  {key}: {masked_value}")
else:
    print("❌ No MongoDB-related environment variables found")

print("\n📋 All environment variables:")
print("-" * 30)
for key, value in os.environ.items():
    if not any(sensitive in key.upper() for sensitive in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
        print(f"  {key}: {value}")
    else:
        print(f"  {key}: ***HIDDEN***")

print("\n💡 If you don't see your MongoDB URL, check your .env file or environment setup.") 