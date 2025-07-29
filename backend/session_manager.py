"""
Enhanced Session Manager with Redis for scalability
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import redis.asyncio as redis
import jwt
from fastapi import HTTPException

logger = logging.getLogger(__name__)

class EnhancedSessionManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.session_prefix = "session:"
        self.user_sessions_prefix = "user_sessions:"
        self.session_ttl = 1800  # 30 minutes in seconds
    
    async def add_session(self, token: str, user_data: Dict) -> bool:
        """Add a new session with Redis"""
        try:
            session_key = f"{self.session_prefix}{token}"
            user_sessions_key = f"{self.user_sessions_prefix}{user_data['id']}"
            
            # Store session data
            session_data = {
                "user_id": user_data["id"],
                "username": user_data.get("username", ""),
                "role": user_data["role"],
                "created_at": datetime.utcnow().isoformat(),
                "last_active": datetime.utcnow().isoformat(),
                "user_agent": user_data.get("user_agent", ""),
                "ip_address": user_data.get("ip_address", ""),
            }
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis.pipeline()
            
            # Store session
            pipe.setex(session_key, self.session_ttl, json.dumps(session_data))
            
            # Add to user's active sessions
            pipe.sadd(user_sessions_key, token)
            pipe.expire(user_sessions_key, self.session_ttl)
            
            # Add to global active sessions set
            pipe.sadd("active_sessions", token)
            
            await pipe.execute()
            
            logger.info(f"Session created for user {user_data['id']}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding session: {e}")
            return False
    
    async def remove_session(self, token: str) -> bool:
        """Remove a session"""
        try:
            session_key = f"{self.session_prefix}{token}"
            
            # Get session data before deletion
            session_data = await self.redis.get(session_key)
            if session_data:
                session_info = json.loads(session_data)
                user_id = session_info.get("user_id")
                
                pipe = self.redis.pipeline()
                
                # Remove session
                pipe.delete(session_key)
                
                # Remove from user's sessions
                if user_id:
                    user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
                    pipe.srem(user_sessions_key, token)
                
                # Remove from global active sessions
                pipe.srem("active_sessions", token)
                
                await pipe.execute()
                
                logger.info(f"Session removed for user {user_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error removing session: {e}")
            return False
    
    async def is_token_valid(self, token: str) -> bool:
        """Check if token is valid and active"""
        try:
            session_key = f"{self.session_prefix}{token}"
            session_data = await self.redis.get(session_key)
            
            if not session_data:
                return False
            
            # Update last active time
            session_info = json.loads(session_data)
            session_info["last_active"] = datetime.utcnow().isoformat()
            
            # Extend session TTL
            await self.redis.setex(session_key, self.session_ttl, json.dumps(session_info))
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking token validity: {e}")
            return False
    
    async def get_user_from_token(self, token: str) -> Optional[Dict]:
        """Get user data from token"""
        try:
            session_key = f"{self.session_prefix}{token}"
            session_data = await self.redis.get(session_key)
            
            if not session_data:
                return None
            
            session_info = json.loads(session_data)
            
            # Update last active time
            session_info["last_active"] = datetime.utcnow().isoformat()
            await self.redis.setex(session_key, self.session_ttl, json.dumps(session_info))
            
            return session_info
            
        except Exception as e:
            logger.error(f"Error getting user from token: {e}")
            return None
    
    async def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all active sessions for a user"""
        try:
            user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
            session_tokens = await self.redis.smembers(user_sessions_key)
            
            sessions = []
            for token in session_tokens:
                session_data = await self.get_user_from_token(token)
                if session_data:
                    sessions.append(session_data)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error getting user sessions: {e}")
            return []
    
    async def get_active_users_count(self) -> int:
        """Get count of active users"""
        try:
            # Get unique user IDs from active sessions
            active_sessions = await self.redis.smembers("active_sessions")
            user_ids = set()
            
            for token in active_sessions:
                session_data = await self.redis.get(f"{self.session_prefix}{token}")
                if session_data:
                    session_info = json.loads(session_data)
                    user_ids.add(session_info.get("user_id"))
            
            return len(user_ids)
            
        except Exception as e:
            logger.error(f"Error getting active users count: {e}")
            return 0
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        try:
            active_sessions = await self.redis.smembers("active_sessions")
            expired_count = 0
            
            for token in active_sessions:
                session_key = f"{self.session_prefix}{token}"
                if not await self.redis.exists(session_key):
                    # Session has expired, remove from active sessions
                    await self.redis.srem("active_sessions", token)
                    expired_count += 1
            
            logger.info(f"Cleaned up {expired_count} expired sessions")
            return expired_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            return 0
    
    async def get_session_stats(self) -> Dict:
        """Get session statistics"""
        try:
            active_sessions = await self.redis.smembers("active_sessions")
            total_sessions = len(active_sessions)
            
            # Get unique users
            user_ids = set()
            for token in active_sessions:
                session_data = await self.redis.get(f"{self.session_prefix}{token}")
                if session_data:
                    session_info = json.loads(session_data)
                    user_ids.add(session_info.get("user_id"))
            
            unique_users = len(user_ids)
            
            return {
                "total_sessions": total_sessions,
                "unique_users": unique_users,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return {
                "total_sessions": 0,
                "unique_users": 0,
                "timestamp": datetime.utcnow().isoformat()
            } 