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
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis = redis_client
        self.session_prefix = "session:"
        self.user_sessions_prefix = "user_sessions:"
        self.session_ttl = 1800  # 30 minutes in seconds
        
        # Fallback in-memory storage
        self.memory_sessions = {}
        self.memory_user_sessions = {}
        self.memory_active_sessions = set()
    
    async def add_session(self, token: str, user_data: Dict) -> bool:
        """Add a new session with Redis or fallback to memory"""
        try:
            if self.redis:
                return await self._add_session_redis(token, user_data)
            else:
                return self._add_session_memory(token, user_data)
        except Exception as e:
            logger.error(f"Error adding session: {e}")
            # Fallback to memory storage
            return self._add_session_memory(token, user_data)
    
    async def _add_session_redis(self, token: str, user_data: Dict) -> bool:
        """Add session using Redis"""
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
    
    def _add_session_memory(self, token: str, user_data: Dict) -> bool:
        """Add session using in-memory storage"""
        session_data = {
            "user_id": user_data["id"],
            "username": user_data.get("username", ""),
            "role": user_data["role"],
            "created_at": datetime.utcnow().isoformat(),
            "last_active": datetime.utcnow().isoformat(),
            "user_agent": user_data.get("user_agent", ""),
            "ip_address": user_data.get("ip_address", ""),
        }
        
        self.memory_sessions[token] = session_data
        self.memory_active_sessions.add(token)
        
        user_id = user_data["id"]
        if user_id not in self.memory_user_sessions:
            self.memory_user_sessions[user_id] = set()
        self.memory_user_sessions[user_id].add(token)
        
        logger.info(f"Session created in memory for user {user_data['id']}")
        return True
    
    async def remove_session(self, token: str) -> bool:
        """Remove a session"""
        try:
            if self.redis:
                return await self._remove_session_redis(token)
            else:
                return self._remove_session_memory(token)
        except Exception as e:
            logger.error(f"Error removing session: {e}")
            return self._remove_session_memory(token)
    
    async def _remove_session_redis(self, token: str) -> bool:
        """Remove session using Redis"""
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
    
    def _remove_session_memory(self, token: str) -> bool:
        """Remove session using in-memory storage"""
        if token in self.memory_sessions:
            session_info = self.memory_sessions[token]
            user_id = session_info.get("user_id")
            
            # Remove from memory storage
            del self.memory_sessions[token]
            self.memory_active_sessions.discard(token)
            
            if user_id and user_id in self.memory_user_sessions:
                self.memory_user_sessions[user_id].discard(token)
                if not self.memory_user_sessions[user_id]:
                    del self.memory_user_sessions[user_id]
            
            logger.info(f"Session removed from memory for user {user_id}")
            return True
        
        return False
    
    async def is_token_valid(self, token: str) -> bool:
        """Check if token is valid and active"""
        try:
            if self.redis:
                return await self._is_token_valid_redis(token)
            else:
                return self._is_token_valid_memory(token)
        except Exception as e:
            logger.error(f"Error checking token validity: {e}")
            return self._is_token_valid_memory(token)
    
    async def _is_token_valid_redis(self, token: str) -> bool:
        """Check token validity using Redis"""
        session_key = f"{self.session_prefix}{token}"
        session_data = await self.redis.get(session_key)
        return session_data is not None
    
    def _is_token_valid_memory(self, token: str) -> bool:
        """Check token validity using memory storage"""
        return token in self.memory_sessions
    
    async def get_user_from_token(self, token: str) -> Optional[Dict]:
        """Get user data from token"""
        try:
            if self.redis:
                return await self._get_user_from_token_redis(token)
            else:
                return self._get_user_from_token_memory(token)
        except Exception as e:
            logger.error(f"Error getting user from token: {e}")
            return self._get_user_from_token_memory(token)
    
    async def _get_user_from_token_redis(self, token: str) -> Optional[Dict]:
        """Get user data from token using Redis"""
        session_key = f"{self.session_prefix}{token}"
        session_data = await self.redis.get(session_key)
        
        if session_data:
            session_info = json.loads(session_data)
            return {
                "id": session_info["user_id"],
                "username": session_info["username"],
                "role": session_info["role"]
            }
        
        return None
    
    def _get_user_from_token_memory(self, token: str) -> Optional[Dict]:
        """Get user data from token using memory storage"""
        if token in self.memory_sessions:
            session_info = self.memory_sessions[token]
            return {
                "id": session_info["user_id"],
                "username": session_info["username"],
                "role": session_info["role"]
            }
        
        return None
    
    async def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get all sessions for a user"""
        try:
            if self.redis:
                return await self._get_user_sessions_redis(user_id)
            else:
                return self._get_user_sessions_memory(user_id)
        except Exception as e:
            logger.error(f"Error getting user sessions: {e}")
            return self._get_user_sessions_memory(user_id)
    
    async def _get_user_sessions_redis(self, user_id: str) -> List[Dict]:
        """Get user sessions using Redis"""
        user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
        tokens = await self.redis.smembers(user_sessions_key)
        
        sessions = []
        for token in tokens:
            session_data = await self.redis.get(f"{self.session_prefix}{token}")
            if session_data:
                sessions.append(json.loads(session_data))
        
        return sessions
    
    def _get_user_sessions_memory(self, user_id: str) -> List[Dict]:
        """Get user sessions using memory storage"""
        if user_id not in self.memory_user_sessions:
            return []
        
        sessions = []
        for token in self.memory_user_sessions[user_id]:
            if token in self.memory_sessions:
                sessions.append(self.memory_sessions[token])
        
        return sessions
    
    async def get_active_users_count(self) -> int:
        """Get count of active users"""
        try:
            if self.redis:
                return await self._get_active_users_count_redis()
            else:
                return self._get_active_users_count_memory()
        except Exception as e:
            logger.error(f"Error getting active users count: {e}")
            return self._get_active_users_count_memory()
    
    async def _get_active_users_count_redis(self) -> int:
        """Get active users count using Redis"""
        active_sessions = await self.redis.smembers("active_sessions")
        unique_users = set()
        
        for token in active_sessions:
            session_data = await self.redis.get(f"{self.session_prefix}{token}")
            if session_data:
                session_info = json.loads(session_data)
                unique_users.add(session_info["user_id"])
        
        return len(unique_users)
    
    def _get_active_users_count_memory(self) -> int:
        """Get active users count using memory storage"""
        unique_users = set()
        for session_info in self.memory_sessions.values():
            unique_users.add(session_info["user_id"])
        
        return len(unique_users)
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        try:
            if self.redis:
                return await self._cleanup_expired_sessions_redis()
            else:
                return self._cleanup_expired_sessions_memory()
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            return self._cleanup_expired_sessions_memory()
    
    async def _cleanup_expired_sessions_redis(self) -> int:
        """Clean up expired sessions using Redis"""
        # Redis automatically expires sessions, so just return 0
        return 0
    
    def _cleanup_expired_sessions_memory(self) -> int:
        """Clean up expired sessions using memory storage"""
        current_time = datetime.utcnow()
        expired_tokens = []
        
        for token, session_info in self.memory_sessions.items():
            created_at = datetime.fromisoformat(session_info["created_at"])
            if (current_time - created_at).total_seconds() > self.session_ttl:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            self._remove_session_memory(token)
        
        return len(expired_tokens)
    
    async def get_session_stats(self) -> Dict:
        """Get session statistics"""
        try:
            if self.redis:
                return await self._get_session_stats_redis()
            else:
                return self._get_session_stats_memory()
        except Exception as e:
            logger.error(f"Error getting session stats: {e}")
            return self._get_session_stats_memory()
    
    async def _get_session_stats_redis(self) -> Dict:
        """Get session statistics using Redis"""
        active_sessions = await self.redis.scard("active_sessions")
        
        return {
            "total_sessions": active_sessions,
            "active_users": await self._get_active_users_count_redis(),
            "storage_type": "redis"
        }
    
    def _get_session_stats_memory(self) -> Dict:
        """Get session statistics using memory storage"""
        return {
            "total_sessions": len(self.memory_active_sessions),
            "active_users": self._get_active_users_count_memory(),
            "storage_type": "memory"
        } 