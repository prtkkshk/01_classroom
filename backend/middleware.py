"""
Middleware for rate limiting, security headers, and request logging
"""

import time
import json
import logging
from typing import Dict, List
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import redis.asyncio as redis
from datetime import datetime, timedelta
import hashlib
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.rate_limits = {
            "default": {"requests": 100, "window": 60},  # 100 requests per minute
            "login": {"requests": 5, "window": 300},     # 5 login attempts per 5 minutes
            "register": {"requests": 3, "window": 3600}, # 3 registrations per hour
            "admin": {"requests": 1000, "window": 60},   # 1000 admin requests per minute
        }
    
    async def is_rate_limited(self, key: str, limit_type: str = "default") -> bool:
        """Check if request is rate limited"""
        try:
            limit = self.rate_limits.get(limit_type, self.rate_limits["default"])
            current_time = int(time.time())
            window_start = current_time - limit["window"]
            
            # Use Redis sorted set for sliding window rate limiting
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(current_time): current_time})
            pipe.zcard(key)
            pipe.expire(key, limit["window"])
            results = await pipe.execute()
            
            request_count = results[2]
            return request_count > limit["requests"]
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            return False  # Allow request if rate limiting fails
    
    def get_client_key(self, request: Request, limit_type: str = "default") -> str:
        """Generate unique key for rate limiting"""
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "")
        
        # For authenticated users, use user ID
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            # Simple hash of token for rate limiting (don't decode for performance)
            user_id = hashlib.md5(token.encode()).hexdigest()
            return f"rate_limit:{limit_type}:{user_id}"
        
        # For unauthenticated users, use IP + user agent
        return f"rate_limit:{limit_type}:{client_ip}:{hashlib.md5(user_agent.encode()).hexdigest()}"

class SecurityMiddleware:
    def __init__(self):
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    
    def add_security_headers(self, response: Response):
        """Add security headers to response"""
        for header, value in self.security_headers.items():
            response.headers[header] = value

class RequestLogger:
    def __init__(self):
        self.logger = logging.getLogger("request_logger")
        self.logger.setLevel(logging.INFO)
    
    def log_request(self, request: Request, response: Response, duration: float):
        """Log request details in structured format"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "url": str(request.url),
            "status_code": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent", ""),
            "content_length": response.headers.get("content-length", 0),
        }
        
        if response.status_code >= 400:
            self.logger.warning(f"Request failed: {log_data}")
        else:
            self.logger.info(f"Request completed: {log_data}")

# Global instances
rate_limiter = None
security_middleware = SecurityMiddleware()
request_logger = RequestLogger()

async def setup_middleware(redis_client: redis.Redis):
    """Setup middleware with Redis client"""
    global rate_limiter
    rate_limiter = RateLimiter(redis_client)

async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    if rate_limiter and request.url.path.startswith("/api"):
        # Determine rate limit type based on endpoint
        limit_type = "default"
        if request.url.path in ["/api/login", "/api/register"]:
            limit_type = "login"
        elif request.url.path == "/api/register":
            limit_type = "register"
        elif request.url.path.startswith("/api/admin"):
            limit_type = "admin"
        
        client_key = rate_limiter.get_client_key(request, limit_type)
        
        if await rate_limiter.is_rate_limited(client_key, limit_type):
            return JSONResponse(
                status_code=429,
                content={
                    "error": True,
                    "message": "Rate limit exceeded. Please try again later.",
                    "status_code": 429,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
    
    response = await call_next(request)
    return response

async def security_middleware_func(request: Request, call_next):
    """Security headers middleware"""
    response = await call_next(request)
    security_middleware.add_security_headers(response)
    
    # Add CORS headers
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    
    return response

async def error_handling_middleware(request: Request, call_next):
    """Error handling middleware"""
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "error": True,
                "message": "Internal server error",
                "status_code": 500,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

async def logging_middleware(request: Request, call_next):
    """Request logging middleware"""
    start_time = time.time()
    
    try:
        response = await call_next(request)
        duration = time.time() - start_time
        request_logger.log_request(request, response, duration)
        return response
    except Exception as e:
        duration = time.time() - start_time
        error_response = JSONResponse(
            status_code=500,
            content={
                "error": True,
                "message": "Internal server error",
                "status_code": 500,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        request_logger.log_request(request, error_response, duration)
        return error_response 