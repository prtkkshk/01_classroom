"""
Production configuration for Classroom Live API
"""

import os
from typing import List

class Config:
    """Base configuration"""
    # Database
    MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
    DB_NAME = os.environ.get('DB_NAME', 'classroom_live')
    
    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES', '30'))
    
    # CORS
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:3001').split(',')
    
    # Rate Limiting
    RATE_LIMIT_DEFAULT = int(os.environ.get('RATE_LIMIT_DEFAULT', '100'))
    RATE_LIMIT_LOGIN = int(os.environ.get('RATE_LIMIT_LOGIN', '5'))
    RATE_LIMIT_REGISTER = int(os.environ.get('RATE_LIMIT_REGISTER', '3'))
    RATE_LIMIT_ADMIN = int(os.environ.get('RATE_LIMIT_ADMIN', '1000'))
    
    # Session
    SESSION_TTL = int(os.environ.get('SESSION_TTL', '1800'))  # 30 minutes
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Environment
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
    
    # Performance
    MAX_CONNECTIONS = int(os.environ.get('MAX_CONNECTIONS', '50'))
    MIN_CONNECTIONS = int(os.environ.get('MIN_CONNECTIONS', '10'))
    
    # Monitoring
    ENABLE_METRICS = os.environ.get('ENABLE_METRICS', 'false').lower() == 'true'
    
    @classmethod
    def get_cors_origins(cls) -> List[str]:
        """Get CORS origins based on environment"""
        if cls.ENVIRONMENT == 'production':
            return [
                "https://classroom-live.com",
                "https://www.classroom-live.com",
                "https://app.classroom-live.com",
                "https://zero1-classroom-1.onrender.com",
                "https://zero1-classroom-2.onrender.com"
            ]
        return cls.ALLOWED_ORIGINS

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    RELOAD = True

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    RELOAD = False
    
    # Stricter security in production
    ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Shorter token lifetime
    SESSION_TTL = 900  # 15 minutes
    
    # Higher rate limits for production
    RATE_LIMIT_DEFAULT = 200
    RATE_LIMIT_ADMIN = 2000

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    MONGO_URL = os.environ.get('TEST_MONGO_URL', 'mongodb://localhost:27017/test')
    REDIS_URL = os.environ.get('TEST_REDIS_URL', 'redis://localhost:6379/1')

def get_config():
    """Get configuration based on environment"""
    env = os.environ.get('ENVIRONMENT', 'development')
    
    if env == 'production':
        return ProductionConfig()
    elif env == 'testing':
        return TestingConfig()
    else:
        return DevelopmentConfig() 