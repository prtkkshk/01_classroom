# Deployment fix - Force redeploy with CORS and CSP headers $(date)
# This comment ensures the latest version is deployed with security headers
# Fixed authentication error handling - removed problematic try-catch in get_courses endpoint

from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
import re
from email_validator import validate_email, EmailNotValidError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uuid
import random
import string
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
import json
from collections import defaultdict
import asyncio
from bson import ObjectId
import time
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Enhanced MongoDB connection with connection pooling
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(
    mongo_url,
    maxPoolSize=50,
    minPoolSize=10,
    maxIdleTimeMS=30000,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000,
    socketTimeoutMS=5000,
    retryWrites=True,
    retryReads=True,
    w="majority"
)
db = client[os.environ.get('DB_NAME', 'classroom_live')]

# Redis connection for caching and session management
redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
redis_client = None

async def get_redis():
    global redis_client
    if not REDIS_AVAILABLE:
        logger.warning("Redis package not available. Using in-memory fallback.")
        return None
    
    try:
        if redis_client is None:
            redis_client = redis.from_url(redis_url, decode_responses=True)
            # Test the connection
            await redis_client.ping()
            logger.info("Redis connection established successfully")
        return redis_client
    except Exception as e:
        logger.warning(f"Redis connection failed: {e}. Using in-memory fallback.")
        redis_client = None
        return None

# Security
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if SECRET_KEY == 'your-secret-key-here-change-in-production':
    logging.warning("[SECURITY] SECRET_KEY is using the default value! Set SECRET_KEY in your environment for production.")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# Create the main app
app = FastAPI(
    title="Classroom Live API", 
    version="2.0.0",
    docs_url="/docs" if os.environ.get('ENVIRONMENT') != 'production' else None,
    redoc_url="/redoc" if os.environ.get('ENVIRONMENT') != 'production' else None
)

# Enhanced CORS middleware with production-ready configuration
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:3001').split(',')
if os.environ.get('ENVIRONMENT') == 'production':
    allowed_origins = [
        "https://classroom-live.com",
        "https://www.classroom-live.com",
        "https://app.classroom-live.com",
        "https://zero1-classroom-1.onrender.com",
        "https://zero1-classroom-2.onrender.com"
    ]
else:
    # For development, be more specific
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,  
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "User-Agent", "DNT", "Cache-Control", "X-Mx-ReqToken", "Keep-Alive", "X-Requested-With", "If-Modified-Since"],
    expose_headers=["*"],
    max_age=3600
)

# Security middleware for adding security headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss:;"
    )
    
    return response

# Import enhanced components first
try:
    from middleware import setup_middleware, rate_limit_middleware, security_middleware_func, error_handling_middleware, logging_middleware
    from session_manager import EnhancedSessionManager
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    ENHANCED_FEATURES_AVAILABLE = False
    logging.warning("Enhanced features (middleware, session manager) not available. Using basic features.")

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "0.0.0.0", "classroom-live.onrender.com", "classroom-live.vercel.app", "zero1-classroom-1.onrender.com"]
)

# Add custom middleware if available
if ENHANCED_FEATURES_AVAILABLE:
    try:
        app.middleware("http")(logging_middleware)
        app.middleware("http")(security_middleware_func)
        # Temporarily disable error_handling_middleware to debug 500 errors
        # app.middleware("http")(error_handling_middleware)
        logger.info("Enhanced middleware added successfully")
    except Exception as e:
        logger.warning(f"Failed to add enhanced middleware: {e}")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Hardcoded credentials
PROFESSOR_USERNAME = "professor60201"
PROFESSOR_PASSWORD = "60201professor"
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

# In-memory session storage fallback
session_storage = {}
active_sessions = set()

# Global session manager - Initialize with basic fallback immediately
session_manager = EnhancedSessionManager() if ENHANCED_FEATURES_AVAILABLE else None

# Input validation and sanitization functions
def sanitize_input(text: str) -> str:
    """Sanitize input to prevent XSS and injection attacks"""
    if not text:
        return text
    
    import re
    
    # Only remove the most dangerous script tags and content
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    
    # Don't escape HTML entities for normal text - this was too aggressive
    # Only remove truly dangerous patterns
    text = re.sub(r'<\s*script', '', text, flags=re.IGNORECASE)
    
    # Trim whitespace
    text = text.strip()
    
    return text

def validate_email_format(email: str) -> bool:
    """Validate email format using email-validator"""
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def validate_password_strength(password: str) -> bool:
    """Validate password strength with reasonable requirements"""
    if not password or len(password) < 6:
        return False
    
    # Check for at least one letter and one digit, or allow longer passwords
    if len(password) >= 8:
        return True  # Longer passwords are acceptable even without complexity
    
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    
    return has_letter and has_digit

def validate_roll_number(roll_number: str) -> bool:
    """Validate roll number format"""
    # Allow alphanumeric with hyphens, underscores, and dots
    pattern = r'^[a-zA-Z0-9_\-\.]+$'
    return bool(re.match(pattern, roll_number)) and len(roll_number) <= 20

def validate_userid(userid: str) -> bool:
    """Validate user ID format"""
    # Allow alphanumeric with hyphens and underscores
    pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(pattern, userid)) and len(userid) <= 20

# Enhanced Pydantic models with validation
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password_hash: str
    role: str  # "student", "professor", "moderator"
    name: str
    roll_number: Optional[str] = None
    userid: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_active: Optional[datetime] = None

class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    roll_number: str

    @validator('email')
    def validate_email(cls, v):
        v = v.strip().lower()
        if not validate_email_format(v):
            raise ValueError('Invalid email format')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:  # Make password requirement less strict
            raise ValueError('Password must be at least 6 characters')
        return v

    @validator('name')
    def validate_name(cls, v):
        v = sanitize_input(v)
        if len(v) < 1 or len(v) > 100:  # More lenient length
            raise ValueError('Name must be between 1 and 100 characters')
        # More permissive regex to allow international names
        if not re.match(r'^[a-zA-Z0-9\s\-\'\.àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ]+$', v, re.IGNORECASE):
            raise ValueError('Name contains invalid characters')
        return v

    @validator('roll_number')
    def validate_roll_number(cls, v):
        if not v or len(v.strip()) < 1:
            raise ValueError("Roll number is required")
        
        # More permissive regex - allow more characters
        import re
        cleaned = v.strip()
        if not re.match(r'^[a-zA-Z0-9\-\_\.@]+$', cleaned):
            raise ValueError("Roll number contains invalid characters")
        
        if len(cleaned) > 50:
            raise ValueError("Roll number too long")
        
        return cleaned.upper()

    

class UserCreateProfessor(BaseModel):
    name: str
    userid: str
    email: str
    password: str

    @validator('email')
    def validate_email(cls, v):
        v = v.strip().lower()
        if not validate_email_format(v):
            raise ValueError('Invalid email format')
        return v

    @validator('password')
    def validate_password(cls, v):
        if not validate_password_strength(v):
            raise ValueError('Password must be at least 6 characters long')
        return v

    @validator('name')
    def validate_name(cls, v):
        if not v or len(v.strip()) < 2:
            raise ValueError("Name must be at least 2 characters long")
        
        # Allow letters, spaces, hyphens, apostrophes, and common name characters
        import re
        if not re.match(r'^[a-zA-Z\s\-\'\.]+$', v):
            raise ValueError("Name can only contain letters, spaces, hyphens, apostrophes, and periods")
        
        # Sanitize the name
        v = sanitize_input(v.strip())
        if len(v) < 2:
            raise ValueError("Name must be at least 2 characters long after sanitization")
        
        return v

    @validator('userid')
    def validate_userid(cls, v):
        if not v or len(v.strip()) < 3:
            raise ValueError("User ID must be at least 3 characters long")
        
        # Allow alphanumeric characters, hyphens, and underscores
        import re
        if not re.match(r'^[a-zA-Z0-9\-\_]+$', v):
            raise ValueError("User ID can only contain letters, numbers, hyphens, and underscores")
        
        # Sanitize the user ID
        v = sanitize_input(v.strip().lower())
        if len(v) < 3:
            raise ValueError("User ID must be at least 3 characters long after sanitization")
        
        return v

class UserLogin(BaseModel):
    username: str
    password: str

    @validator('username')
    def validate_username(cls, v):
        v = sanitize_input(v)
        if len(v) < 1:
            raise ValueError('Username cannot be empty')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 1:
            raise ValueError('Password cannot be empty')
        return v

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class Course(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    code: str  # 8-letter unique code
    professor_id: str
    professor_name: str
    students: List[str] = []  # List of student IDs
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class CourseCreate(BaseModel):
    name: str

class CourseJoin(BaseModel):
    code: str

class Question(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question_text: str
    user_id: str
    username: str
    course_id: str
    is_anonymous: bool = False
    is_answered: bool = False
    priority: int = 0  # For moderator prioritization
    tags: List[str] = []  # For categorization
    created_at: datetime = Field(default_factory=datetime.utcnow)
    answered_at: Optional[datetime] = None

class QuestionCreate(BaseModel):
    question_text: str
    course_id: str
    is_anonymous: bool = False
    tags: List[str] = []

class QuestionUpdate(BaseModel):
    question_text: Optional[str] = None
    is_answered: Optional[bool] = None
    priority: Optional[int] = None
    tags: Optional[List[str]] = None

class Poll(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question: str
    options: List[str]
    course_id: str
    created_by: str
    is_active: bool = True
    is_anonymous: bool = False
    allow_multiple: bool = False
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PollCreate(BaseModel):
    question: str
    options: List[str]
    course_id: str
    is_anonymous: bool = False
    allow_multiple: bool = False
    expires_minutes: Optional[int] = None

class Vote(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    poll_id: str
    user_id: str
    options_selected: List[str]  # Support multiple options
    created_at: datetime = Field(default_factory=datetime.utcnow)

class VoteCreate(BaseModel):
    poll_id: str
    options_selected: List[str]

class PollResults(BaseModel):
    poll: Poll
    votes: Dict[str, int]
    total_votes: int
    user_votes: Optional[List[str]] = None

class Session(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    token: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    is_active: bool = True
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None

class Announcement(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    course_id: str
    created_by: str
    priority: str = "normal"  # "low", "normal", "high", "urgent"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

class AnnouncementCreate(BaseModel):
    title: str
    content: str
    course_id: str
    priority: str = "normal"
    expires_hours: Optional[int] = None

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def generate_course_code():
    """Generate a unique 8-letter course code"""
    while True:
        code = ''.join(random.choices(string.ascii_uppercase, k=8))
        existing_course = await db.courses.find_one({"code": code})
        if not existing_course:
            return code

# Session Management
class SessionManager:
    def __init__(self):
        self.active_sessions = {}  # token -> user_data
        self.user_sessions = defaultdict(list)  # user_id -> list of tokens
        self.websocket_sessions = {}  # websocket -> user_data
    
    async def add_session(self, token, user_data):
        self.active_sessions[token] = user_data
        self.user_sessions[user_data['id']].append(token)
    
    async def remove_session(self, token):
        if token in self.active_sessions:
            user_data = self.active_sessions[token]
            if token in self.user_sessions[user_data['id']]:
                self.user_sessions[user_data['id']].remove(token)
            del self.active_sessions[token]
    
    def get_user_sessions(self, user_id):
        return self.user_sessions.get(user_id, [])
    
    async def is_token_valid(self, token):
        return token in self.active_sessions
    
    def get_user_from_token(self, token):
        return self.active_sessions.get(token)
    
    def get_active_users_count(self):
        return len(set(data['id'] for data in self.active_sessions.values()))

# Initialize enhanced session manager (will be set up in startup)
session_manager = None

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections = {}  # websocket -> user_data
        self.user_connections = defaultdict(list)  # user_id -> list of websockets
        self.course_connections = defaultdict(list)  # course_id -> list of websockets

    async def connect(self, websocket: WebSocket, user_data: dict):
        await websocket.accept()
        self.active_connections[websocket] = user_data
        self.user_connections[user_data['id']].append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            user_data = self.active_connections[websocket]
            if websocket in self.user_connections[user_data['id']]:
                self.user_connections[user_data['id']].remove(websocket)
            del self.active_connections[websocket]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except:
            self.disconnect(websocket)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections.keys()):
            try:
                await connection.send_text(message)
            except:
                self.disconnect(connection)

    async def broadcast_to_course(self, course_id: str, message: str):
        # Get all users enrolled in the course
        course = await db.courses.find_one({"id": course_id})
        if not course:
            return
        
        # Include professor and all students
        target_users = [course["professor_id"]] + course.get("students", [])
        
        for connection, user_data in list(self.active_connections.items()):
            if user_data['id'] in target_users:
                try:
                    await connection.send_text(message)
                except:
                    self.disconnect(connection)

    async def send_to_user(self, user_id: str, message: str):
        for connection in self.user_connections[user_id][:]:
            try:
                await connection.send_text(message)
            except:
                self.user_connections[user_id].remove(connection)
                if connection in self.active_connections:
                    del self.active_connections[connection]

# Create connection manager instance
manager = ConnectionManager()

# Include the API router
app.include_router(api_router)

# Authentication function
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Unexpected error in JWT validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Try to find user by roll_number first (students), then by userid (professors/moderators)
        user = await db.users.find_one({"roll_number": username})
        if not user:
            user = await db.users.find_one({"userid": username})
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Convert ObjectId to string for JSON serialization
        if "_id" in user:
            user["_id"] = str(user["_id"])
        
        # Update last active timestamp (don't fail authentication if this fails)
        try:
            await db.users.update_one(
                {"_id": ObjectId(user["_id"]) if isinstance(user["_id"], str) else user["_id"]},
                {"$set": {"last_active": datetime.utcnow()}}
            )
        except Exception as e:
            logger.warning(f"Failed to update last_active: {e}")
        
        return User(**user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Database error in get_current_user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error"
        )

# Optional authentication for WebSocket
async def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            logger.warning("JWT payload missing 'sub' field in WebSocket auth")
            return None
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired in WebSocket auth")
        return None
    except jwt.JWTError as e:
        logger.warning(f"JWT validation error in WebSocket auth: {str(e)}")
        return None
    
    try:
        # Try to find user by roll_number first (students), then by userid (professors/moderators)
        user = await db.users.find_one({"roll_number": username})
        if not user:
            user = await db.users.find_one({"userid": username})
        
        if user is None:
            logger.warning(f"User not found for username in WebSocket auth: {username}")
            return None
        
        # Convert ObjectId to string for JSON serialization
        if "_id" in user:
            user["_id"] = str(user["_id"])
        
        logger.info(f"WebSocket user authenticated: {user.get('name', 'Unknown')} with role: {user.get('role', 'Unknown')}")
        return user
    except Exception as e:
        logger.error(f"Database error in WebSocket get_user_from_token: {e}")
        return None

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    try:
        user_data = {"id": "anonymous", "username": "anonymous", "role": "guest"}
        
        if token:
            user = await get_user_from_token(token)
            if user:
                username_field = user.get("roll_number") if user["role"] == "student" else user.get("userid")
                user_data = {
                    "id": user["id"],
                    "username": username_field,
                    "role": user["role"],
                    "name": user["name"]
                }
        
        await manager.connect(websocket, user_data)
        
        while True:
            try:
                data = await websocket.receive_text()
                message_data = json.loads(data)
                message_type = message_data.get("type")
                
                if message_type == "join_course":
                    course_id = message_data.get("course_id")
                    if course_id and user_data["id"] != "anonymous":
                        course = await db.courses.find_one({"id": course_id})
                        if course and (user_data["id"] == course["professor_id"] or user_data["id"] in course.get("students", [])):
                            await manager.send_personal_message(
                                json.dumps({"type": "course_joined", "course_id": course_id}),
                                websocket
                            )
                
                elif message_type == "ping":
                    await manager.send_personal_message(
                        json.dumps({"type": "pong", "timestamp": datetime.utcnow().isoformat()}),
                        websocket
                    )
                    
            except json.JSONDecodeError:
                await manager.broadcast(f"Message from {user_data['username']}: {data}")
            except Exception as e:
                logger.error(f"WebSocket message error: {e}")
                break
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        try:
            await websocket.close()
        except:
            pass
        manager.disconnect(websocket)

# Auth Routes
@api_router.post("/register", response_model=Token)
async def register(user_data: UserCreate):
    try:
        # Check if roll number already exists
        existing_roll = await db.users.find_one({"roll_number": user_data.roll_number})
        if existing_roll:
            raise HTTPException(status_code=400, detail="Roll number already registered")
        
        existing_email = await db.users.find_one({"email": user_data.email})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user with unique ID
        user_dict = user_data.model_dump()
        user_dict["password_hash"] = get_password_hash(user_data.password)
        user_dict["role"] = "student"
        user_dict["id"] = str(uuid.uuid4())  # Ensure unique ID
        user_dict.pop("password")
        
        user_obj = User(**user_dict)
        
        try:
            # Use upsert to handle race conditions
            result = await db.users.replace_one(
                {"$or": [{"email": user_data.email}, {"roll_number": user_data.roll_number}]},
                user_obj.model_dump(),
                upsert=True
            )
            
            # If matched_count > 0, it means user already exists
            if result.matched_count > 0:
                raise HTTPException(status_code=400, detail="Email or roll number already registered")
                
        except Exception as e:
            if "duplicate key error" in str(e).lower() or "11000" in str(e):
                raise HTTPException(status_code=400, detail="Email or roll number already registered")
            logger.error(f"Database error during registration: {e}")
            raise HTTPException(status_code=500, detail="Registration failed due to database error")
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_obj.roll_number}, expires_delta=access_token_expires
        )
        
        user_data_dict = {
            "id": user_obj.id,
            "username": user_obj.roll_number,
            "email": user_obj.email,
            "role": user_obj.role,
            "name": user_obj.name,
            "roll_number": user_obj.roll_number
        }
        
        # Add session
        try:
            if session_manager:
                await session_manager.add_session(access_token, user_data_dict)
        except Exception as e:
            logger.warning(f"Failed to add session: {e}")
            # Continue without session if session manager fails
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error during registration")

@api_router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin):
    try:
        # Check if it's moderator login
        if user_credentials.username == MODERATOR_USERNAME and user_credentials.password == MODERATOR_PASSWORD:
            moderator = await db.users.find_one({"userid": MODERATOR_USERNAME})
            if not moderator:
                moderator = await db.users.find_one({"role": "moderator"})
                if moderator and not moderator.get("userid"):
                    await db.users.update_one(
                        {"id": moderator["id"]}, 
                        {"$set": {"userid": MODERATOR_USERNAME}}
                    )
                    moderator["userid"] = MODERATOR_USERNAME
            
            if not moderator:
                moderator_user = User(
                    id=str(uuid.uuid4()),
                    email="moderator@classroom.com",
                    password_hash=get_password_hash(MODERATOR_PASSWORD),
                    role="moderator",
                    name="Moderator",
                    userid=MODERATOR_USERNAME
                )
                await db.users.insert_one(moderator_user.model_dump())
                moderator = moderator_user.model_dump()
            
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": MODERATOR_USERNAME}, expires_delta=access_token_expires
            )
            
            user_data_dict = {
                "id": moderator["id"],
                "username": moderator["userid"],
                "email": moderator["email"],
                "role": moderator["role"],
                "name": moderator.get("name", "Moderator"),
                "userid": moderator["userid"]
            }
            
            try:
                if session_manager:
                    await session_manager.add_session(access_token, user_data_dict)
            except Exception as e:
                logger.warning(f"Failed to add session: {e}")
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": user_data_dict
            }
        
        # Check if it's professor login
        if user_credentials.username == PROFESSOR_USERNAME and user_credentials.password == PROFESSOR_PASSWORD:
            professor = await db.users.find_one({"userid": PROFESSOR_USERNAME})
            if not professor:
                professor = await db.users.find_one({"role": "professor"})
                if professor and not professor.get("userid"):
                    await db.users.update_one(
                        {"id": professor["id"]}, 
                        {"$set": {"userid": PROFESSOR_USERNAME}}
                    )
                    professor["userid"] = PROFESSOR_USERNAME
            
            if not professor:
                professor_user = User(
                    id=str(uuid.uuid4()),
                    email="professor@classroom.com",
                    password_hash=get_password_hash(PROFESSOR_PASSWORD),
                    role="professor",
                    name="Professor",
                    userid=PROFESSOR_USERNAME
                )
                await db.users.insert_one(professor_user.model_dump())
                professor = professor_user.model_dump()
            
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(
                data={"sub": PROFESSOR_USERNAME}, expires_delta=access_token_expires
            )
            
            user_data_dict = {
                "id": professor["id"],
                "username": professor["userid"],
                "email": professor["email"],
                "role": professor["role"],
                "name": professor.get("name", "Professor"),
                "userid": professor["userid"]
            }
            
            try:
                if session_manager:
                    await session_manager.add_session(access_token, user_data_dict)
            except Exception as e:
                logger.warning(f"Failed to add session: {e}")
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "user": user_data_dict
            }
        
        # Regular user login
        user = await db.users.find_one({"roll_number": user_credentials.username})
        if not user:
            user = await db.users.find_one({"userid": user_credentials.username})
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        if not verify_password(user_credentials.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Convert ObjectId to string for JSON serialization
        if "_id" in user:
            user["_id"] = str(user["_id"])
        
        username_field = user.get("roll_number") if user["role"] == "student" else user.get("userid")
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username_field}, expires_delta=access_token_expires
        )
        
        user_data_dict = {
            "id": user["id"],
            "username": username_field,
            "email": user["email"],
            "role": user["role"],
            "name": user["name"],
            "roll_number": user.get("roll_number"),
            "userid": user.get("userid")
        }
        
        try:
            if session_manager:
                await session_manager.add_session(access_token, user_data_dict)
        except Exception as e:
            logger.warning(f"Failed to add session: {e}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

@api_router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        if session_manager:
            await session_manager.remove_session(token)
        return {"message": "Logged out successfully"}
    except Exception as e:
        logger.warning(f"Logout error: {e}")
        return {"message": "Logged out successfully"}

# Course Routes
@api_router.post("/courses", response_model=Course)
async def create_course(course_data: CourseCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can create courses")
    
    code = await generate_course_code()
    
    course = Course(
        name=course_data.name,
        code=code,
        professor_id=current_user.id,
        professor_name=current_user.name
    )
    
    await db.courses.insert_one(course.model_dump())
    return course

@api_router.get("/courses", response_model=List[Course])
async def get_courses(current_user: User = Depends(get_current_user)):
    logger.info(f"User accessing courses: {current_user.id}, role: {current_user.role}")
    
    if current_user.role == "professor":
        courses = await db.courses.find({"professor_id": current_user.id, "is_active": True}).to_list(1000)
    elif current_user.role == "student":
        courses = await db.courses.find({"students": current_user.id, "is_active": True}).to_list(1000)
    elif current_user.role == "moderator":
        courses = await db.courses.find({"is_active": True}).to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Invalid role")
    
    courses = fix_mongo_ids(courses)
    logger.info(f"Found {len(courses)} courses for user {current_user.id}")
    return [Course(**course) for course in courses]

@api_router.post("/courses/join")
async def join_course(course_data: CourseJoin, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can join courses")
    
    course = await db.courses.find_one({"code": course_data.code.upper(), "is_active": True})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if current_user.id in course["students"]:
        raise HTTPException(status_code=400, detail="Already enrolled in this course")
    
    await db.courses.update_one(
        {"id": course["id"]},
        {"$push": {"students": current_user.id}}
    )
    
    # Notify via WebSocket
    await manager.send_to_user(
        course["professor_id"],
        json.dumps({
            "type": "student_joined",
            "course_id": course["id"],
            "student_name": current_user.name,
            "student_id": current_user.id
        })
    )
    
    return {"message": f"Successfully joined course: {course['name']}"}

@api_router.delete("/courses/{course_id}")
async def delete_course(course_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can delete courses")
    
    course = await db.courses.find_one({"id": course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own courses")
    
    # Soft delete - mark as inactive
    await db.courses.update_one({"id": course_id}, {"$set": {"is_active": False}})
    
    return {"message": "Course deleted successfully"}

@api_router.get("/courses/{course_id}/students")
async def get_course_students(course_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    course = await db.courses.find_one({"id": course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    students = []
    for student_id in course["students"]:
        student = await db.users.find_one({"id": student_id})
        if student:
            students.append({
                "id": student["id"],
                "name": student["name"],
                "roll_number": student.get("roll_number"),
                "email": student["email"],
                "last_active": student.get("last_active")
            })
    
    return {"students": students, "total_count": len(students)}

# Question Routes
@api_router.post("/questions", response_model=Question)
async def create_question(question_data: QuestionCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can ask questions")
    
    course = await db.courses.find_one({"id": question_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if current_user.id not in course["students"]:
        raise HTTPException(status_code=403, detail="You must be enrolled in this course to ask questions")
    
    question_dict = question_data.model_dump()
    question_dict["user_id"] = current_user.id
    question_dict["username"] = current_user.name if not question_data.is_anonymous else "Anonymous"
    
    question_obj = Question(**question_dict)
    await db.questions.insert_one(question_obj.model_dump())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        question_data.course_id,
        json.dumps({
            "type": "new_question",
            "data": question_obj.model_dump()
        }, default=str)
    )
    
    return question_obj

@api_router.get("/questions", response_model=List[Question])
async def get_questions(course_id: str = None, current_user: User = Depends(get_current_user)):
    if course_id:
        # Verify access to course
        course = await db.courses.find_one({"id": course_id})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        
        if (current_user.role == "student" and current_user.id not in course["students"]) or \
           (current_user.role == "professor" and course["professor_id"] != current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        
        questions = await db.questions.find({"course_id": course_id}).sort([("priority", -1), ("created_at", -1)]).to_list(1000)
    else:
        if current_user.role != "moderator":
            raise HTTPException(status_code=400, detail="Course ID is required")
        questions = await db.questions.find().sort([("priority", -1), ("created_at", -1)]).to_list(1000)
    questions = fix_mongo_ids(questions)
    return [Question(**question) for question in questions]

@api_router.get("/questions/my", response_model=List[Question])
async def get_my_questions(course_id: str = None, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can view their own questions")
    
    query = {"user_id": current_user.id}
    if course_id:
        query["course_id"] = course_id
    
    questions = await db.questions.find(query).sort("created_at", -1).to_list(1000)
    questions = fix_mongo_ids(questions)
    return [Question(**question) for question in questions]

@api_router.put("/questions/{question_id}", response_model=Question)
async def update_question(question_id: str, question_update: QuestionUpdate, current_user: User = Depends(get_current_user)):
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Students can only update their own questions (text and tags)
    if current_user.role == "student":
        if question["user_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="You can only update your own questions")
        # Students cannot change priority or answered status
        if question_update.priority is not None or question_update.is_answered is not None:
            raise HTTPException(status_code=403, detail="You cannot change priority or answered status")
    
    # Professors can mark questions as answered and change priority
    elif current_user.role == "professor":
        course = await db.courses.find_one({"id": question["course_id"]})
        if not course or course["professor_id"] != current_user.id:
            raise HTTPException(status_code=403, detail="You can only update questions in your courses")
        # Professors cannot change question text
        if question_update.question_text is not None:
            raise HTTPException(status_code=403, detail="Professors cannot edit question text")
    
    update_data = {k: v for k, v in question_update.dict().items() if v is not None}
    
    # Set answered timestamp if marking as answered
    if question_update.is_answered is True and not question.get("is_answered"):
        update_data["answered_at"] = datetime.utcnow()
    
    if update_data:
        await db.questions.update_one({"id": question_id}, {"$set": update_data})
    
    updated_question = await db.questions.find_one({"id": question_id})
    
    # Broadcast update to course participants
    await manager.broadcast_to_course(
        question["course_id"],
        json.dumps({
            "type": "question_updated",
            "data": updated_question
        }, default=str)
    )
    
    return Question(**updated_question)

@api_router.delete("/questions/{question_id}")
async def delete_question(question_id: str, current_user: User = Depends(get_current_user)):
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Only students can delete their own questions
    if current_user.role != "student" or question["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own questions")
    
    await db.questions.delete_one({"id": question_id})
    
    # Broadcast deletion to course participants
    await manager.broadcast_to_course(
        question["course_id"],
        json.dumps({
            "type": "question_deleted",
            "question_id": question_id
        })
    )
    
    return {"message": "Question deleted successfully"}

# Poll Routes
@api_router.post("/polls", response_model=Poll)
async def create_poll(poll_data: PollCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can create polls")
    
    course = await db.courses.find_one({"id": poll_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Professors can only create polls in their own courses
    # Moderators can create polls in any course
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only create polls in your own courses")
    
    poll_dict = poll_data.model_dump()
    poll_dict["created_by"] = current_user.id
    
    # Set expiration time if specified
    if poll_data.expires_minutes:
        poll_dict["expires_at"] = datetime.utcnow() + timedelta(minutes=poll_data.expires_minutes)
    
    poll_dict.pop("expires_minutes", None)
    
    poll_obj = Poll(**poll_dict)
    await db.polls.insert_one(poll_obj.model_dump())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        poll_data.course_id,
        json.dumps({
            "type": "new_poll",
            "data": poll_obj.model_dump()
        }, default=str)
    )
    
    return poll_obj

@api_router.get("/polls", response_model=List[Poll])
async def get_polls(course_id: str = None, current_user: User = Depends(get_current_user)):
    if course_id:
        course = await db.courses.find_one({"id": course_id})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        
        if (current_user.role == "student" and current_user.id not in course["students"]) or \
           (current_user.role == "professor" and course["professor_id"] != current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Filter out expired polls for students
        query = {"course_id": course_id, "is_active": True}
        if current_user.role == "student":
            query["$or"] = [
                {"expires_at": None},
                {"expires_at": {"$gt": datetime.utcnow()}}
            ]
        
        polls = await db.polls.find(query).sort("created_at", -1).to_list(1000)
    else:
        if current_user.role != "moderator":
            raise HTTPException(status_code=400, detail="Course ID is required")
        polls = await db.polls.find({"is_active": True}).sort("created_at", -1).to_list(1000)
    polls = fix_mongo_ids(polls)
    return [Poll(**poll) for poll in polls]

@api_router.post("/polls/{poll_id}/vote")
async def vote_on_poll(poll_id: str, vote_data: VoteCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can vote")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if not poll.get("is_active", True):
        raise HTTPException(status_code=400, detail="Poll is not active")
    
    # Check if poll has expired
    if poll.get("expires_at") and poll["expires_at"] < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Poll has expired")
    
    # Check if user has already voted
    existing_vote = await db.votes.find_one({"poll_id": poll_id, "user_id": current_user.id})
    if existing_vote:
        raise HTTPException(status_code=400, detail="You have already voted on this poll")
    
    # Validate selected options
    if not poll.get("allow_multiple", False) and len(vote_data.options_selected) > 1:
        raise HTTPException(status_code=400, detail="This poll only allows single selection")
    
    for option in vote_data.options_selected:
        if option not in poll["options"]:
            raise HTTPException(status_code=400, detail=f"Invalid option: {option}")
    
    vote_dict = vote_data.model_dump()
    vote_dict["user_id"] = current_user.id
    
    vote_obj = Vote(**vote_dict)
    await db.votes.insert_one(vote_obj.model_dump())
    
    # Broadcast vote update to professor (anonymous if poll is anonymous)
    if not poll.get("is_anonymous", False):
        voter_info = {"name": current_user.name, "roll_number": current_user.roll_number}
    else:
        voter_info = {"name": "Anonymous", "roll_number": "***"}
    
    await manager.send_to_user(
        poll["created_by"],
        json.dumps({
            "type": "new_vote",
            "poll_id": poll_id,
            "voter": voter_info,
            "options": vote_data.options_selected
        })
    )
    
    return {"message": "Vote recorded successfully"}

@api_router.get("/polls/{poll_id}/results", response_model=PollResults)
async def get_poll_results(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can view poll results")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if current_user.role == "professor" and poll["created_by"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only view results for your own polls")
    
    votes = await db.votes.find({"poll_id": poll_id}).to_list(1000)
    
    # Count votes for each option
    vote_counts = {option: 0 for option in poll["options"]}
    for vote in votes:
        for option in vote["options_selected"]:
            vote_counts[option] += 1
    
    return PollResults(
        poll=Poll(**poll),
        votes=vote_counts,
        total_votes=len(votes)
    )

@api_router.get("/polls/{poll_id}/user-vote")
async def get_user_vote(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can check their votes")
    
    vote = await db.votes.find_one({"poll_id": poll_id, "user_id": current_user.id})
    if vote:
        return {"voted": True, "options": vote["options_selected"]}
    return {"voted": False}

@api_router.delete("/polls/{poll_id}")
async def delete_poll(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can delete polls")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    # Professors can only delete their own polls
    # Moderators can delete any poll
    if current_user.role == "professor" and poll["created_by"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own polls")
    
    # Soft delete - mark as inactive
    await db.polls.update_one({"id": poll_id}, {"$set": {"is_active": False}})
    
    # Broadcast deletion to course participants
    await manager.broadcast_to_course(
        poll["course_id"],
        json.dumps({
            "type": "poll_deleted",
            "poll_id": poll_id
        })
    )
    
    return {"message": "Poll deleted successfully"}

# Announcement Routes
@api_router.post("/announcements", response_model=Announcement)
async def create_announcement(announcement_data: AnnouncementCreate, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can create announcements")
    
    course = await db.courses.find_one({"id": announcement_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Professors can only create announcements in their own courses
    # Moderators can create announcements in any course
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only create announcements in your own courses")
    
    announcement_dict = announcement_data.model_dump()
    announcement_dict["created_by"] = current_user.id
    
    # Set expiration time if specified
    if announcement_data.expires_hours:
        announcement_dict["expires_at"] = datetime.utcnow() + timedelta(hours=announcement_data.expires_hours)
    
    announcement_dict.pop("expires_hours", None)
    
    announcement_obj = Announcement(**announcement_dict)
    await db.announcements.insert_one(announcement_obj.model_dump())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        announcement_data.course_id,
        json.dumps({
            "type": "new_announcement",
            "data": announcement_obj.model_dump()
        }, default=str)
    )
    
    return announcement_obj

@api_router.get("/announcements")
async def get_announcements(course_id: str = None, current_user: User = Depends(get_current_user)):
    if course_id:
        course = await db.courses.find_one({"id": course_id})
        if not course:
            raise HTTPException(status_code=404, detail="Course not found")
        
        if (current_user.role == "student" and current_user.id not in course["students"]) or \
           (current_user.role == "professor" and course["professor_id"] != current_user.id):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Filter out expired announcements
        query = {
            "course_id": course_id,
            "$or": [
                {"expires_at": None},
                {"expires_at": {"$gt": datetime.utcnow()}}
            ]
        }
        
        announcements = await db.announcements.find(query).sort([("priority", -1), ("created_at", -1)]).to_list(1000)
    else:
        if current_user.role != "moderator":
            raise HTTPException(status_code=400, detail="Course ID is required")
        announcements = await db.announcements.find().sort([("priority", -1), ("created_at", -1)]).to_list(1000)
    announcements = fix_mongo_ids(announcements)
    return [Announcement(**announcement) for announcement in announcements]

@api_router.delete("/announcements/{announcement_id}")
async def delete_announcement(announcement_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can delete announcements")
    
    announcement = await db.announcements.find_one({"id": announcement_id})
    if not announcement:
        raise HTTPException(status_code=404, detail="Announcement not found")
    
    if current_user.role == "professor" and announcement["created_by"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own announcements")
    
    await db.announcements.delete_one({"id": announcement_id})
    
    # Broadcast deletion to course participants
    await manager.broadcast_to_course(
        announcement["course_id"],
        json.dumps({
            "type": "announcement_deleted",
            "announcement_id": announcement_id
        })
    )
    
    return {"message": "Announcement deleted successfully"}

# Admin/Moderator Routes
@api_router.post("/admin/create-professor", response_model=Token)
async def create_professor(professor_data: UserCreateProfessor, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can create professor accounts")
    
    try:
        # Check for existing users
        existing_email = await db.users.find_one({"email": professor_data.email})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        existing_userid = await db.users.find_one({"userid": professor_data.userid})
        if existing_userid:
            raise HTTPException(status_code=400, detail="User ID already registered")
        
        # Create professor with unique identifiers
        professor_dict = professor_data.model_dump()
        professor_dict["id"] = str(uuid.uuid4())
        professor_dict["password_hash"] = get_password_hash(professor_data.password)
        professor_dict["role"] = "professor"
        professor_dict["created_at"] = datetime.utcnow()
        professor_dict.pop("password")
        
        # Ensure we don't have roll_number conflicts
        professor_dict["roll_number"] = None
        
        professor_obj = User(**professor_dict)
        
        result = await db.users.insert_one(professor_obj.model_dump())
        logger.info(f"Professor created successfully: {result.inserted_id}")
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": professor_obj.userid}, expires_delta=access_token_expires
        )
        
        user_data_dict = {
            "id": professor_obj.id,
            "username": professor_obj.userid,
            "email": professor_obj.email,
            "role": professor_obj.role,
            "name": professor_obj.name,
            "userid": professor_obj.userid
        }
        
        try:
            if session_manager:
                await session_manager.add_session(access_token, user_data_dict)
        except Exception as e:
            logger.warning(f"Failed to add session for professor: {e}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating professor: {str(e)}")
        if "duplicate key error" in str(e).lower() or "11000" in str(e):
            raise HTTPException(status_code=400, detail="User ID or email already exists")
        raise HTTPException(status_code=500, detail="Failed to create professor account")

def fix_mongo_ids(doc):
    # Recursively convert ObjectId to str in a dict or list
    if isinstance(doc, list):
        return [fix_mongo_ids(item) for item in doc]
    if isinstance(doc, dict):
        return {k: (str(v) if isinstance(v, ObjectId) else fix_mongo_ids(v)) for k, v in doc.items()}
    return doc

@api_router.get("/admin/users")
async def get_all_users(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    users = await db.users.find().sort("created_at", -1).to_list(1000)
    
    # Remove sensitive information
    for user in users:
        user.pop("password_hash", None)
    
    users = fix_mongo_ids(users)
    return {"users": users, "total_count": len(users)}

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Check if user exists
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # If deleting a professor, also delete their courses
    if user["role"] == "professor":
        await db.courses.update_many(
            {"professor_id": user_id},
            {"$set": {"is_active": False}}
        )
    
    # If deleting a student, remove from all courses
    if user["role"] == "student":
        await db.courses.update_many(
            {"students": user_id},
            {"$pull": {"students": user_id}}
        )
    
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deleted successfully"}

@api_router.get("/admin/stats")
async def get_admin_stats(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    # Get counts for all entities
    users_count = await db.users.count_documents({})
    questions_count = await db.questions.count_documents({})
    polls_count = await db.polls.count_documents({"is_active": True})
    votes_count = await db.votes.count_documents({})
    courses_count = await db.courses.count_documents({"is_active": True})
    announcements_count = await db.announcements.count_documents({})
    
    # Get counts by role
    students_count = await db.users.count_documents({"role": "student"})
    professors_count = await db.users.count_documents({"role": "professor"})
    moderators_count = await db.users.count_documents({"role": "moderator"})
    
    # Get answered questions count
    answered_questions = await db.questions.count_documents({"is_answered": True})
    unanswered_questions = questions_count - answered_questions
    
    # Get total students enrolled in courses
    total_enrollments = 0
    courses = await db.courses.find({"is_active": True}).to_list(1000)
    for course in courses:
        total_enrollments += len(course.get("students", []))
    
    # Get active sessions
    try:
        if session_manager:
            active_sessions = await session_manager.get_active_users_count()
        else:
            active_sessions = 0
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        active_sessions = 0
    
    return {
        "total_users": users_count,
        "students": students_count,
        "professors": professors_count,
        "moderators": moderators_count,
        "total_questions": questions_count,
        "answered_questions": answered_questions,
        "unanswered_questions": unanswered_questions,
        "total_polls": polls_count,
        "total_votes": votes_count,
        "total_courses": courses_count,
        "total_enrollments": total_enrollments,
        "total_announcements": announcements_count,
        "active_users": active_sessions
    }

@api_router.get("/admin/active-sessions")
async def get_active_sessions(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    try:
        if session_manager is None:
            return {
                "total_active_sessions": 0,
                "unique_users": 0,
                "user_sessions": {}
            }
        
        # Get session statistics from session manager
        stats = await session_manager.get_session_stats()
        
        return {
            "total_active_sessions": stats.get("total_sessions", 0),
            "unique_users": stats.get("active_users", 0),
            "user_sessions": {},
            "storage_type": stats.get("storage_type", "unknown")
        }
    except Exception as e:
        logger.error(f"Error getting active sessions: {e}")
        return {
            "total_active_sessions": 0,
            "unique_users": 0,
            "user_sessions": {},
            "error": "Failed to retrieve session data"
        }

# Additional admin endpoints for full CRUD
@api_router.delete("/admin/questions/{question_id}")
async def delete_any_question(question_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    await db.questions.delete_one({"id": question_id})
    
    # Broadcast deletion
    await manager.broadcast_to_course(
        question["course_id"],
        json.dumps({
            "type": "question_deleted",
            "question_id": question_id,
            "deleted_by": "moderator"
        })
    )
    
    return {"message": "Question deleted successfully"}

@api_router.put("/admin/questions/{question_id}", response_model=Question)
async def update_any_question(question_id: str, question_update: QuestionUpdate, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    update_data = {k: v for k, v in question_update.model_dump().items() if v is not None}
    
    if question_update.is_answered is True and not question.get("is_answered"):
        update_data["answered_at"] = datetime.utcnow()
    
    if update_data:
        await db.questions.update_one({"id": question_id}, {"$set": update_data})
    
    updated_question = await db.questions.find_one({"id": question_id})
    
    # Broadcast update
    await manager.broadcast_to_course(
        question["course_id"],
        json.dumps({
            "type": "question_updated",
            "data": updated_question,
            "updated_by": "moderator"
        }, default=str)
    )
    
    return Question(**updated_question)

@api_router.delete("/admin/polls/{poll_id}")
async def delete_any_poll(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    # Delete all votes for this poll first
    await db.votes.delete_many({"poll_id": poll_id})
    
    # Delete the poll
    
    await db.polls.delete_one({"id": poll_id})
    
    # Broadcast deletion
    await manager.broadcast_to_course(
        poll["course_id"],
        json.dumps({
            "type": "poll_deleted",
            "poll_id": poll_id,
            "deleted_by": "moderator"
        })
    )
    
    return {"message": "Poll and all associated votes deleted successfully"}

@api_router.get("/admin/votes")
async def get_all_votes(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    votes = await db.votes.find().sort("created_at", -1).to_list(1000)
    votes = fix_mongo_ids(votes)
    return {"votes": votes, "total_count": len(votes)}

@api_router.delete("/admin/votes/{vote_id}")
async def delete_vote(vote_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    result = await db.votes.delete_one({"id": vote_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Vote not found")
    
    return {"message": "Vote deleted successfully"}

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Classroom Live API",
        "version": "2.0.0",
        "status": "running",
        "docs": "/docs",
        "health": "/api/health",
        "info": "/api/info"
    }

# Simple status endpoint for monitoring
@app.get("/status")
async def status():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }

# Health check and info endpoints
@api_router.get("/health")
async def health_check():
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {}
    }
    
    # Test database connection
    try:
        await db.users.find_one()
        health_status["components"]["database"] = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        health_status["components"]["database"] = "unhealthy"
        health_status["status"] = "degraded"
    
    # Test Redis connection
    try:
        redis_client = await get_redis()
        if redis_client:
            await redis_client.ping()
            health_status["components"]["redis"] = "healthy"
        else:
            health_status["components"]["redis"] = "not_configured"
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        health_status["components"]["redis"] = "unhealthy"
        health_status["status"] = "degraded"
    
    # Get active sessions count
    try:
        if session_manager and hasattr(session_manager, 'get_active_users_count'):
            active_sessions = await session_manager.get_active_users_count()
        elif session_manager and hasattr(session_manager, 'memory_active_sessions'):
            active_sessions = len(session_manager.memory_active_sessions)
        else:
            active_sessions = 0
        health_status["components"]["sessions"] = "healthy"
        health_status["active_sessions"] = active_sessions
    except Exception as e:
        logger.error(f"Session count error: {str(e)}")
        health_status["components"]["sessions"] = "unhealthy"
        health_status["active_sessions"] = 0
        health_status["status"] = "degraded"
    
    # Get websocket count
    try:
        active_websockets = len(manager.active_connections) if manager else 0
        health_status["components"]["websockets"] = "healthy"
        health_status["active_websockets"] = active_websockets
    except Exception as e:
        logger.error(f"WebSocket count error: {str(e)}")
        health_status["components"]["websockets"] = "unhealthy"
        health_status["active_websockets"] = 0
        health_status["status"] = "degraded"
    
    # Add API uptime
    import time
    health_status["uptime_seconds"] = time.time() - app.start_time if hasattr(app, 'start_time') else 0
    
    from fastapi.responses import JSONResponse
    response = JSONResponse(health_status)
    
    # Add CSP header
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    
    return response

@api_router.get("/info")
async def get_api_info():
    from fastapi.responses import JSONResponse
    response = JSONResponse({
        "name": "Classroom Live API",
        "version": "2.0.0",
        "features": [
            "User Authentication (Students, Professors, Moderators)",
            "Course Management",
            "Real-time Questions & Answers",
            "Interactive Polls with Multiple Options",
            "Course Announcements",
            "WebSocket Real-time Updates",
            "Session Management",
            "Admin Dashboard"
        ],
        "endpoints": {
            "auth": ["/api/register", "/api/login", "/api/logout"],
            "courses": ["/api/courses", "/api/courses/join"],
            "questions": ["/api/questions", "/api/questions/my"],
            "polls": ["/api/polls", "/api/polls/{id}/vote", "/api/polls/{id}/results"],
            "announcements": ["/api/announcements"],
            "admin": ["/api/admin/users", "/api/admin/stats", "/api/admin/create-professor"]
        }
    })
    
    # Add CSP header
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
    
    return response

# Add middleware to the app (if available)
if ENHANCED_FEATURES_AVAILABLE:
    app.middleware("http")(error_handling_middleware)
    app.middleware("http")(security_middleware_func)
    app.middleware("http")(rate_limit_middleware)
    logger.info("Enhanced middleware added")
else:
    logger.info("Using basic middleware (enhanced features not available)")

# Include the router in the main app
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://zero1-classroom-1.onrender.com",
        "https://zero1-classroom-2.onrender.com",
    ],
    allow_origin_regex=r"https://.*\.onrender\.com",  # Allow all onrender.com subdomains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Background tasks
async def cleanup_expired_sessions():
    """Clean up expired sessions periodically"""
    while True:
        try:
            if session_manager:
                expired_count = await session_manager.cleanup_expired_sessions()
                if expired_count > 0:
                    logger.info(f"Cleaned up {expired_count} expired sessions")
            await asyncio.sleep(3600)  # 1 hour
        except Exception as e:
            logger.error(f"Session cleanup error: {str(e)}")
            await asyncio.sleep(300)  # Wait 5 minutes on error

async def deactivate_expired_polls():
    """Deactivate expired polls periodically"""
    while True:
        try:
            current_time = datetime.utcnow()
            expired_polls = await db.polls.find({
                "expires_at": {"$lt": current_time},
                "is_active": True
            }).to_list(1000)
            for poll in expired_polls:
                await db.polls.update_one(
                    {"id": poll["id"]},
                    {"$set": {"is_active": False}}
                )
                await manager.broadcast_to_course(
                    poll["course_id"],
                    json.dumps({
                        "type": "poll_expired",
                        "poll_id": poll["id"]
                    })
                )
            if expired_polls:
                logger.info(f"Deactivated {len(expired_polls)} expired polls")
            await asyncio.sleep(600)  # 10 minutes
        except Exception as e:
            logger.error(f"Poll expiration check error: {str(e)}")
            await asyncio.sleep(300)

# NOTE: SessionManager is in-memory and will lose all sessions on server restart. For production, use a persistent store.
# NOTE: Background tasks will run in each process if using multiple workers (e.g., gunicorn), which may cause race conditions.

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    import time
    app.start_time = time.time()
    
    logger.info("Starting Classroom Live API...")
    
    # Initialize database connection
    try:
        await db.users.find_one()
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise
    
    # Initialize Redis connection
    try:
        redis_client = await get_redis()
        if redis_client:
            await redis_client.ping()
            logger.info("Redis connection established")
        else:
            logger.warning("Redis not configured, using memory fallback")
    except Exception as e:
        logger.warning(f"Redis connection failed, using memory fallback: {e}")
    
    # Initialize session manager
    global session_manager
    if ENHANCED_FEATURES_AVAILABLE:
        try:
            session_manager = EnhancedSessionManager(redis_client)
            logger.info("Enhanced session manager initialized")
        except Exception as e:
            logger.warning(f"Enhanced session manager failed, using basic: {e}")
            session_manager = SessionManager()
    else:
        session_manager = SessionManager()
        logger.info("Basic session manager initialized")
    
    # Initialize connection manager
    global manager
    manager = ConnectionManager()
    logger.info("Connection manager initialized")
    
    # Create database indexes
    try:
        await db.users.create_index("email", unique=True)
    except Exception as e:
        logger.warning(f"Failed to create users email index: {e}")
    
    try:
        await db.users.create_index("roll_number", unique=True)
    except Exception as e:
        logger.warning(f"Failed to create users roll_number index: {e}")
    
    try:
        await db.users.create_index("userid", unique=True)
    except Exception as e:
        logger.warning(f"Failed to create users userid index: {e}")
    
    try:
        await db.courses.create_index("code", unique=True)
    except Exception as e:
        logger.warning(f"Failed to create courses code index: {e}")
    
    try:
        await db.courses.create_index("professor_id")
    except Exception as e:
        logger.warning(f"Failed to create courses professor_id index: {e}")
    
    try:
        await db.questions.create_index("course_id")
    except Exception as e:
        logger.warning(f"Failed to create questions course_id index: {e}")
    
    try:
        await db.questions.create_index("user_id")
    except Exception as e:
        logger.warning(f"Failed to create questions user_id index: {e}")
    
    try:
        await db.questions.create_index("created_at")
    except Exception as e:
        logger.warning(f"Failed to create questions created_at index: {e}")
    
    try:
        await db.polls.create_index("course_id")
    except Exception as e:
        logger.warning(f"Failed to create polls course_id index: {e}")
    
    try:
        await db.polls.create_index("created_by")
    except Exception as e:
        logger.warning(f"Failed to create polls created_by index: {e}")
    
    try:
        await db.polls.create_index("created_at")
    except Exception as e:
        logger.warning(f"Failed to create polls created_at index: {e}")
    
    try:
        await db.polls.create_index("expires_at")
    except Exception as e:
        logger.warning(f"Failed to create polls expires_at index: {e}")
    
    try:
        await db.votes.create_index("poll_id")
    except Exception as e:
        logger.warning(f"Failed to create votes poll_id index: {e}")
    
    try:
        await db.votes.create_index("user_id")
    except Exception as e:
        logger.warning(f"Failed to create votes user_id index: {e}")
    
    try:
        await db.votes.create_index([("poll_id", 1), ("user_id", 1)], unique=True)
    except Exception as e:
        logger.warning(f"Failed to create votes compound index: {e}")
    
    try:
        await db.votes.create_index("created_at")
    except Exception as e:
        logger.warning(f"Failed to create votes created_at index: {e}")
    
    try:
        await db.announcements.create_index("course_id")
    except Exception as e:
        logger.warning(f"Failed to create announcements course_id index: {e}")
    
    try:
        await db.announcements.create_index("created_by")
    except Exception as e:
        logger.warning(f"Failed to create announcements created_by index: {e}")
    
    try:
        await db.announcements.create_index("created_at")
    except Exception as e:
        logger.warning(f"Failed to create announcements created_at index: {e}")
    
    try:
        await db.announcements.create_index("expires_at")
    except Exception as e:
        logger.warning(f"Failed to create announcements expires_at index: {e}")
    
    logger.info("Database indexes created successfully")
    
    # Start background tasks
    asyncio.create_task(cleanup_expired_sessions())
    asyncio.create_task(deactivate_expired_polls())
    
    logger.info("Classroom Live API started successfully with enhanced features")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Classroom Live API...")
    client.close()
    if session_manager:
        try:
            # Clear memory sessions if using memory fallback
            if hasattr(session_manager, 'memory_sessions'):
                session_manager.memory_sessions.clear()
                session_manager.memory_user_sessions.clear()
                session_manager.memory_active_sessions.clear()
        except Exception as e:
            logger.warning(f"Error clearing sessions during shutdown: {e}")
    logger.info("Classroom Live API shutdown complete")

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Remove the general exception handler or make it much more specific
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    # NEVER catch HTTPExceptions here - they should bubble up
    if isinstance(exc, HTTPException):
        raise exc
    
    # Only log truly unexpected errors and return 500
    logger.error(f"Unhandled exception in {request.method} {request.url}: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "message": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=True if os.environ.get("ENVIRONMENT") == "development" else False,
        log_level="info"
    )