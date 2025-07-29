from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'classroom_live')]

# Security
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app
app = FastAPI(title="Classroom Live API", version="2.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Hardcoded credentials
PROFESSOR_USERNAME = "professor60201"
PROFESSOR_PASSWORD = "60201professor"
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

# Pydantic Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    password_hash: str
    role: str  # "student", "professor", "moderator"
    name: str
    roll_number: Optional[str] = None  # For students (acts as username)
    userid: Optional[str] = None  # For professors/moderators (acts as username)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_active: Optional[datetime] = None

class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    roll_number: str

class UserCreateProfessor(BaseModel):
    name: str
    userid: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

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
    
    def add_session(self, token, user_data):
        self.active_sessions[token] = user_data
        self.user_sessions[user_data['id']].append(token)
    
    def remove_session(self, token):
        if token in self.active_sessions:
            user_data = self.active_sessions[token]
            if token in self.user_sessions[user_data['id']]:
                self.user_sessions[user_data['id']].remove(token)
            del self.active_sessions[token]
    
    def get_user_sessions(self, user_id):
        return self.user_sessions.get(user_id, [])
    
    def is_token_valid(self, token):
        return token in self.active_sessions
    
    def get_user_from_token(self, token):
        return self.active_sessions.get(token)
    
    def get_active_users_count(self):
        return len(set(data['id'] for data in self.active_sessions.values()))

# Create session manager instance
session_manager = SessionManager()

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

# Authentication function
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    # Try to find user by roll_number first (students), then by userid (professors/moderators)
    user = await db.users.find_one({"roll_number": username})
    if not user:
        user = await db.users.find_one({"userid": username})
    
    if user is None:
        raise credentials_exception
    
    # Update last active timestamp
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"last_active": datetime.utcnow()}}
    )
    
    # Re-add to session manager if not present
    if not session_manager.is_token_valid(token):
        username_field = user.get("roll_number") if user["role"] == "student" else user.get("userid")
        user_data_dict = {
            "id": user["id"],
            "username": username_field,
            "email": user["email"],
            "role": user["role"],
            "name": user["name"],
            "roll_number": user.get("roll_number"),
            "userid": user.get("userid")
        }
        session_manager.add_session(token, user_data_dict)
    
    return User(**user)

# Optional authentication for WebSocket
async def get_user_from_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except jwt.PyJWTError:
        return None
    
    user = await db.users.find_one({"roll_number": username})
    if not user:
        user = await db.users.find_one({"userid": username})
    
    return user

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
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
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)
                message_type = message_data.get("type")
                
                if message_type == "join_course":
                    course_id = message_data.get("course_id")
                    if course_id and user_data["id"] != "anonymous":
                        # Verify user has access to course
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
                # Handle plain text messages
                await manager.broadcast(f"Message from {user_data['username']}: {data}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Auth Routes
@api_router.post("/register", response_model=Token)
async def register(user_data: UserCreate):
    try:
        # Validate input data
        if not user_data.name or not user_data.name.strip():
            raise HTTPException(status_code=422, detail="Name is required")
        
        if not user_data.roll_number or not user_data.roll_number.strip():
            raise HTTPException(status_code=422, detail="Roll number is required")
        
        if not user_data.email or not user_data.email.strip():
            raise HTTPException(status_code=422, detail="Email is required")
        
        if not user_data.password or len(user_data.password) < 6:
            raise HTTPException(status_code=422, detail="Password must be at least 6 characters")
        
        # Check if roll number already exists
        existing_roll = await db.users.find_one({"roll_number": user_data.roll_number})
        if existing_roll:
            raise HTTPException(status_code=400, detail="Roll number already registered")
        
        existing_email = await db.users.find_one({"email": user_data.email})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        user_dict = user_data.dict()
        user_dict["password_hash"] = get_password_hash(user_data.password)
        user_dict["role"] = "student"
        user_dict.pop("password")
        
        user_obj = User(**user_dict)
        await db.users.insert_one(user_obj.dict())
        
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
        
        # Add to session manager
        session_manager.add_session(access_token, user_data_dict)
        
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
            await db.users.insert_one(moderator_user.dict())
            moderator = moderator_user.dict()
        
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
        
        session_manager.add_session(access_token, user_data_dict)
        
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
            await db.users.insert_one(professor_user.dict())
            professor = professor_user.dict()
        
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
        
        session_manager.add_session(access_token, user_data_dict)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
    
    # Regular user login
    user = await db.users.find_one({"roll_number": user_credentials.username})
    if not user:
        user = await db.users.find_one({"userid": user_credentials.username})
    
    if not user or not verify_password(user_credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect roll number/user ID or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
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
        "name": user.get("name", ""),
        "roll_number": user.get("roll_number"),
        "userid": user.get("userid")
    }
    
    session_manager.add_session(access_token, user_data_dict)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data_dict
    }

@api_router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    session_manager.remove_session(token)
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
    
    await db.courses.insert_one(course.dict())
    return course

@api_router.get("/courses", response_model=List[Course])
async def get_courses(current_user: User = Depends(get_current_user)):
    if current_user.role == "professor":
        courses = await db.courses.find({"professor_id": current_user.id, "is_active": True}).to_list(1000)
    elif current_user.role == "student":
        courses = await db.courses.find({"students": current_user.id, "is_active": True}).to_list(1000)
    elif current_user.role == "moderator":
        courses = await db.courses.find({"is_active": True}).to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Invalid role")
    
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
    
    question_dict = question_data.dict()
    question_dict["user_id"] = current_user.id
    question_dict["username"] = current_user.name if not question_data.is_anonymous else "Anonymous"
    
    question_obj = Question(**question_dict)
    await db.questions.insert_one(question_obj.dict())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        question_data.course_id,
        json.dumps({
            "type": "new_question",
            "data": question_obj.dict()
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
    
    return [Question(**question) for question in questions]

@api_router.get("/questions/my", response_model=List[Question])
async def get_my_questions(course_id: str = None, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can view their own questions")
    
    query = {"user_id": current_user.id}
    if course_id:
        query["course_id"] = course_id
    
    questions = await db.questions.find(query).sort("created_at", -1).to_list(1000)
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
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can create polls")
    
    course = await db.courses.find_one({"id": poll_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only create polls in your own courses")
    
    poll_dict = poll_data.dict()
    poll_dict["created_by"] = current_user.id
    
    # Set expiration time if specified
    if poll_data.expires_minutes:
        poll_dict["expires_at"] = datetime.utcnow() + timedelta(minutes=poll_data.expires_minutes)
    
    poll_dict.pop("expires_minutes", None)
    
    poll_obj = Poll(**poll_dict)
    await db.polls.insert_one(poll_obj.dict())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        poll_data.course_id,
        json.dumps({
            "type": "new_poll",
            "data": poll_obj.dict()
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
    
    vote_dict = vote_data.dict()
    vote_dict["user_id"] = current_user.id
    
    vote_obj = Vote(**vote_dict)
    await db.votes.insert_one(vote_obj.dict())
    
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
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can delete polls")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    if poll["created_by"] != current_user.id:
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
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can create announcements")
    
    course = await db.courses.find_one({"id": announcement_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only create announcements in your own courses")
    
    announcement_dict = announcement_data.dict()
    announcement_dict["created_by"] = current_user.id
    
    # Set expiration time if specified
    if announcement_data.expires_hours:
        announcement_dict["expires_at"] = datetime.utcnow() + timedelta(hours=announcement_data.expires_hours)
    
    announcement_dict.pop("expires_hours", None)
    
    announcement_obj = Announcement(**announcement_dict)
    await db.announcements.insert_one(announcement_obj.dict())
    
    # Broadcast to course participants
    await manager.broadcast_to_course(
        announcement_data.course_id,
        json.dumps({
            "type": "new_announcement",
            "data": announcement_obj.dict()
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
    
    existing_email = await db.users.find_one({"email": professor_data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_userid = await db.users.find_one({"userid": professor_data.userid})
    if existing_userid:
        raise HTTPException(status_code=400, detail="User ID already registered")
    
    professor_dict = professor_data.dict()
    professor_dict["password_hash"] = get_password_hash(professor_data.password)
    professor_dict["role"] = "professor"
    professor_dict.pop("password")
    
    professor_obj = User(**professor_dict)
    await db.users.insert_one(professor_obj.dict())
    
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
    
    session_manager.add_session(access_token, user_data_dict)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data_dict
    }

@api_router.get("/admin/users")
async def get_all_users(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    users = await db.users.find().sort("created_at", -1).to_list(1000)
    
    # Remove sensitive information
    for user in users:
        user.pop("password_hash", None)
    
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
    active_sessions = session_manager.get_active_users_count()
    
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
    
    active_sessions = session_manager.active_sessions
    session_count = len(active_sessions)
    
    # Group by user
    user_session_count = defaultdict(int)
    user_details = {}
    
    for user_data in active_sessions.values():
        username = user_data['username']
        user_session_count[username] += 1
        if username not in user_details:
            user_details[username] = {
                "name": user_data.get('name', 'Unknown'),
                "role": user_data.get('role', 'Unknown'),
                "sessions": 0
            }
        user_details[username]["sessions"] += 1
    
    return {
        "total_active_sessions": session_count,
        "unique_users": len(user_session_count),
        "user_sessions": user_details
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
    
    update_data = {k: v for k, v in question_update.dict().items() if v is not None}
    
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
    return {"votes": votes, "total_count": len(votes)}

@api_router.delete("/admin/votes/{vote_id}")
async def delete_vote(vote_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    result = await db.votes.delete_one({"id": vote_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Vote not found")
    
    return {"message": "Vote deleted successfully"}

# Health check and info endpoints
@api_router.get("/health")
async def health_check():
    try:
        # Test database connection
        await db.users.find_one()
        db_status = "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        db_status = "unhealthy"
    
    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "database": db_status,
        "active_sessions": len(session_manager.active_sessions),
        "active_websockets": len(manager.active_connections),
        "timestamp": datetime.utcnow().isoformat()
    }

@api_router.get("/info")
async def get_api_info():
    return {
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
    }

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
    allow_origin_regex=r"https://.*\\.onrender\\.com",  # Allow all onrender.com subdomains
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
            # Clean up database sessions (if using database session manager)
            expired_count = 0
            current_time = datetime.utcnow()
            
            # Remove expired tokens from session manager
            expired_tokens = []
            for token, user_data in session_manager.active_sessions.items():
                try:
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    exp = payload.get("exp")
                    if exp and datetime.utcfromtimestamp(exp) < current_time:
                        expired_tokens.append(token)
                except jwt.PyJWTError:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                session_manager.remove_session(token)
                expired_count += 1
            
            if expired_count > 0:
                logger.info(f"Cleaned up {expired_count} expired sessions")
            
            # Wait 1 hour before next cleanup
            await asyncio.sleep(3600)
            
        except Exception as e:
            logger.error(f"Session cleanup error: {str(e)}")
            await asyncio.sleep(300)  # Wait 5 minutes on error

async def deactivate_expired_polls():
    """Deactivate expired polls periodically"""
    while True:
        try:
            current_time = datetime.utcnow()
            
            # Find and deactivate expired polls
            expired_polls = await db.polls.find({
                "expires_at": {"$lt": current_time},
                "is_active": True
            }).to_list(1000)
            
            for poll in expired_polls:
                await db.polls.update_one(
                    {"id": poll["id"]},
                    {"$set": {"is_active": False}}
                )
                
                # Notify course participants
                await manager.broadcast_to_course(
                    poll["course_id"],
                    json.dumps({
                        "type": "poll_expired",
                        "poll_id": poll["id"]
                    })
                )
            
            if expired_polls:
                logger.info(f"Deactivated {len(expired_polls)} expired polls")
            
            # Wait 10 minutes before next check
            await asyncio.sleep(600)
            
        except Exception as e:
            logger.error(f"Poll expiration check error: {str(e)}")
            await asyncio.sleep(300)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logger.info("Starting Classroom Live API...")
    
    # Create database indexes for better performance
    try:
        # User indexes
        await db.users.create_index("email", unique=True)
        await db.users.create_index("roll_number", unique=True, sparse=True)
        await db.users.create_index("userid", unique=True, sparse=True)
        
        # Course indexes
        await db.courses.create_index("code", unique=True)
        await db.courses.create_index("professor_id")
        await db.courses.create_index("is_active")
        
        # Question indexes
        await db.questions.create_index([("course_id", 1), ("created_at", -1)])
        await db.questions.create_index("user_id")
        await db.questions.create_index("is_answered")
        
        # Poll indexes
        await db.polls.create_index([("course_id", 1), ("created_at", -1)])
        await db.polls.create_index("created_by")
        await db.polls.create_index("is_active")
        await db.polls.create_index("expires_at")
        
        # Vote indexes
        await db.votes.create_index([("poll_id", 1), ("user_id", 1)], unique=True)
        await db.votes.create_index("poll_id")
        
        # Announcement indexes
        await db.announcements.create_index([("course_id", 1), ("created_at", -1)])
        await db.announcements.create_index("expires_at")
        
        logger.info("Database indexes created successfully")
        
    except Exception as e:
        logger.warning(f"Index creation warning: {str(e)}")
    
    # Start background tasks
    asyncio.create_task(cleanup_expired_sessions())
    asyncio.create_task(deactivate_expired_polls())
    
    logger.info("Classroom Live API started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down Classroom Live API...")
    
    # Close database connection
    client.close()
    
    # Clear session manager
    session_manager.active_sessions.clear()
    session_manager.user_sessions.clear()
    
    logger.info("Classroom Live API shutdown complete")

# Root endpoint
@app.get("/")
async def read_root():
    return {
        "message": "Welcome to Classroom Live API v2.0.0",
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/api/health",
        "info": "/api/info"
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return {
        "error": True,
        "message": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return {
        "error": True,
        "message": "Internal server error",
        "status_code": 500,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=True if os.environ.get("ENVIRONMENT") == "development" else False,
        log_level="info"
    )