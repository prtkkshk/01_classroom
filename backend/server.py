from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
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
SECRET_KEY = "your-secret-key-here-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Hardcoded professor credentials
PROFESSOR_USERNAME = "professor60201"
PROFESSOR_PASSWORD = "60201professor"

# Hardcoded moderator credentials
MODERATOR_USERNAME = "pepper_moderator"
MODERATOR_PASSWORD = "pepper_14627912"

# Pydantic Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    password_hash: str
    role: str  # "student" or "professor"
    name: str
    roll_number: Optional[str] = None  # For students
    userid: Optional[str] = None  # For professors
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserCreate(BaseModel):
    username: str
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

class Question(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question_text: str
    user_id: str
    username: str
    course_id: str  # Add course_id field
    is_anonymous: bool = False
    is_answered: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

class QuestionCreate(BaseModel):
    question_text: str
    course_id: str  # Add course_id field
    is_anonymous: bool = False

class QuestionUpdate(BaseModel):
    question_text: Optional[str] = None
    is_answered: Optional[bool] = None

class Poll(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question: str
    options: List[str]
    course_id: str  # Add course_id field
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PollCreate(BaseModel):
    question: str
    options: List[str]
    course_id: str  # Add course_id field

class Vote(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    poll_id: str
    user_id: str
    option_selected: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class VoteCreate(BaseModel):
    poll_id: str
    option_selected: str

class PollResults(BaseModel):
    poll: Poll
    votes: Dict[str, int]
    total_votes: int

class Course(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    code: str  # 8-letter unique code
    professor_id: str
    professor_name: str
    students: List[str] = []  # List of student IDs
    created_at: datetime = Field(default_factory=datetime.utcnow)

class CourseCreate(BaseModel):
    name: str

class CourseJoin(BaseModel):
    code: str

class Session(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    token: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    is_active: bool = True

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
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def generate_course_code():
    """Generate a unique 8-letter course code"""
    while True:
        code = ''.join(random.choices(string.ascii_uppercase, k=8))
        # Check if code already exists
        existing_course = await db.courses.find_one({"code": code})
        if not existing_course:
            return code

# Session Management
class SessionManager:
    def __init__(self):
        self.active_sessions = {}  # token -> user_data
        self.user_sessions = defaultdict(list)  # user_id -> list of tokens
        self.websocket_sessions = {}  # websocket -> token
    
    def add_session(self, token, user_data):
        self.active_sessions[token] = user_data
        self.user_sessions[user_data['id']].append(token)
    
    def remove_session(self, token):
        if token in self.active_sessions:
            user_data = self.active_sessions[token]
            self.user_sessions[user_data['id']].remove(token)
            del self.active_sessions[token]
    
    def get_user_sessions(self, user_id):
        return self.user_sessions.get(user_id, [])
    
    def is_token_valid(self, token):
        return token in self.active_sessions
    
    def get_user_from_token(self, token):
        return self.active_sessions.get(token)

# Create session manager instance
session_manager = SessionManager()

# Database Session Manager (optional - for better scalability)
class DatabaseSessionManager:
    def __init__(self, db):
        self.db = db
    
    async def add_session(self, token, user_data):
        expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        session = Session(
            user_id=user_data['id'],
            token=token,
            expires_at=expires_at
        )
        await self.db.sessions.insert_one(session.dict())
    
    async def remove_session(self, token):
        await self.db.sessions.update_one(
            {"token": token},
            {"$set": {"is_active": False}}
        )
    
    async def is_token_valid(self, token):
        session = await self.db.sessions.find_one({
            "token": token,
            "is_active": True,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        return session is not None
    
    async def cleanup_expired_sessions(self):
        await self.db.sessions.update_many(
            {"expires_at": {"$lt": datetime.utcnow()}},
            {"$set": {"is_active": False}}
        )

# Create database session manager
db_session_manager = DatabaseSessionManager(db)

# Connection Manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections = {}  # websocket -> user_data
        self.user_connections = defaultdict(list)  # user_id -> list of websockets

    async def connect(self, websocket: WebSocket, user_data: dict):
        await websocket.accept()
        self.active_connections[websocket] = user_data
        self.user_connections[user_data['id']].append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            user_data = self.active_connections[websocket]
            self.user_connections[user_data['id']].remove(websocket)
            del self.active_connections[websocket]

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in list(self.active_connections.keys()):
            try:
                await connection.send_text(message)
            except:
                self.disconnect(connection)

    async def send_to_user(self, user_id: str, message: str):
        for connection in self.user_connections[user_id]:
            try:
                await connection.send_text(message)
            except:
                self.user_connections[user_id].remove(connection)

# Create connection manager instance
manager = ConnectionManager()

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # For now, we'll accept all connections
    await manager.connect(websocket, {"id": "anonymous"})
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"Client message: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Authentication function - THIS MUST BE DEFINED BEFORE BEING USED
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    
    # First check if token is in active sessions
    if not session_manager.is_token_valid(token):
        raise credentials_exception
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = await db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    
    return User(**user)

# Auth Routes
@api_router.post("/register", response_model=Token)
async def register(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    existing_email = await db.users.find_one({"email": user_data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if roll number already exists
    existing_roll = await db.users.find_one({"roll_number": user_data.roll_number})
    if existing_roll:
        raise HTTPException(status_code=400, detail="Roll number already registered")
    
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
        data={"sub": user_obj.username}, expires_delta=access_token_expires
    )
    
    user_data_dict = {
        "id": user_obj.id,
        "username": user_obj.username,
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

@api_router.post("/login", response_model=Token)
async def login(user_credentials: UserLogin):
    # Check if it's moderator login
    if user_credentials.username == MODERATOR_USERNAME and user_credentials.password == MODERATOR_PASSWORD:
        # Create or get moderator user
        moderator = await db.users.find_one({"username": MODERATOR_USERNAME})
        if not moderator:
            moderator_user = User(
                username=MODERATOR_USERNAME,
                email="moderator@classroom.com",
                password_hash=get_password_hash(MODERATOR_PASSWORD),
                role="moderator"
            )
            await db.users.insert_one(moderator_user.dict())
            moderator = moderator_user.dict()
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": MODERATOR_USERNAME}, expires_delta=access_token_expires
        )
        
        user_data_dict = {
            "id": moderator["id"],
            "username": moderator["username"],
            "email": moderator["email"],
            "role": moderator["role"],
            "name": moderator.get("name", "Moderator"),
            "roll_number": moderator.get("roll_number"),
            "userid": moderator.get("userid")
        }
        
        # Add to session manager
        session_manager.add_session(access_token, user_data_dict)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
    
    # Check if it's professor login
    if user_credentials.username == PROFESSOR_USERNAME and user_credentials.password == PROFESSOR_PASSWORD:
        # Create or get professor user
        professor = await db.users.find_one({"username": PROFESSOR_USERNAME})
        if not professor:
            professor_user = User(
                username=PROFESSOR_USERNAME,
                email="professor@classroom.com",
                password_hash=get_password_hash(PROFESSOR_PASSWORD),
                role="professor"
            )
            await db.users.insert_one(professor_user.dict())
            professor = professor_user.dict()
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": PROFESSOR_USERNAME}, expires_delta=access_token_expires
        )
        
        user_data_dict = {
            "id": professor["id"],
            "username": professor["username"],
            "email": professor["email"],
            "role": professor["role"],
            "name": professor.get("name", "Professor"),
            "roll_number": professor.get("roll_number"),
            "userid": professor.get("userid")
        }
        
        # Add to session manager
        session_manager.add_session(access_token, user_data_dict)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data_dict
        }
    
    # Regular student login
    user = await db.users.find_one({"username": user_credentials.username})
    if not user or not verify_password(user_credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    
    user_data_dict = {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "name": user.get("name", ""),
        "roll_number": user.get("roll_number"),
        "userid": user.get("userid")
    }
    
    # Add to session manager
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

# Question Routes
@api_router.post("/questions", response_model=Question)
async def create_question(question_data: QuestionCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can ask questions")
    
    # Verify user is enrolled in the course
    course = await db.courses.find_one({"id": question_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if current_user.id not in course["students"]:
        raise HTTPException(status_code=403, detail="You must be enrolled in this course to ask questions")
    
    question_dict = question_data.dict()
    question_dict["user_id"] = current_user.id
    question_dict["username"] = current_user.username if not question_data.is_anonymous else "Anonymous"
    
    question_obj = Question(**question_dict)
    await db.questions.insert_one(question_obj.dict())
    
    # Broadcast new question to all connected clients
    await manager.broadcast(json.dumps({
        "type": "new_question",
        "data": question_obj.dict(),
    }, default=str))
    
    return question_obj

@api_router.get("/questions", response_model=List[Question])
async def get_questions(course_id: str = None, current_user: User = Depends(get_current_user)):
    if course_id:
        # Get questions for specific course
        questions = await db.questions.find({"course_id": course_id}).sort("created_at", -1).to_list(1000)
    else:
        # Get all questions (for moderators or when no course specified)
        if current_user.role != "moderator":
            raise HTTPException(status_code=400, detail="Course ID is required")
        questions = await db.questions.find().sort("created_at", -1).to_list(1000)
    
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
    
    # Students can only update their own questions
    if current_user.role == "student" and question["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only update your own questions")
    
    # Professors can mark any question as answered
    if current_user.role == "professor" and question_update.question_text is not None:
        raise HTTPException(status_code=403, detail="Professors can only mark questions as answered")
    
    update_data = {k: v for k, v in question_update.dict().items() if v is not None}
    if update_data:
        await db.questions.update_one({"id": question_id}, {"$set": update_data})
    
    updated_question = await db.questions.find_one({"id": question_id})
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
    return {"message": "Question deleted successfully"}

# Poll Routes
@api_router.post("/polls", response_model=Poll)
async def create_poll(poll_data: PollCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can create polls")
    
    # Verify professor owns the course
    course = await db.courses.find_one({"id": poll_data.course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    if course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only create polls in your own courses")
    
    poll_dict = poll_data.dict()
    poll_dict["created_by"] = current_user.id
    
    poll_obj = Poll(**poll_dict)
    await db.polls.insert_one(poll_obj.dict())
    
    return poll_obj

@api_router.get("/polls", response_model=List[Poll])
async def get_polls(course_id: str = None, current_user: User = Depends(get_current_user)):
    if course_id:
        # Get polls for specific course
        polls = await db.polls.find({"course_id": course_id}).sort("created_at", -1).to_list(1000)
    else:
        # Get all polls (for moderators or when no course specified)
        if current_user.role != "moderator":
            raise HTTPException(status_code=400, detail="Course ID is required")
        polls = await db.polls.find().sort("created_at", -1).to_list(1000)
    
    return [Poll(**poll) for poll in polls]

@api_router.post("/polls/{poll_id}/vote")
async def vote_on_poll(poll_id: str, vote_data: VoteCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can vote")
    
    # Check if poll exists
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    # Check if user has already voted
    existing_vote = await db.votes.find_one({"poll_id": poll_id, "user_id": current_user.id})
    if existing_vote:
        raise HTTPException(status_code=400, detail="You have already voted on this poll")
    
    # Check if selected option is valid
    if vote_data.option_selected not in poll["options"]:
        raise HTTPException(status_code=400, detail="Invalid option selected")
    
    vote_dict = vote_data.dict()
    vote_dict["user_id"] = current_user.id
    
    vote_obj = Vote(**vote_dict)
    await db.votes.insert_one(vote_obj.dict())
    
    return {"message": "Vote recorded successfully"}

@api_router.get("/polls/{poll_id}/results", response_model=PollResults)
async def get_poll_results(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can view poll results")
    
    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    # Get all votes for this poll
    votes = await db.votes.find({"poll_id": poll_id}).to_list(1000)
    
    # Count votes for each option
    vote_counts = {option: 0 for option in poll["options"]}
    for vote in votes:
        vote_counts[vote["option_selected"]] += 1
    
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
        return {"voted": True, "option": vote["option_selected"]}
    return {"voted": False}

@api_router.delete("/polls/{poll_id}")
async def delete_own_poll(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can delete their own polls")

    poll = await db.polls.find_one({"id": poll_id})
    if not poll:
        raise HTTPException(status_code=404, detail="Poll not found")
    if poll["created_by"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete polls you created")

    # Delete all votes for this poll first
    await db.votes.delete_many({"poll_id": poll_id})
    result = await db.polls.delete_one({"id": poll_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Poll not found")

    return {"message": "Poll and all associated votes deleted successfully"}

# Course endpoints
@api_router.post("/courses", response_model=Course)
async def create_course(course_data: CourseCreate, current_user: User = Depends(get_current_user)):
    if current_user.role != "professor":
        raise HTTPException(status_code=403, detail="Only professors can create courses")
    
    # Generate unique course code
    code = await generate_course_code()
    
    # Create course
    course = Course(
        name=course_data.name,
        code=code,
        professor_id=current_user.id,
        professor_name=current_user.username
    )
    
    await db.courses.insert_one(course.dict())
    return course

@api_router.get("/courses", response_model=List[Course])
async def get_courses(current_user: User = Depends(get_current_user)):
    if current_user.role == "professor":
        # Professors see their own courses
        courses = await db.courses.find({"professor_id": current_user.id}).to_list(1000)
    elif current_user.role == "student":
        # Students see courses they're enrolled in
        courses = await db.courses.find({"students": current_user.id}).to_list(1000)
    elif current_user.role == "moderator":
        # Moderators see all courses
        courses = await db.courses.find().to_list(1000)
    else:
        raise HTTPException(status_code=403, detail="Invalid role")
    
    return [Course(**course) for course in courses]

@api_router.post("/courses/join")
async def join_course(course_data: CourseJoin, current_user: User = Depends(get_current_user)):
    if current_user.role != "student":
        raise HTTPException(status_code=403, detail="Only students can join courses")
    
    # Find course by code
    course = await db.courses.find_one({"code": course_data.code.upper()})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Check if student is already enrolled
    if current_user.id in course["students"]:
        raise HTTPException(status_code=400, detail="Already enrolled in this course")
    
    # Add student to course
    await db.courses.update_one(
        {"id": course["id"]},
        {"$push": {"students": current_user.id}}
    )
    
    return {"message": f"Successfully joined course: {course['name']}"}

@api_router.delete("/courses/{course_id}")
async def delete_course(course_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Only professors and moderators can delete courses")
    
    # Check if course exists
    course = await db.courses.find_one({"id": course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Professors can only delete their own courses, moderators can delete any
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own courses")
    
    # Delete the course
    await db.courses.delete_one({"id": course_id})
    
    return {"message": "Course deleted successfully"}

@api_router.get("/courses/{course_id}/students")
async def get_course_students(course_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ["professor", "moderator"]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if course exists
    course = await db.courses.find_one({"id": course_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Professors can only see students in their own courses
    if current_user.role == "professor" and course["professor_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get student details
    students = []
    for student_id in course["students"]:
        student = await db.users.find_one({"id": student_id})
        if student:
            students.append({
                "id": student["id"],
                "username": student["username"],
                "email": student["email"]
            })
    
    return {"students": students}

# Moderator-specific endpoints for full CRUD access
@api_router.get("/admin/users", response_model=List[User])
async def get_all_users(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    users = await db.users.find().to_list(1000)
    return [User(**user) for user in users]

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    # Don't allow deleting own account
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deleted successfully"}

@api_router.delete("/admin/questions/{question_id}")
async def delete_any_question(question_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    result = await db.questions.delete_one({"id": question_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Question not found")
    
    return {"message": "Question deleted successfully"}

@api_router.put("/admin/questions/{question_id}", response_model=Question)
async def update_any_question(question_id: str, question_update: QuestionUpdate, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    question = await db.questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    update_data = {k: v for k, v in question_update.dict().items() if v is not None}
    if update_data:
        await db.questions.update_one({"id": question_id}, {"$set": update_data})
    
    updated_question = await db.questions.find_one({"id": question_id})
    return Question(**updated_question)

@api_router.delete("/admin/polls/{poll_id}")
async def delete_any_poll(poll_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    # Delete all votes for this poll first
    await db.votes.delete_many({"poll_id": poll_id})
    
    result = await db.polls.delete_one({"id": poll_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Poll not found")
    
    return {"message": "Poll and all associated votes deleted successfully"}

@api_router.get("/admin/votes", response_model=List[Vote])
async def get_all_votes(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    votes = await db.votes.find().to_list(1000)
    return [Vote(**vote) for vote in votes]

@api_router.delete("/admin/votes/{vote_id}")
async def delete_vote(vote_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    result = await db.votes.delete_one({"id": vote_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Vote not found")
    
    return {"message": "Vote deleted successfully"}

@api_router.get("/admin/stats")
async def get_admin_stats(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    # Get counts for all entities
    users_count = await db.users.count_documents({})
    questions_count = await db.questions.count_documents({})
    polls_count = await db.polls.count_documents({})
    votes_count = await db.votes.count_documents({})
    courses_count = await db.courses.count_documents({})
    
    # Get counts by role
    students_count = await db.users.count_documents({"role": "student"})
    professors_count = await db.users.count_documents({"role": "professor"})
    moderators_count = await db.users.count_documents({"role": "moderator"})
    
    # Get answered questions count
    answered_questions = await db.questions.count_documents({"is_answered": True})
    unanswered_questions = questions_count - answered_questions
    
    # Get total students enrolled in courses
    total_enrollments = 0
    courses = await db.courses.find().to_list(1000)
    for course in courses:
        total_enrollments += len(course.get("students", []))
    
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
        "total_enrollments": total_enrollments
    }

@api_router.get("/admin/active-sessions")
async def get_active_sessions(current_user: User = Depends(get_current_user)):
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can access this endpoint")
    
    active_sessions = session_manager.active_sessions
    session_count = len(active_sessions)
    
    # Group by user
    user_session_count = defaultdict(int)
    for user_data in active_sessions.values():
        user_session_count[user_data['username']] += 1
    
    return {
        "total_active_sessions": session_count,
        "unique_users": len(user_session_count),
        "sessions_per_user": dict(user_session_count)
    }

@api_router.post("/admin/create-professor", response_model=Token)
async def create_professor(professor_data: UserCreateProfessor, current_user: User = Depends(get_current_user)):
    # Check if current user is moderator
    if current_user.role != "moderator":
        raise HTTPException(status_code=403, detail="Only moderators can create professor accounts")
    
    # Check if email already exists
    existing_email = await db.users.find_one({"email": professor_data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check if userid already exists
    existing_userid = await db.users.find_one({"userid": professor_data.userid})
    if existing_userid:
        raise HTTPException(status_code=400, detail="User ID already registered")
    
    # Create professor user
    professor_dict = professor_data.dict()
    professor_dict["password_hash"] = get_password_hash(professor_data.password)
    professor_dict["role"] = "professor"
    professor_dict["username"] = professor_data.userid  # Use userid as username
    professor_dict.pop("password")
    
    professor_obj = User(**professor_dict)
    await db.users.insert_one(professor_obj.dict())
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": professor_obj.username}, expires_delta=access_token_expires
    )
    
    user_data_dict = {
        "id": professor_obj.id,
        "username": professor_obj.username,
        "email": professor_obj.email,
        "role": professor_obj.role,
        "name": professor_obj.name,
        "userid": professor_obj.userid
    }
    
    # Add to session manager
    session_manager.add_session(access_token, user_data_dict)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data_dict
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://zero1-classroom-2.onrender.com"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

@app.get("/")
def read_root():
    return {"message": "Backend is running!"}