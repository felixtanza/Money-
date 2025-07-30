from fastapi import FastAPI, Depends, HTTPException, status, Body, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from enum import Enum
from pydantic import BaseModel, Field, EmailStr 
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import os
import uuid
import jwt # PyJWT
import logging
import bcrypt # For password hashing
import asyncio # Used for async operations if needed, though no sleep() in payment logic now
import httpx # For making HTTP requests to M-Pesa API
import base64 # For encoding M-Pesa API password

# Configure logging for production
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Pydantic Models (Moved from models.py) ---
# Helper to convert MongoDB ObjectId to string
class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, (str, bytes)):
            raise ValueError("ObjectId must be string or bytes")
        return str(v)

# Enum for user roles
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

# User model: Defines the structure for user accounts.
class User(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    user_id: str = Field(..., unique=True)
    username: str = Field(..., min_length=3, max_length=20, unique=True)
    email: EmailStr = Field(...)
    hashed_password: str = Field(...)
    full_name: str = Field(...)
    phone: str = Field(..., regex=r"^254\d{9}$") # Kenyan phone number format validation
    wallet_balance: float = Field(default=0.0)
    total_earned: float = Field(default=0.0)
    total_withdrawn: float = Field(default=0.0)
    referral_code: str = Field(..., unique=True)
    referred_by: Optional[str] = None
    referral_count: int = Field(default=0)
    referral_earnings: float = Field(default=0.0)
    is_activated: bool = Field(default=False)
    activation_amount: float = Field(default=500.0)
    role: UserRole = Field(default=UserRole.USER)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    theme: str = Field(default="light")

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "password": "securepassword",
                "full_name": "John Doe",
                "phone": "254712345678",
                "referral_code": "JOHNDOE123"
            }
        }

# UserInDB model: Used specifically for handling incoming user registration/login data.
class UserInDB(User):
    password: str = Field(...) # Temporary field for incoming plain-text password

# Enum for different types of tasks.
class TaskType(str, Enum):
    SURVEY = "survey"
    AD = "ad"
    WRITING = "writing"
    SOCIAL = "social"
    REFERRAL = "referral"

# Task model: Defines the structure for tasks available on the platform.
class Task(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    task_id: str = Field(..., unique=True)
    title: str = Field(...)
    description: str = Field(...)
    reward: float = Field(..., gt=0)
    type: TaskType = Field(...)
    requirements: List[Dict[str, Any]] = Field(default_factory=list)
    auto_approve: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "title": "Complete a short survey",
                "description": "Answer 5 quick questions about your shopping habits.",
                "reward": 20.0,
                "type": "survey",
                "requirements": [
                    {"type": "text", "label": "What is your favorite color?", "field_name": "favorite_color", "required": True},
                    {"type": "number", "label": "How many hours did you spend?", "field_name": "hours_spent", "required": False, "min": 0}
                ],
                "auto_approve": False
            }
        }

# TaskCompletion model: Records a user's attempt to complete a task.
class TaskCompletion(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    completion_id: str = Field(..., unique=True)
    user_id: str = Field(...)
    task_id: str = Field(...)
    status: str = Field(default="completed")
    completion_data: Dict[str, Any] = Field(default_factory=dict)
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "user_id": "some_user_id",
                "task_id": "some_task_id",
                "completion_data": {"favorite_color": "blue", "hours_spent": 2},
                "status": "pending_review"
            }
        }

# TaskSubmission model: Specifically for tasks that require manual admin approval.
class TaskSubmission(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    submission_id: str = Field(..., unique=True)
    user_id: str = Field(...)
    task_id: str = Field(...)
    task_title: str = Field(...)
    task_reward: float = Field(...)
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    completion_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="pending")
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "user_id": "user123",
                "task_id": "taskabc",
                "task_title": "Complete Survey X",
                "task_reward": 50.0,
                "completion_data": {"question1": "answer1", "question2": "answer2"},
                "status": "pending"
            }
        }

# Enums for transaction types and statuses.
class TransactionType(str, Enum):
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TASK_REWARD = "task_reward"
    REFERRAL_BONUS = "referral_bonus"
    ACTIVATION_FEE = "activation_fee"

class TransactionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"

# Transaction model: Records all financial movements within the platform.
class Transaction(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    transaction_id: str = Field(..., unique=True)
    user_id: str = Field(...)
    type: TransactionType = Field(...)
    amount: float = Field(...)
    status: TransactionStatus = Field(default=TransactionStatus.PENDING)
    method: Optional[str] = None
    mpesa_receipt: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None # Added for M-Pesa callback failures

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "user_id": "some_user_id",
                "type": "deposit",
                "amount": 500.0,
                "status": "pending",
                "method": "M-Pesa"
            }
        }

# Enum for different types of notifications.
class NotificationType(str, Enum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"

# Notification model: Defines the structure for messages sent to users.
class Notification(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    notification_id: str = Field(..., unique=True)
    user_id: Optional[str] = None # Null for broadcast notifications
    title: str = Field(...)
    message: str = Field(...)
    type: NotificationType = Field(default=NotificationType.INFO)
    read: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {PyObjectId: str}
        schema_extra = {
            "example": {
                "user_id": "some_user_id",
                "title": "Welcome!",
                "message": "Your account has been activated.",
                "type": "success"
            }
        }
# --- End Pydantic Models ---


app = FastAPI(
    title="EarnPlatform Backend API",
    description="API for a money-making platform with tasks, referrals, and payments.",
    version="1.0.0",
)

# --- CORS Middleware Configuration ---
origins = [
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "https://money-makingplatformbyequitybankand.onrender.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database Connection ---
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017/earnplatform_db")
try:
    client = AsyncIOMotorClient(MONGO_DETAILS)
    database = client.get_database()
    logger.info("Successfully connected to MongoDB.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

# --- MongoDB Collections ---
users_collection = database.get_collection("users")
tasks_collection = database.get_collection("tasks")
task_completions_collection = database.get_collection("task_completions")
transactions_collection = database.get_collection("transactions")
notifications_collection = database.get_collection("notifications")
task_submissions_collection = database.get_collection("task_submissions")

# --- MongoDB Index Creation on Startup ---
@app.on_event("startup")
async def startup_db_client():
    logger.info("Creating MongoDB indexes...")
    try:
        await users_collection.create_index("user_id", unique=True)
        await users_collection.create_index("username", unique=True)
        await users_collection.create_index("email", unique=True)
        await users_collection.create_index("phone", unique=True)
        await users_collection.create_index("referral_code", unique=True)
        await tasks_collection.create_index("task_id", unique=True)
        await task_completions_collection.create_index([("user_id", 1), ("task_id", 1)], unique=True)
        await transactions_collection.create_index("transaction_id", unique=True)
        await notifications_collection.create_index("notification_id", unique=True)
        await task_submissions_collection.create_index("submission_id", unique=True)
        logger.info("MongoDB indexes created successfully.")
    except Exception as e:
        logger.error(f"Failed to create MongoDB indexes: {e}.")


# --- JWT Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-please-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60

# --- Initial Admin Creation Secret Key ---
SECRET_ADMIN_KEY = os.getenv("SECRET_ADMIN_KEY", "default-admin-key-change-me-in-production")

# --- M-Pesa API Credentials (Environment Variables) ---
# You MUST set these securely in your Render environment variables.
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY", "your_mpesa_consumer_key")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET", "your_mpesa_consumer_secret")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE", "600986") # Paybill or Till Number
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY", "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919") # M-Pesa Daraja API Passkey
MPESA_CALLBACK_URL = os.getenv("MPESA_CALLBACK_URL", "https://your-backend-url.onrender.com/api/payments/mpesa-callback") # Your deployed callback URL

# M-Pesa Daraja API Endpoints (Sandbox/Production)
# For production, change to the live URLs.
MPESA_AUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
MPESA_STK_PUSH_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
MPESA_B2C_URL = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/queryrequest" # For B2C payouts, this is for querying status. Actual B2C is different.
# For B2C Payout, you'd typically use: https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest
# This example focuses on STK Push for deposit and a conceptual B2C for withdrawal.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# --- M-Pesa Utility Functions ---

async def get_mpesa_access_token():
    """Fetches an M-Pesa Daraja API access token."""
    try:
        # Concatenate consumer key and secret with a colon and base64 encode
        credentials = f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()

        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(MPESA_AUTH_URL, headers=headers)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            data = response.json()
            access_token = data.get("access_token")
            if not access_token:
                logger.error(f"M-Pesa Auth: No access token in response: {data}")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get M-Pesa access token (no token in response).")
            logger.info("M-Pesa access token obtained successfully.")
            return access_token
    except httpx.HTTPStatusError as e:
        logger.error(f"M-Pesa Auth HTTP error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"M-Pesa authentication failed: {e.response.text}")
    except httpx.RequestError as e:
        logger.error(f"M-Pesa Auth network error: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="M-Pesa authentication failed (network error).")
    except Exception as e:
        logger.error(f"Unexpected error getting M-Pesa access token: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during M-Pesa authentication.")


# --- Utility Functions (Authentication & Authorization) ---

def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    hashed_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a bcrypt hashed password."""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError as e:
        logger.error(f"Error verifying password (hashed password format issue?): {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during password verification: {e}")
        return False

async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def decode_access_token(token: str):
    """Decodes a JWT access token and handles expiration/invalidity."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Expired JWT token received.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logger.error("Invalid JWT token received.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to get the current authenticated user."""
    payload = await decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        logger.warning("JWT payload missing 'sub' (user_id).")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_doc = await users_collection.find_one({"user_id": user_id})
    if user_doc is None:
        logger.warning(f"User with ID {user_id} not found after token validation. Token might be for a deleted user.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return User(**user_doc)

async def get_current_admin_user(current_user: User = Depends(get_current_user)):
    """Dependency to get the current authenticated admin user."""
    if current_user.role != UserRole.ADMIN:
        logger.warning(f"User {current_user.user_id} ({current_user.username}) attempted unauthorized admin access. Role: {current_user.role}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource",
        )
    return current_user

# --- Authentication Endpoints ---

@app.post("/api/auth/register", response_model=Dict[str, Any], summary="Register a new user account")
async def register(user_data: UserInDB):
    logger.info(f"Attempting to register new user: {user_data.username} ({user_data.email})")
    
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered.")
    if await users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")
    if await users_collection.find_one({"phone": user_data.phone}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered.")

    hashed_password = hash_password(user_data.password)
    
    new_user = User(
        user_id=str(uuid.uuid4()),
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        phone=user_data.phone,
        referral_code=user_data.username.upper() + str(uuid.uuid4())[:4],
        wallet_balance=0.0,
        total_earned=0.0,
        total_withdrawn=0.0,
        referral_count=0,
        referral_earnings=0.0,
        is_activated=False,
        activation_amount=500.0,
        role=UserRole.USER,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        theme="light"
    )

    if user_data.referral_code:
        referrer = await users_collection.find_one({"referral_code": user_data.referral_code})
        if referrer:
            new_user.referred_by = referrer["user_id"]
            await users_collection.update_one(
                {"user_id": referrer["user_id"]},
                {"$inc": {"referral_count": 1}}
            )
            logger.info(f"User {new_user.username} referred by {referrer['username']} ({referrer['user_id']}).")
            await notifications_collection.insert_one(Notification(
                notification_id=str(uuid.uuid4()),
                user_id=referrer["user_id"],
                title="New Referral!",
                message=f"You have a new referral: {new_user.username}",
                type=NotificationType.INFO
            ).dict(by_alias=True, exclude_none=True))
        else:
            logger.warning(f"Invalid referral code '{user_data.referral_code}' provided during registration for {user_data.username}. Proceeding without referrer.")
            new_user.referred_by = None

    user_dict_to_save = new_user.dict(by_alias=True, exclude_none=True)
    await users_collection.insert_one(user_dict_to_save)

    access_token = await create_access_token(data={"sub": new_user.user_id})

    user_response_data = new_user.dict(by_alias=True, exclude_none=True)
    user_response_data.pop("hashed_password")
    
    logger.info(f"User {new_user.username} registered successfully.")
    return {"success": True, "message": "User registered successfully", "token": access_token, "user": user_response_data}

@app.post("/api/auth/login", response_model=Dict[str, Any], summary="Authenticate user and issue JWT token")
async def login(username: str = Body(..., description="Username of the user"), password: str = Body(..., description="Password of the user")):
    logger.info(f"Attempting login for user: {username}")
    user_doc = await users_collection.find_one({"username": username})
    if not user_doc:
        logger.warning(f"Login failed for {username}: User not found.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    if not verify_password(password, user_doc["hashed_password"]):
        logger.warning(f"Login failed for {username}: Incorrect password.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    access_token = await create_access_token(data={"sub": user_doc["user_id"]})
    
    user_response_data = User(**user_doc).dict(by_alias=True, exclude_none=True)
    user_response_data.pop("hashed_password")
    
    logger.info(f"User {username} logged in successfully.")
    return {"success": True, "message": "Login successful", "token": access_token, "user": user_response_data}

# --- User Endpoints ---

@app.get("/api/dashboard/stats", response_model=Dict[str, Any], summary="Get authenticated user's dashboard statistics")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    logger.info(f"Fetching dashboard stats for user: {current_user.user_id}")
    
    user_doc = await users_collection.find_one({"user_id": current_user.user_id})
    if user_doc is None:
        logger.error(f"Dashboard stats requested for non-existent user: {current_user.user_id} (This indicates a data inconsistency if token is valid).")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    user_data = User(**user_doc)

    total_tasks_completed = await task_completions_collection.count_documents({"user_id": current_user.user_id, "status": "approved"})
    
    referral_stats = {
        "total_referred": user_data.referral_count,
        "total_referral_earnings": user_data.referral_earnings
    }

    user_data_dict = user_data.dict(by_alias=True, exclude_none=True)
    user_data_dict.pop("hashed_password", None)

    return {
        "success": True,
        "user": user_data_dict,
        "task_completions": total_tasks_completed,
        "referral_stats": referral_stats
    }

@app.put("/api/user/profile", response_model=Dict[str, Any], summary="Update authenticated user's profile")
async def update_user_profile(
    updated_profile: Dict[str, Any] = Body(..., description="Dictionary of profile fields to update (e.g., {'theme': 'dark'})."),
    current_user: User = Depends(get_current_user)
):
    """
    Allows users to update their profile information.
    Currently, primarily used for updating the 'theme' preference.
    """
    user_id = current_user.user_id
    logger.info(f"User {user_id} attempting to update profile with data: {updated_profile}")
    
    allowed_fields = {"theme"}
    update_data = {k: v for k, v in updated_profile.items() if k in allowed_fields}

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid fields provided for update."
        )

    update_data["updated_at"] = datetime.utcnow()

    result = await users_collection.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )

    if result.modified_count == 0:
        logger.warning(f"User {user_id} profile update resulted in no modification. Data might be identical or user not found (though user should exist).")

    updated_user_doc = await users_collection.find_one({"user_id": user_id})
    if not updated_user_doc:
        logger.error(f"User {user_id} disappeared after profile update attempt. Critical error.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found after update attempt.")

    updated_user_data = User(**updated_user_doc)
    user_response_data = updated_user_data.dict(by_alias=True, exclude_none=True)
    user_response_data.pop("hashed_password", None)
    
    logger.info(f"User {user_id} profile updated successfully.")
    return {"success": True, "message": "Profile updated successfully", "user": user_response_data}


# --- Task Endpoints ---

@app.post("/api/tasks", response_model=Task, status_code=status.HTTP_201_CREATED, summary="Create a new task (Admin only)")
async def create_task(task: Task, current_user: User = Depends(get_current_admin_user)):
    """
    Creates a new task. Only accessible by admin users.
    """
    task.task_id = str(uuid.uuid4())
    task_dict = task.dict(by_alias=True, exclude_none=True)
    await tasks_collection.insert_one(task_dict)
    logger.info(f"Admin {current_user.user_id} created new task: '{task.title}' (ID: {task.task_id}). Auto-approve: {task.auto_approve}")
    return task

@app.get("/api/tasks", response_model=Dict[str, Any], summary="Get available tasks for the current user")
async def get_tasks(current_user: User = Depends(get_current_user)):
    """
    Retrieves available tasks for the current user.
    Only activated users can see tasks.
    """
    if not current_user.is_activated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not activated. Please deposit to activate your account and access tasks."
        )

    all_tasks_cursor = tasks_collection.find({})
    all_tasks = await all_tasks_cursor.to_list(length=1000)

    completed_or_pending_task_ids_cursor = task_completions_collection.find(
        {"user_id": current_user.user_id, "status": {"$in": ["approved", "pending_review"]}},
        {"task_id": 1}
    )
    completed_or_pending_task_ids = {doc["task_id"] for doc in await completed_or_pending_task_ids_cursor.to_list(length=None)}

    available_tasks = [
        Task(**task_doc) for task_doc in all_tasks
        if task_doc["task_id"] not in completed_or_pending_task_ids
    ]
    logger.info(f"User {current_user.user_id} fetched {len(available_tasks)} available tasks.")
    return {"success": True, "tasks": available_tasks}

@app.post("/api/tasks/complete", response_model=Dict[str, Any], summary="Submit a task for completion")
async def complete_task(
    task_id: str = Body(..., description="The ID of the task to complete."),
    completion_data: Dict[str, Any] = Body(..., description="Data submitted by the user for task completion (e.g., answers to questions)."),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"User {current_user.user_id} attempting to complete task {task_id}.")
    
    if not current_user.is_activated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not activated. Please activate your account to complete tasks."
        )

    task_doc = await tasks_collection.find_one({"task_id": task_id})
    if not task_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found.")

    task = Task(**task_doc)

    existing_completion = await task_completions_collection.find_one(
        {"user_id": current_user.user_id, "task_id": task_id, "status": {"$in": ["approved", "pending_review"]}}
    )
    if existing_completion:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You have already completed or submitted this task.")

    if task.auto_approve:
        new_balance = current_user.wallet_balance + task.reward
        new_total_earned = current_user.total_earned + task.reward

        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned, "updated_at": datetime.utcnow()}}
        )

        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="approved",
            completion_data=completion_data,
            completed_at=datetime.utcnow(),
            reviewed_at=datetime.utcnow()
        )
        await task_completions_collection.insert_one(completion.dict(by_alias=True, exclude_none=True))

        transaction = Transaction(
            transaction_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            type=TransactionType.TASK_REWARD,
            amount=task.reward,
            status=TransactionStatus.COMPLETED,
            method="System",
            completed_at=datetime.utcnow()
        )
        await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

        await notifications_collection.insert_one(Notification(
            notification_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            title="Task Completed!",
            message=f"You earned KSH {task.reward:.2f} for completing '{task.title}'.",
            type=NotificationType.SUCCESS
        ).dict(by_alias=True, exclude_none=True))
        logger.info(f"Task {task.task_id} auto-approved for user {current_user.user_id}. Credited KSH {task.reward}.")
        return {"success": True, "message": f"Task '{task.title}' completed successfully! KSH {task.reward:.2f} added to your wallet."}
    else:
        submission = TaskSubmission(
            submission_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            task_title=task.title,
            task_reward=task.reward,
            submitted_at=datetime.utcnow(),
            completion_data=completion_data,
            status="pending"
        )
        await task_submissions_collection.insert_one(submission.dict(by_alias=True, exclude_none=True))

        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="pending_review",
            completion_data=completion_data,
            completed_at=datetime.utcnow()
        )
        await task_completions_collection.insert_one(completion.dict(by_alias=True, exclude_none=True))

        await notifications_collection.insert_one(Notification(
            notification_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            title="Task Submitted for Review",
            message=f"Your submission for '{task.title}' is pending review. You will be credited once approved.",
            type=NotificationType.INFO
        ).dict(by_alias=True, exclude_none=True))
        logger.info(f"Task {task.task_id} submitted for review by user {current_user.user_id}.")
        return {"success": True, "message": f"Task '{task.title}' submitted for review. You will be notified upon approval."}

# --- Payment Endpoints ---

@app.post("/api/payments/deposit", response_model=Dict[str, Any], summary="Initiate a deposit via M-Pesa STK Push")
async def deposit_money(
    amount: float = Body(..., gt=0, description="Amount to deposit in KSH."),
    phone: str = Body(..., pattern=r"^254\d{9}$", description="M-Pesa phone number in 254XXXXXXXXX format."),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Deposit request for KSH {amount} from {phone} by user {current_user.user_id}.")
    
    transaction_id = str(uuid.uuid4())
    
    transaction = Transaction(
        transaction_id=transaction_id,
        user_id=current_user.user_id,
        type=TransactionType.DEPOSIT,
        amount=amount,
        status=TransactionStatus.PENDING,
        method="M-Pesa"
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    try:
        access_token = await get_mpesa_access_token()
        
        # M-Pesa STK Push parameters
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()).decode()
        
        payload = {
            "BusinessShortCode": MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline", # Or "CustomerBuyGoodsOnline"
            "Amount": int(amount), # Amount must be an integer for M-Pesa API
            "PartyA": phone, # Customer's phone number
            "PartyB": MPESA_SHORTCODE, # Your Paybill/Till Number
            "PhoneNumber": phone, # Customer's phone number
            "CallBackURL": MPESA_CALLBACK_URL,
            "AccountReference": f"EarnPlatform-{current_user.user_id}", # Unique reference for your system
            "TransactionDesc": f"Deposit for {current_user.username}"
        }

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient() as client:
            mpesa_response = await client.post(MPESA_STK_PUSH_URL, json=payload, headers=headers, timeout=30.0)
            mpesa_response.raise_for_status() # Raise HTTP errors

            mpesa_data = mpesa_response.json()
            logger.info(f"M-Pesa STK Push response: {mpesa_data}")

            if mpesa_data.get("ResponseCode") == "0":
                # STK Push initiated successfully, store CheckoutRequestID for callback matching
                checkout_request_id = mpesa_data.get("CheckoutRequestID")
                await transactions_collection.update_one(
                    {"transaction_id": transaction_id},
                    {"$set": {"mpesa_checkout_request_id": checkout_request_id}} # Store this for callback
                )
                logger.info(f"M-Pesa STK Push initiated successfully for {phone}. CheckoutRequestID: {checkout_request_id}")
                message = "Deposit initiated. Please check your phone for the M-Pesa prompt to complete the transaction."
            else:
                # STK Push initiation failed at Daraja API level
                error_message = mpesa_data.get("ResponseDescription", "Unknown M-Pesa error")
                await transactions_collection.update_one(
                    {"transaction_id": transaction_id},
                    {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": error_message}}
                )
                logger.error(f"M-Pesa STK Push initiation failed: {error_message}")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate M-Pesa STK Push: {error_message}")

    except httpx.HTTPStatusError as e:
        logger.error(f"M-Pesa STK Push HTTP error: {e.response.status_code} - {e.response.text}")
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"HTTP Error: {e.response.text}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"M-Pesa STK Push failed: {e.response.text}")
    except httpx.RequestError as e:
        logger.error(f"M-Pesa STK Push network error: {e}")
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"Network Error: {str(e)}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="M-Pesa STK Push failed (network error).")
    except Exception as e:
        logger.error(f"Unexpected error during M-Pesa STK Push: {e}", exc_info=True)
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"Unexpected Error: {str(e)}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during your deposit.")

    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=current_user.user_id,
        title="Deposit Initiated",
        message=message,
        type=NotificationType.INFO
    ).dict(by_alias=True, exclude_none=True))
    logger.info(f"Deposit request for KSH {amount} by user {current_user.user_id} initiated. Status: PENDING.")

    return {"success": True, "message": message}


@app.post("/api/payments/withdraw", response_model=Dict[str, Any], summary="Request a withdrawal via M-Pesa B2C")
async def withdraw_money(
    amount: float = Body(..., gt=0, description="Amount to withdraw in KSH."),
    phone: str = Body(..., regex=r"^254\d{9}$", description="M-Pesa phone number to send money to."),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Withdrawal request for KSH {amount} to {phone} by user {current_user.user_id}.")
    
    if current_user.wallet_balance < amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance.")
    if not current_user.is_activated:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not activated. Cannot withdraw.")
    if amount < 100:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Minimum withdrawal amount is KSH 100.")

    transaction_id = str(uuid.uuid4())
    
    transaction = Transaction(
        transaction_id=transaction_id,
        user_id=current_user.user_id,
        type=TransactionType.WITHDRAWAL,
        amount=amount,
        status=TransactionStatus.PENDING,
        method="M-Pesa"
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    # Optimistically deduct from user's balance
    new_balance = current_user.wallet_balance - amount
    new_total_withdrawn = current_user.total_withdrawn + amount
    await users_collection.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_withdrawn": new_total_withdrawn, "updated_at": datetime.utcnow()}}
    )
    logger.info(f"User {current_user.user_id} balance updated for withdrawal. New balance: {new_balance:.2f}.")

    try:
        access_token = await get_mpesa_access_token()
        
        # M-Pesa B2C Payout parameters
        # IMPORTANT: B2C requires a specific Security Credential and Initiator Name.
        # You'll need to generate a Security Credential from your Daraja API dashboard.
        # This example is conceptual.
        payload = {
            "InitiatorName": "YourInitiatorName", # From Daraja API credentials
            "SecurityCredential": "YourSecurityCredential", # Generated from Daraja API
            "CommandID": "BusinessPayment", # Or "SalaryPayment", "PromotionPayment"
            "Amount": int(amount),
            "PartyA": MPESA_SHORTCODE, # Your Paybill/Till Number
            "PartyB": phone, # Customer's phone number
            "Remarks": f"Withdrawal for {current_user.username}",
            "QueueTimeOutURL": MPESA_CALLBACK_URL, # M-Pesa will send timeout/result here
            "ResultURL": MPESA_CALLBACK_URL, # M-Pesa will send final result here
            "Occasion": f"Withdrawal-{transaction_id}" # Optional, for your records
        }

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient() as client:
            # The actual B2C endpoint is usually different from STK Push.
            # Use the correct B2C Payment Request URL from Daraja documentation.
            mpesa_response = await client.post("https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest", json=payload, headers=headers, timeout=30.0)
            mpesa_response.raise_for_status()

            mpesa_data = mpesa_response.json()
            logger.info(f"M-Pesa B2C Payout response: {mpesa_data}")

            if mpesa_data.get("ResponseCode") == "0":
                # Payout initiated successfully, store ConversationID for callback matching
                conversation_id = mpesa_data.get("ConversationID")
                originator_conversation_id = mpesa_data.get("OriginatorConversationID")
                await transactions_collection.update_one(
                    {"transaction_id": transaction_id},
                    {"$set": {"mpesa_conversation_id": conversation_id, "mpesa_originator_conversation_id": originator_conversation_id}}
                )
                logger.info(f"M-Pesa B2C Payout initiated successfully. ConversationID: {conversation_id}")
                message = "Withdrawal request submitted successfully. You will be notified of its status."
            else:
                error_message = mpesa_data.get("ResponseDescription", "Unknown M-Pesa error")
                # IMPORTANT: If payout initiation fails, REVERSE the user's balance deduction!
                await users_collection.update_one(
                    {"user_id": current_user.user_id},
                    {"$inc": {"wallet_balance": amount, "total_withdrawn": -amount}, "$set": {"updated_at": datetime.utcnow()}}
                )
                await transactions_collection.update_one(
                    {"transaction_id": transaction_id},
                    {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": error_message}}
                )
                logger.error(f"M-Pesa B2C Payout initiation failed: {error_message}. User balance reversed.")
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate withdrawal: {error_message}. Funds reversed to your wallet.")

    except httpx.HTTPStatusError as e:
        logger.error(f"M-Pesa B2C Payout HTTP error: {e.response.status_code} - {e.response.text}")
        # Reverse balance if HTTP error during initiation
        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$inc": {"wallet_balance": amount, "total_withdrawn": -amount}, "$set": {"updated_at": datetime.utcnow()}}
        )
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"HTTP Error: {e.response.text}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"M-Pesa B2C Payout failed: {e.response.text}. Funds reversed to your wallet.")
    except httpx.RequestError as e:
        logger.error(f"M-Pesa B2C Payout network error: {e}")
        # Reverse balance if network error during initiation
        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$inc": {"wallet_balance": amount, "total_withdrawn": -amount}, "$set": {"updated_at": datetime.utcnow()}}
        )
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"Network Error: {str(e)}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="M-Pesa B2C Payout failed (network error). Funds reversed to your wallet.")
    except Exception as e:
        logger.error(f"Unexpected error during M-Pesa B2C Payout: {e}", exc_info=True)
        # Catch-all for unexpected errors, ensure balance reversal is considered
        # This might be tricky if the error happens *after* M-Pesa accepted the request but before callback.
        # For simplicity, we'll reverse here, but in production, you'd need reconciliation.
        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$inc": {"wallet_balance": amount, "total_withdrawn": -amount}, "$set": {"updated_at": datetime.utcnow()}}
        )
        await transactions_collection.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": f"Unexpected Error: {str(e)}"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during your withdrawal. Funds reversed to your wallet.")


    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=current_user.user_id,
        title="Withdrawal Requested",
        message=message,
        type=NotificationType.INFO
    ).dict(by_alias=True, exclude_none=True))
    logger.info(f"Withdrawal request for KSH {amount} by user {current_user.user_id} submitted. Status: PENDING.")
    return {"success": True, "message": message}


@app.post("/api/payments/mpesa-callback", summary="M-Pesa Callback for Transaction Confirmation")
async def mpesa_callback(request: Request):
    """
    Receives M-Pesa transaction confirmation callbacks.
    This endpoint is critical for updating transaction statuses and user balances.
    It handles both STK Push (deposit) and B2C (withdrawal) callbacks.
    """
    try:
        callback_data = await request.json()
        logger.info(f"M-Pesa Callback Received: {callback_data}")

        # --- IMPORTANT: Robust M-Pesa callback parsing and validation here ---
        # The exact structure of `callback_data` depends on the M-Pesa Daraja API
        # and whether it's an STK Push callback or a B2C Result/QueueTimeOut callback.

        # Common fields across callbacks
        result_code = None
        result_desc = None
        transaction_id_from_mpesa = None # This will be CheckoutRequestID for STK Push, TransactionID for B2C
        mpesa_receipt = None
        amount_paid_or_transferred = None
        phone_number = None # For STK Push, this is PartyA

        # --- Parse STK Push Callback (for Deposits) ---
        stk_callback = callback_data.get("Body", {}).get("stkCallback", {})
        if stk_callback:
            result_code = stk_callback.get("ResultCode")
            result_desc = stk_callback.get("ResultDesc")
            transaction_id_from_mpesa = stk_callback.get("CheckoutRequestID") # This is the key to match
            callback_metadata = stk_callback.get("CallbackMetadata", {}).get("Item", [])

            for item in callback_metadata:
                if item.get("Name") == "Amount":
                    amount_paid_or_transferred = float(item.get("Value"))
                elif item.get("Name") == "MpesaReceiptNumber":
                    mpesa_receipt = item.get("Value")
                elif item.get("Name") == "PhoneNumber":
                    phone_number = item.get("Value")

            # Find the pending transaction using CheckoutRequestID
            transaction_doc = await transactions_collection.find_one(
                {"mpesa_checkout_request_id": transaction_id_from_mpesa, "status": TransactionStatus.PENDING.value}
            )
            transaction_type_in_db = TransactionType.DEPOSIT # Assume deposit for STK Push callback

        # --- Parse B2C Callback (for Withdrawals) ---
        # B2C callbacks are typically under "Result" or "QueueTimeOut" in the main body
        b2c_result = callback_data.get("Result")
        if b2c_result:
            result_code = b2c_result.get("ResultCode")
            result_desc = b2c_result.get("ResultDesc")
            transaction_id_from_mpesa = b2c_result.get("TransactionID") # M-Pesa's transaction ID for B2C
            originator_conversation_id = b2c_result.get("OriginatorConversationID") # Your ID sent in request

            if b2c_result.get("ResultParameters"):
                for item in b2c_result["ResultParameters"].get("ResultParameter", []):
                    if item.get("Key") == "B2CUtilityAccountAvailableFunds":
                        # This might indicate the new balance of the utility account, not user's.
                        pass
                    elif item.get("Key") == "B2CWorkingAccountAvailableFunds":
                        pass
                    elif item.get("Key") == "TransactionAmount": # This might be the amount transferred
                        amount_paid_or_transferred = float(item.get("Value"))
                    elif item.get("Key") == "ReceiptNo": # M-Pesa receipt for B2C
                        mpesa_receipt = item.get("Value")

            # Find the pending transaction using OriginatorConversationID
            transaction_doc = await transactions_collection.find_one(
                {"mpesa_originator_conversation_id": originator_conversation_id, "status": TransactionStatus.PENDING.value}
            )
            transaction_type_in_db = TransactionType.WITHDRAWAL # Assume withdrawal for B2C callback
        
        # If no relevant transaction doc found, or callback data is malformed
        if not transaction_doc:
            logger.warning(f"M-Pesa Callback: No pending transaction found for received callback data. Request ID: {transaction_id_from_mpesa or originator_conversation_id}")
            return {"ResultCode": 0, "ResultDesc": "C2B/B2C Callback received but no matching pending transaction found."} # Always return 0 to M-Pesa

        transaction = Transaction(**transaction_doc)
        user_doc = await users_collection.find_one({"user_id": transaction.user_id})
        if not user_doc:
            logger.error(f"M-Pesa Callback: User {transaction.user_id} not found for transaction {transaction.transaction_id}. Data inconsistency!")
            return {"ResultCode": 0, "ResultDesc": "User not found for transaction."} # Always return 0 to M-Pesa

        user = User(**user_doc)

        # --- Process Transaction Result ---
        if result_code == 0: # M-Pesa success code
            logger.info(f"M-Pesa Callback: Transaction {transaction.transaction_id} successful. Receipt: {mpesa_receipt}, Amount: {amount_paid_or_transferred}")
            
            # Update transaction status to COMPLETED
            await transactions_collection.update_one(
                {"transaction_id": transaction.transaction_id},
                {"$set": {"status": TransactionStatus.COMPLETED, "completed_at": datetime.utcnow(), "mpesa_receipt": mpesa_receipt}}
            )

            if transaction.type == TransactionType.DEPOSIT:
                # Credit user's wallet for deposit
                # Use transaction.amount from DB for consistency, or amount_paid_or_transferred from callback if preferred
                new_balance = user.wallet_balance + transaction.amount 
                await users_collection.update_one(
                    {"user_id": user.user_id},
                    {"$set": {"wallet_balance": new_balance, "updated_at": datetime.utcnow()}}
                )
                logger.info(f"User {user.username} credited KSH {transaction.amount:.2f}. New balance: {new_balance:.2f}.")

                # Check for account activation
                if not user.is_activated and transaction.amount >= user.activation_amount:
                    await users_collection.update_one(
                        {"user_id": user.user_id},
                        {"$set": {"is_activated": True, "updated_at": datetime.utcnow()}}
                    )
                    logger.info(f"User {user.username} account activated.")
                    await notifications_collection.insert_one(Notification(
                        notification_id=str(uuid.uuid4()),
                        user_id=user.user_id,
                        title="Account Activated!",
                        message="Your account is now active. You can start earning tasks!",
                        type=NotificationType.SUCCESS
                    ).dict(by_alias=True, exclude_none=True))

                    # If referred, give referral bonus
                    if user.referred_by:
                        referrer_doc = await users_collection.find_one({"user_id": user.referred_by})
                        if referrer_doc:
                            referrer = User(**referrer_doc)
                            referral_bonus_amount = 50.0
                            new_referrer_balance = referrer.wallet_balance + referral_bonus_amount
                            new_referrer_earnings = referrer.referral_earnings + referral_bonus_amount

                            await users_collection.update_one(
                                {"user_id": referrer.user_id},
                                {"$set": {"wallet_balance": new_referrer_balance, "referral_earnings": new_referrer_earnings, "updated_at": datetime.utcnow()}}
                            )
                            await transactions_collection.insert_one(Transaction(
                                transaction_id=str(uuid.uuid4()),
                                user_id=referrer.user_id,
                                type=TransactionType.REFERRAL_BONUS,
                                amount=referral_bonus_amount,
                                status=TransactionStatus.COMPLETED,
                                method="System",
                                completed_at=datetime.utcnow()
                            ).dict(by_alias=True, exclude_none=True))
                            await notifications_collection.insert_one(Notification(
                                notification_id=str(uuid.uuid4()),
                                user_id=referrer.user_id,
                                title="Referral Bonus!",
                                message=f"You earned KSH {referral_bonus_amount:.2f} for {user.username}'s account activation!",
                                type=NotificationType.SUCCESS
                            ).dict(by_alias=True, exclude_none=True))
                            logger.info(f"Referral bonus of KSH {referral_bonus_amount} given to {referrer.username}.")
            
            elif transaction.type == TransactionType.WITHDRAWAL:
                logger.info(f"M-Pesa Callback: Withdrawal {transaction.transaction_id} confirmed successful for user {user.username}.")
                await notifications_collection.insert_one(Notification(
                    notification_id=str(uuid.uuid4()),
                    user_id=user.user_id,
                    title="Withdrawal Successful!",
                    message=f"Your withdrawal of KSH {transaction.amount:.2f} has been successfully processed.",
                    type=NotificationType.SUCCESS
                ).dict(by_alias=True, exclude_none=True))

        else: # M-Pesa transaction failed
            logger.error(f"M-Pesa Callback: Transaction {transaction.transaction_id} failed. ResultCode: {result_code}, Desc: {result_desc}")
            
            # Update transaction status to FAILED
            await transactions_collection.update_one(
                {"transaction_id": transaction.transaction_id},
                {"$set": {"status": TransactionStatus.FAILED, "completed_at": datetime.utcnow(), "error_message": result_desc}}
            )

            if transaction.type == TransactionType.DEPOSIT:
                logger.warning(f"M-Pesa Callback: Deposit {transaction.transaction_id} failed for user {user.username}. No credit issued.")
                await notifications_collection.insert_one(Notification(
                    notification_id=str(uuid.uuid4()),
                    user_id=user.user_id,
                    title="Deposit Failed",
                    message=f"Your deposit of KSH {transaction.amount:.2f} failed. Reason: {result_desc or 'Please try again.'}",
                    type=NotificationType.ERROR
                ).dict(by_alias=True, exclude_none=True))
            
            elif transaction.type == TransactionType.WITHDRAWAL:
                # For failed withdrawals, you MUST reverse the optimistic balance deduction
                await users_collection.update_one(
                    {"user_id": user.user_id},
                    {"$inc": {"wallet_balance": transaction.amount, "total_withdrawn": -transaction.amount}, "$set": {"updated_at": datetime.utcnow()}}
                )
                logger.critical(f"M-Pesa Callback: Withdrawal {transaction.transaction_id} failed for user {user.username}. KSH {transaction.amount:.2f} reversed to wallet.")
                await notifications_collection.insert_one(Notification(
                    notification_id=str(uuid.uuid4()),
                    user_id=user.user_id,
                    title="Withdrawal Failed & Reversed",
                    message=f"Your withdrawal of KSH {transaction.amount:.2f} failed. Funds have been reversed to your wallet. Reason: {result_desc or 'Please try again.'}",
                    type=NotificationType.ERROR
                ).dict(by_alias=True, exclude_none=True))

        # M-Pesa requires a specific JSON response with ResultCode 0 for success
        # This confirms to M-Pesa that you received and processed the callback.
        return {"ResultCode": 0, "ResultDesc": "C2B/B2C Callback received successfully."}
    
    except Exception as e:
        logger.error(f"Error processing M-Pesa callback: {e}", exc_info=True)
        # Always return a 200 OK with ResultCode 0 to M-Pesa on internal error to prevent repeated callbacks
        return {"ResultCode": 0, "ResultDesc": f"Internal server error processing callback: {str(e)}"}


# --- Notification Endpoints ---

@app.get("/api/notifications", response_model=Dict[str, Any], summary="Get authenticated user's notifications")
async def get_user_notifications(current_user: User = Depends(get_current_user)):
    """
    Retrieves notifications for the current user.
    """
    notifications_cursor = notifications_collection.find({"user_id": current_user.user_id}).sort("created_at", -1)
    notifications = await notifications_cursor.to_list(length=100)
    logger.info(f"User {current_user.user_id} fetched {len(notifications)} notifications.")
    return {"success": True, "notifications": notifications}

@app.put("/api/notifications/{notification_id}/read", response_model=Dict[str, Any], summary="Mark a notification as read")
async def mark_notification_as_read(notification_id: str, current_user: User = Depends(get_current_user)):
    """
    Marks a specific notification as read for the current user.
    """
    result = await notifications_collection.update_one(
        {"notification_id": notification_id, "user_id": current_user.user_id},
        {"$set": {"read": True}}
    )
    if result.modified_count == 0:
        logger.warning(f"Notification {notification_id} not found or already read for user {current_user.user_id}.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found or already read.")
    logger.info(f"Notification {notification_id} marked as read for user {current_user.user_id}.")
    return {"success": True, "message": "Notification marked as read."}

# --- Admin Endpoints ---

@app.post("/api/admin/create-initial-admin", status_code=status.HTTP_201_CREATED, response_model=Dict[str, Any], summary="Create the very first admin user (Highly Sensitive!)")
async def create_initial_admin(
    admin_data: UserInDB,
    secret_admin_key: str = Body(..., description="Secret key to authorize initial admin creation. MUST match SECRET_ADMIN_KEY environment variable.")
):
    """
    Creates the very first admin user. This endpoint is highly sensitive and should be:
    1. Used ONLY ONCE during initial deployment/setup.
    2. Secured by a strong, pre-shared SECRET_ADMIN_KEY environment variable.
    3. Ideally, disabled or removed after the first admin is created for maximum security.
    """
    if secret_admin_key != SECRET_ADMIN_KEY:
        logger.error("Attempted initial admin creation with incorrect SECRET_ADMIN_KEY.")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin creation key.")

    existing_admin = await users_collection.find_one({"role": UserRole.ADMIN})
    if existing_admin:
        logger.warning("Attempted to create initial admin, but an admin user already exists. This endpoint should be for initial setup only.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="An admin user already exists. This endpoint is for initial setup only.")

    if await users_collection.find_one({"username": admin_data.username}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")
    if await users_collection.find_one({"email": admin_data.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists.")

    hashed_password = hash_password(admin_data.password)

    new_admin = User(
        user_id=str(uuid.uuid4()),
        username=admin_data.username,
        email=admin_data.email,
        hashed_password=hashed_password,
        full_name=admin_data.full_name,
        phone=admin_data.phone,
        referral_code=admin_data.username.upper() + str(uuid.uuid4())[:4],
        wallet_balance=0.0,
        total_earned=0.0,
        total_withdrawn=0.0,
        referral_count=0,
        referral_earnings=0.0,
        is_activated=True,
        activation_amount=0.0,
        role=UserRole.ADMIN,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        theme="dark"
    )

    await users_collection.insert_one(new_admin.dict(by_alias=True, exclude_none=True))
    logger.critical(f"Initial ADMIN user '{new_admin.username}' (ID: {new_admin.user_id}) created successfully. IMPORTANT: CONSIDER DISABLING OR REMOVING THIS ENDPOINT AFTER USE.")
    return {"success": True, "message": "Initial admin user created successfully. Please secure this endpoint."}


@app.get("/api/admin/users", response_model=List[User], summary="Get all user accounts (Admin only)")
async def get_all_users(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all users. Only accessible by admin users.
    """
    users_cursor = users_collection.find({})
    users = await users_cursor.to_list(length=1000)
    for user_doc in users:
        user_doc.pop("hashed_password", None)
    logger.info(f"Admin {current_user.user_id} fetched {len(users)} users.")
    return users

@app.put("/api/admin/users/{user_id}/role", response_model=Dict[str, Any], summary="Update a user's role (Admin only)")
async def update_user_role(
    user_id: str,
    new_role: str = Body(..., embed=True, alias="new_role", description="New role for the user ('user' or 'admin')."),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Updates a user's role. Only accessible by admin users.
    """
    if new_role not in [UserRole.USER.value, UserRole.ADMIN.value]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified. Must be 'user' or 'admin'.")
    
    if user_id == current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You cannot change your own role via this endpoint.")

    result = await users_collection.update_one(
        {"user_id": user_id},
        {"$set": {"role": UserRole(new_role), "updated_at": datetime.utcnow()}}
    )
    if result.modified_count == 0:
        logger.warning(f"Admin {current_user.user_id} attempted to change role for {user_id} to {new_role}, but no modification occurred (user not found or role already same).")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or role is already the same.")
    logger.info(f"Admin {current_user.user_id} updated user {user_id} role to {new_role}.")
    return {"success": True, "message": f"User {user_id} role updated to {new_role}."}

@app.get("/api/admin/transactions", response_model=Dict[str, Any], summary="Get all transactions (Admin only)")
async def get_all_transactions(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all transactions. Only accessible by admin users.
    """
    transactions_cursor = transactions_collection.find({}).sort("created_at", -1)
    transactions = await transactions_cursor.to_list(length=1000)
    logger.info(f"Admin {current_user.user_id} fetched {len(transactions)} transactions.")
    return {"success": True, "transactions": transactions}

@app.post("/api/admin/notifications/broadcast", response_model=Dict[str, Any], summary="Send a broadcast notification to all users (Admin only)")
async def broadcast_notification(
    title: str = Body(..., description="Title of the broadcast notification."),
    message: str = Body(..., description="Content of the broadcast notification."),
    type: NotificationType = Body(NotificationType.INFO, description="Type of notification (info, success, warning, error)."),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Sends a broadcast notification to all users. Only accessible by admin users.
    """
    notification = Notification(
        notification_id=str(uuid.uuid4()),
        user_id=None,
        title=title,
        message=message,
        type=type
    )
    await notifications_collection.insert_one(notification.dict(by_alias=True, exclude_none=True))
    logger.info(f"Admin {current_user.user_id} sent broadcast notification: '{title}'")
    return {"success": True, "message": "Broadcast notification sent."}

# --- Admin Task Submission Endpoints ---

@app.get("/api/admin/task-submissions/pending", response_model=Dict[str, Any], summary="Get all pending task submissions for review (Admin only)")
async def get_pending_task_submissions(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all pending task submissions for admin review.
    """
    submissions_cursor = task_submissions_collection.find({"status": "pending"}).sort("submitted_at", -1)
    submissions = await submissions_cursor.to_list(length=100)
    logger.info(f"Admin {current_user.user_id} fetched {len(submissions)} pending task submissions.")
    return {"success": True, "submissions": submissions}

@app.put("/api/admin/task-submissions/{submission_id}/approve", response_model=Dict[str, Any], summary="Approve a pending task submission (Admin only)")
async def approve_task_submission(submission_id: str, current_user: User = Depends(get_current_admin_user)):
    """
    Approves a pending task submission, credits the user, and updates task completion status.
    """
    submission_doc = await task_submissions_collection.find_one({"submission_id": submission_id, "status": "pending"})
    if not submission_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending submission not found.")
    
    submission = TaskSubmission(**submission_doc)
    user_doc = await users_collection.find_one({"user_id": submission.user_id})
    if not user_doc:
        logger.error(f"User {submission.user_id} for submission {submission_id} not found during approval. This indicates data inconsistency.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User for submission not found.")
    
    user = User(**user_doc)
    
    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "approved", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "approved", "reviewed_at": datetime.utcnow()}}
    )

    new_balance = user.wallet_balance + submission.task_reward
    new_total_earned = user.total_earned + submission.task_reward
    await users_collection.update_one(
        {"user_id": user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned, "updated_at": datetime.utcnow()}}
    )

    transaction = Transaction(
        transaction_id=str(uuid.uuid4()),
        user_id=user.user_id,
        type=TransactionType.TASK_REWARD,
        amount=submission.task_reward,
        status=TransactionStatus.COMPLETED,
        method="System",
        completed_at=datetime.utcnow()
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=user.user_id,
        title="Task Approved!",
        message=f"Your submission for '{submission.task_title}' has been approved. KSH {submission.task_reward:.2f} added to your wallet.",
        type=NotificationType.SUCCESS
    ).dict(by_alias=True, exclude_none=True))
    logger.info(f"Admin {current_user.user_id} approved submission {submission_id} for user {user.user_id}. Credited KSH {submission.task_reward}.")
    return {"success": True, "message": "Task submission approved and user credited."}

@app.put("/api/admin/task-submissions/{submission_id}/reject", response_model=Dict[str, Any], summary="Reject a pending task submission (Admin only)")
async def reject_task_submission(submission_id: str, current_user: User = Depends(get_current_admin_user)):
    """
    Rejects a pending task submission and updates its status.
    """
    submission_doc = await task_submissions_collection.find_one({"submission_id": submission_id, "status": "pending"})
    if not submission_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending submission not found.")
    
    submission = TaskSubmission(**submission_doc)

    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "rejected", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "rejected", "reviewed_at": datetime.utcnow()}}
    )

    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=submission.user_id,
        title="Task Submission Rejected",
        message=f"Your submission for '{submission.task_title}' was rejected. Please review the task requirements and try again.",
        type=NotificationType.ERROR
    ).dict(by_alias=True, exclude_none=True))
    logger.info(f"Admin {current_user.user_id} rejected submission {submission_id} for user {submission.user_id}.")
    return {"success": True, "message": "Task submission rejected."}

# --- Root Endpoint (for health check) ---
@app.get("/", summary="Backend health check")
async def read_root():
    """Simple endpoint to check if the backend is running."""
    return {"message": "EarnPlatform Backend is running!"}
