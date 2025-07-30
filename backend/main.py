from fastapi import FastAPI, Depends, HTTPException, status, Body, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import os
import uuid
import jwt # PyJWT
import logging
import bcrypt # For password hashing
import asyncio # For simulated payment delays

# Using relative import for flexibility in project structure.
# This assumes your 'models.py' file is located one directory level up from 'main.py'.
# For example, if your project structure is:
# /your_project_root
#   ├── models.py
#   └── backend/
#       └── main.py
# This import will correctly find models.py.
from ..models import User, UserInDB, Task, TaskCompletion, Transaction, Notification, UserRole, TaskSubmission, TransactionType, TransactionStatus, NotificationType

# Configure logging for production
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(
    title="EarnPlatform Backend API",
    description="API for a money-making platform with tasks, referrals, and payments.",
    version="1.0.0",
)

# --- CORS Middleware Configuration ---
# This allows your frontend application to communicate with your backend.
# Ensure FRONTEND_URL environment variable is set correctly in Render.
origins = [
    os.getenv("FRONTEND_URL", "http://localhost:3000"), # Default for local dev, overridden by Render env
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "https://money-makingplatformbyequitybank.onrender.com" # Explicitly add your Render frontend URL here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"], # Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"], # Allows all headers, including Authorization
)

# --- Database Connection ---
# MONGO_DETAILS should be set as an environment variable in Render (e.g., MongoDB Atlas connection string)
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017/earnplatform_db")
try:
    client = AsyncIOMotorClient(MONGO_DETAILS)
    database = client.get_database() # Get database from connection string
    logger.info("Successfully connected to MongoDB.")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    # In a production app, you might want to exit or have a health check fail if DB connection fails
    raise

# --- MongoDB Collections ---
users_collection = database.get_collection("users")
tasks_collection = database.get_collection("tasks")
task_completions_collection = database.get_collection("task_completions")
transactions_collection = database.get_collection("transactions")
notifications_collection = database.get_collection("notifications")
task_submissions_collection = database.get_collection("task_submissions") # New collection for admin review

# --- MongoDB Index Creation on Startup ---
# Creates unique indexes for critical fields to ensure data integrity and improve query performance.
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
        # Ensure a user can complete a specific task only once, or submit for review once
        await task_completions_collection.create_index([("user_id", 1), ("task_id", 1)], unique=True)
        await transactions_collection.create_index("transaction_id", unique=True)
        await notifications_collection.create_index("notification_id", unique=True)
        await task_submissions_collection.create_index("submission_id", unique=True)
        logger.info("MongoDB indexes created successfully.")
    except Exception as e:
        logger.error(f"Failed to create MongoDB indexes: {e}. This might indicate a problem with existing data or permissions.")
        # In production, you might want to handle this more gracefully or alert.


# --- JWT Configuration ---
# IMPORTANT: Set SECRET_KEY as a strong environment variable in Render.
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-please-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60 # JWT token valid for 30 days

# --- Initial Admin Creation Secret Key ---
# This key should be different from SECRET_KEY and known only to you for initial setup.
# IMPORTANT: Set SECRET_ADMIN_KEY as a strong environment variable in Render.
SECRET_ADMIN_KEY = os.getenv("SECRET_ADMIN_KEY", "default-admin-key-change-me-in-production")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

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
async def register(user_data: UserInDB): # UserInDB expects a 'password' field for hashing
    logger.info(f"Attempting to register new user: {user_data.username} ({user_data.email})")
    
    # Check for existing user by username, email, or phone to prevent duplicates
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered.")
    if await users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered.")
    if await users_collection.find_one({"phone": user_data.phone}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered.")

    # Securely hash the plain-text password
    hashed_password = hash_password(user_data.password)
    
    # Create a new User object with hashed password and default values
    new_user = User(
        user_id=str(uuid.uuid4()),
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        phone=user_data.phone,
        referral_code=user_data.username.upper() + str(uuid.uuid4())[:4], # Simple referral code generation
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
        theme="light" # Default theme for new users
    )

    # Handle referrer logic if a referral code was provided
    if user_data.referral_code:
        referrer = await users_collection.find_one({"referral_code": user_data.referral_code})
        if referrer:
            new_user.referred_by = referrer["user_id"]
            await users_collection.update_one(
                {"user_id": referrer["user_id"]},
                {"$inc": {"referral_count": 1}} # Increment referrer's count
            )
            logger.info(f"User {new_user.username} referred by {referrer['username']} ({referrer['user_id']}).")
            # Notify the referrer of a new referral
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

    # Insert the new user into the database
    user_dict_to_save = new_user.dict(by_alias=True, exclude_none=True)
    await users_collection.insert_one(user_dict_to_save)

    # Create JWT token for immediate login after successful registration
    access_token = await create_access_token(data={"sub": new_user.user_id})

    # Prepare user data for response (exclude hashed password for security)
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

    # Verify the provided password against the stored hashed password
    if not verify_password(password, user_doc["hashed_password"]):
        logger.warning(f"Login failed for {username}: Incorrect password.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    # Create JWT token for the authenticated user
    access_token = await create_access_token(data={"sub": user_doc["user_id"]})
    
    # Prepare user data for response (exclude hashed password)
    user_response_data = User(**user_doc).dict(by_alias=True, exclude_none=True)
    user_response_data.pop("hashed_password")
    
    logger.info(f"User {username} logged in successfully.")
    return {"success": True, "message": "Login successful", "token": access_token, "user": user_response_data}

# --- User Endpoints ---

@app.get("/api/dashboard/stats", response_model=Dict[str, Any], summary="Get authenticated user's dashboard statistics")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    logger.info(f"Fetching dashboard stats for user: {current_user.user_id}")
    
    # Fetch latest user data from DB to ensure it's up-to-date (e.g., balance changes)
    user_doc = await users_collection.find_one({"user_id": current_user.user_id})
    if not user_doc:
        logger.error(f"Dashboard stats requested for non-existent user: {current_user.user_id} (This indicates a data inconsistency if token is valid).")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    user_data = User(**user_doc)

    # Count tasks completed by the user that have been approved
    total_tasks_completed = await task_completions_collection.count_documents({"user_id": current_user.user_id, "status": "approved"})
    
    # Prepare referral statistics
    referral_stats = {
        "total_referred": user_data.referral_count,
        "total_referral_earnings": user_data.referral_earnings
    }

    # Prepare user data for response (exclude hashed password)
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
    
    # Filter allowed fields to update to prevent arbitrary changes
    allowed_fields = {"theme"} # Explicitly define which fields the user can update
    update_data = {k: v for k, v in updated_profile.items() if k in allowed_fields}

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid fields provided for update."
        )

    update_data["updated_at"] = datetime.utcnow() # Update the timestamp

    result = await users_collection.update_one(
        {"user_id": user_id},
        {"$set": update_data}
    )

    if result.modified_count == 0:
        logger.warning(f"User {user_id} profile update resulted in no modification. Data might be identical or user not found (though user should exist).")
        # No HTTPException here, as the frontend can handle a non-modified response gracefully.
        # It means the state was already as requested.

    # Fetch the updated user document to return the latest state
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
    all_tasks = await all_tasks_cursor.to_list(length=1000) # Fetch up to 1000 tasks

    # Get tasks already completed or pending review by the user
    # This prevents users from re-completing tasks they've already done or submitted.
    completed_or_pending_task_ids_cursor = task_completions_collection.find(
        {"user_id": current_user.user_id, "status": {"$in": ["approved", "pending_review"]}},
        {"task_id": 1} # Project only task_id to optimize query
    )
    completed_or_pending_task_ids = {doc["task_id"] for doc in await completed_or_pending_task_ids_cursor.to_list(length=None)}

    # Filter out tasks that are already completed or pending review by the user
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

    # Check if user has already completed or submitted this task to prevent duplicate submissions
    existing_completion = await task_completions_collection.find_one(
        {"user_id": current_user.user_id, "task_id": task_id, "status": {"$in": ["approved", "pending_review"]}}
    )
    if existing_completion:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You have already completed or submitted this task.")

    if task.auto_approve:
        # If task is auto-approved: credit user instantly
        new_balance = current_user.wallet_balance + task.reward
        new_total_earned = current_user.total_earned + task.reward

        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned, "updated_at": datetime.utcnow()}}
        )

        # Record task completion as 'approved'
        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="approved",
            completion_data=completion_data,
            completed_at=datetime.utcnow(),
            reviewed_at=datetime.utcnow() # Auto-approved, so reviewed now
        )
        await task_completions_collection.insert_one(completion.dict(by_alias=True, exclude_none=True))

        # Record transaction for the task reward
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

        # Notify user of completion and reward
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
        # If task requires manual approval: create a submission for admin review
        submission = TaskSubmission(
            submission_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            task_title=task.title, # Denormalized for easier admin viewing
            task_reward=task.reward, # Denormalized
            submitted_at=datetime.utcnow(),
            completion_data=completion_data,
            status="pending" # Set status to pending for admin review
        )
        await task_submissions_collection.insert_one(submission.dict(by_alias=True, exclude_none=True))

        # Record task completion as 'pending_review'
        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="pending_review",
            completion_data=completion_data,
            completed_at=datetime.utcnow()
        )
        await task_completions_collection.insert_one(completion.dict(by_alias=True, exclude_none=True))

        # Notify user that submission is pending review
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

@app.post("/api/payments/deposit", response_model=Dict[str, Any], summary="Initiate a deposit via M-Pesa (Simulated)")
async def deposit_money(
    amount: float = Body(..., gt=0, description="Amount to deposit in KSH."),
    phone: str = Body(..., regex=r"^254\d{9}$", description="M-Pesa phone number in 254XXXXXXXXX format."),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Deposit request for KSH {amount} from {phone} by user {current_user.user_id}.")
    
    # In a real production application, this section would integrate with a payment gateway
    # like M-Pesa Daraja API. You would typically initiate an STK Push (or similar) here.
    # The actual crediting of the user's wallet would happen in a separate callback endpoint
    # that the M-Pesa API hits upon successful payment.

    transaction_id = str(uuid.uuid4())
    
    # Create a pending transaction record
    transaction = Transaction(
        transaction_id=transaction_id,
        user_id=current_user.user_id,
        type=TransactionType.DEPOSIT,
        amount=amount,
        status=TransactionStatus.PENDING,
        method="M-Pesa"
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    # --- SIMULATED M-PESA STK PUSH & CALLBACK (REPLACE WITH REAL API INTEGRATION) ---
    logger.info(f"SIMULATION: M-Pesa STK Push initiated for {phone} with amount {amount}. Waiting for simulated callback...")
    await asyncio.sleep(2) # Simulate network latency and processing time for the STK push and callback

    # For this demo, we auto-complete the transaction and update user balance immediately.
    # In a real system, this would be triggered by the M-Pesa API's success callback.
    await transactions_collection.update_one(
        {"transaction_id": transaction_id},
        {"$set": {"status": TransactionStatus.COMPLETED, "completed_at": datetime.utcnow(), "mpesa_receipt": "SIMULATED_MPESA_ABC123"}}
    )

    # Update user's wallet balance
    new_balance = current_user.wallet_balance + amount
    await users_collection.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"wallet_balance": new_balance, "updated_at": datetime.utcnow()}}
    )
    logger.info(f"SIMULATION: Deposit of KSH {amount} completed for user {current_user.user_id}. New balance: {new_balance:.2f}.")

    # Check for account activation if conditions are met
    if not current_user.is_activated and amount >= current_user.activation_amount:
        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$set": {"is_activated": True, "updated_at": datetime.utcnow()}}
        )
        logger.info(f"User {current_user.user_id} account activated due to KSH {amount} deposit.")
        # Notify user of successful activation
        await notifications_collection.insert_one(Notification(
            notification_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            title="Account Activated!",
            message="Your account is now active. You can start earning tasks!",
            type=NotificationType.SUCCESS
        ).dict(by_alias=True, exclude_none=True))

        # If referred, give referral bonus to the referrer
        if current_user.referred_by:
            referrer_doc = await users_collection.find_one({"user_id": current_user.referred_by})
            if referrer_doc:
                referrer = User(**referrer_doc)
                referral_bonus_amount = 50.0 # Example bonus for successful activation
                new_referrer_balance = referrer.wallet_balance + referral_bonus_amount
                new_referrer_earnings = referrer.referral_earnings + referral_bonus_amount

                await users_collection.update_one(
                    {"user_id": referrer.user_id},
                    {"$set": {"wallet_balance": new_referrer_balance, "referral_earnings": new_referrer_earnings, "updated_at": datetime.utcnow()}}
                )
                # Record referral bonus transaction
                referral_transaction = Transaction(
                    transaction_id=str(uuid.uuid4()),
                    user_id=referrer.user_id,
                    type=TransactionType.REFERRAL_BONUS,
                    amount=referral_bonus_amount,
                    status=TransactionStatus.COMPLETED,
                    method="System",
                    completed_at=datetime.utcnow()
                )
                await transactions_collection.insert_one(referral_transaction.dict(by_alias=True, exclude_none=True))
                # Notify the referrer
                await notifications_collection.insert_one(Notification(
                    notification_id=str(uuid.uuid4()),
                    user_id=referrer.user_id,
                    title="Referral Bonus!",
                    message=f"You earned KSH {referral_bonus_amount:.2f} for {current_user.username}'s account activation!",
                    type=NotificationType.SUCCESS
                ).dict(by_alias=True, exclude_none=True))
                logger.info(f"Referral bonus of KSH {referral_bonus_amount} given to {referrer.username} ({referrer.user_id}).")
            else:
                logger.warning(f"Referrer {current_user.referred_by} not found for user {current_user.user_id} during activation bonus.")

    return {"success": True, "message": "Deposit initiated. Check your phone for M-Pesa prompt."}

@app.post("/api/payments/withdraw", response_model=Dict[str, Any], summary="Request a withdrawal via M-Pesa (Simulated)")
async def withdraw_money(
    amount: float = Body(..., gt=0, description="Amount to withdraw in KSH."),
    phone: str = Body(..., regex=r"^254\d{9}$", description="M-Pesa phone number to send money to."),
    current_user: User = Depends(get_current_user)
):
    logger.info(f"Withdrawal request for KSH {amount} to {phone} by user {current_user.user_id}.")
    
    # Pre-checks for withdrawal eligibility
    if current_user.wallet_balance < amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance.")
    if not current_user.is_activated:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not activated. Cannot withdraw.")
    if amount < 100: # Minimum withdrawal amount
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Minimum withdrawal amount is KSH 100.")

    transaction_id = str(uuid.uuid4())
    
    # Create a pending withdrawal transaction record
    transaction = Transaction(
        transaction_id=transaction_id,
        user_id=current_user.user_id,
        type=TransactionType.WITHDRAWAL,
        amount=amount,
        status=TransactionStatus.PENDING,
        method="M-Pesa"
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    # Deduct from user's balance immediately (optimistic update)
    new_balance = current_user.wallet_balance - amount
    new_total_withdrawn = current_user.total_withdrawn + amount
    await users_collection.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_withdrawn": new_total_withdrawn, "updated_at": datetime.utcnow()}}
    )
    logger.info(f"User {current_user.user_id} balance updated for withdrawal. New balance: {new_balance:.2f}.")

    # --- SIMULATED M-PESA PAYOUT (REPLACE WITH REAL API INTEGRATION) ---
    logger.info(f"SIMULATION: M-Pesa Payout initiated for {phone} with amount {amount}. Waiting for simulated completion...")
    await asyncio.sleep(3) # Simulate processing time for payout

    # For demo, auto-complete after a short delay.
    # In a real system, the M-Pesa API's callback would update the transaction status to COMPLETED or FAILED.
    await transactions_collection.update_one(
        {"transaction_id": transaction_id},
        {"$set": {"status": TransactionStatus.COMPLETED, "completed_at": datetime.utcnow()}}
    )

    # Notify user of withdrawal request
    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=current_user.user_id,
        title="Withdrawal Requested",
        message=f"Your withdrawal of KSH {amount:.2f} to {phone} is being processed. It may take 24-48 hours.",
        type=NotificationType.INFO
    ).dict(by_alias=True, exclude_none=True))
    logger.info(f"Withdrawal request for KSH {amount} by user {current_user.user_id} submitted successfully and simulated completion.")
    return {"success": True, "message": "Withdrawal request submitted successfully."}

# --- Notification Endpoints ---

@app.get("/api/notifications", response_model=Dict[str, Any], summary="Get authenticated user's notifications")
async def get_user_notifications(current_user: User = Depends(get_current_user)):
    """
    Retrieves notifications for the current user.
    """
    notifications_cursor = notifications_collection.find({"user_id": current_user.user_id}).sort("created_at", -1)
    notifications = await notifications_cursor.to_list(length=100) # Fetch latest 100 notifications
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
    admin_data: UserInDB, # Expects plain password for the new admin
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

    # Check if any admin already exists (optional, but good for enforcing "initial" admin concept)
    existing_admin = await users_collection.find_one({"role": UserRole.ADMIN})
    if existing_admin:
        logger.warning("Attempted to create initial admin, but an admin user already exists. This endpoint should be for initial setup only.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="An admin user already exists. This endpoint is for initial setup only.")

    # Check for existing user by username or email
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
        phone=admin_data.phone, # Admin also needs a valid phone format
        referral_code=admin_data.username.upper() + str(uuid.uuid4())[:4], # Admin also gets a referral code
        wallet_balance=0.0,
        total_earned=0.0,
        total_withdrawn=0.0,
        referral_count=0,
        referral_earnings=0.0,
        is_activated=True, # Admins are typically activated by default
        activation_amount=0.0, # No activation fee for admin
        role=UserRole.ADMIN, # Set role to ADMIN
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        theme="dark" # Default dark theme for admin for better visibility
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
    users = await users_cursor.to_list(length=1000) # Fetch up to 1000 users
    # Remove hashed passwords before sending to frontend for security
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
    
    # Prevent admin from changing their own role via this endpoint (important security measure)
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
    transactions = await transactions_cursor.to_list(length=1000) # Fetch up to 1000 transactions
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
        user_id=None, # Null user_id indicates a broadcast notification
        title=title,
        message=message,
        type=type
    )
    # In a real large-scale system, for a true broadcast to all users,
    # you might use a message queue or a background task to efficiently
    # fan out this notification to a global feed or individual user notification lists.
    # For this current setup, inserting with user_id=None implies it's a broadcast
    # that the frontend can fetch if it queries for all notifications (or specifically for broadcasts).
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
    
    # Update submission status in TaskSubmission collection
    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "approved", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    # Update corresponding TaskCompletion status (from pending_review to approved)
    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "approved", "reviewed_at": datetime.utcnow()}}
    )

    # Credit user's wallet and total earned
    new_balance = user.wallet_balance + submission.task_reward
    new_total_earned = user.total_earned + submission.task_reward
    await users_collection.update_one(
        {"user_id": user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned, "updated_at": datetime.utcnow()}}
    )

    # Record transaction for task reward
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

    # Notify user of approval
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

    # Update submission status in TaskSubmission collection
    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "rejected", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    # Update corresponding TaskCompletion status (from pending_review to rejected)
    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "rejected", "reviewed_at": datetime.utcnow()}}
    )

    # Notify user of rejection
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
