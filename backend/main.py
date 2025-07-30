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

# Assuming your models.py is in the same directory or accessible
from models import User, Task, TaskCompletion, Transaction, Notification, UserRole, TaskSubmission, TransactionType, TransactionStatus, NotificationType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS Middleware
origins = [
    os.getenv("FRONTEND_URL", "http://localhost:3000"), # Allow your frontend URL
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:3000",
    "https://money-makingplatformbyequitybank.onrender.com" # Ensure your Render frontend URL is here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Connection
MONGO_DETAILS = os.getenv("MONGO_DETAILS", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_DETAILS)
database = client.earnplatform_db

# Collections
users_collection = database.get_collection("users")
tasks_collection = database.get_collection("tasks")
task_completions_collection = database.get_collection("task_completions")
transactions_collection = database.get_collection("transactions")
notifications_collection = database.get_collection("notifications")
task_submissions_collection = database.get_collection("task_submissions") # New collection

# JWT Secret Key and Algorithm
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key") # CHANGE THIS IN PRODUCTION!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60 # 30 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# --- Utility Functions (Authentication & Authorization) ---

async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
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

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = await decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_doc = await users_collection.find_one({"user_id": user_id})
    if user_doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return User(**user_doc)

async def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource",
        )
    return current_user

# --- Authentication Endpoints ---

@app.post("/api/auth/register")
async def register(user_data: User):
    # Check if username or email already exists
    if await users_collection.find_one({"username": user_data.username}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
    if await users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    if await users_collection.find_one({"phone": user_data.phone}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered")

    # Hash password (using a simple hash for demonstration, use a strong library like bcrypt in production)
    hashed_password = user_data.password + "notarealhash" # Replace with actual hashing
    user_data.hashed_password = hashed_password
    user_data.user_id = str(uuid.uuid4())
    user_data.referral_code = user_data.username.upper() + str(uuid.uuid4())[:4] # Simple referral code

    # Handle referrer
    if user_data.referral_code:
        referrer = await users_collection.find_one({"referral_code": user_data.referral_code})
        if referrer:
            user_data.referred_by = referrer["user_id"]
            await users_collection.update_one(
                {"user_id": referrer["user_id"]},
                {"$inc": {"referral_count": 1}}
            )
            # Notify referrer of new referral (optional)
            await notifications_collection.insert_one(Notification(
                notification_id=str(uuid.uuid4()),
                user_id=referrer["user_id"],
                title="New Referral!",
                message=f"You have a new referral: {user_data.username}",
                type=NotificationType.INFO
            ).dict(by_alias=True, exclude_none=True))
        else:
            # If referral code is provided but invalid, register without it
            user_data.referral_code = None # Clear invalid referral code
            user_data.referred_by = None
            logger.warning(f"Invalid referral code provided during registration for {user_data.username}")


    user_dict = user_data.dict(by_alias=True, exclude_none=True)
    # Remove plain password before saving
    user_dict.pop("password", None)
    
    await users_collection.insert_one(user_dict)

    # Create token for immediate login
    access_token = await create_access_token(data={"sub": user_data.user_id})

    # Return user data without hashed password
    user_dict.pop("hashed_password")
    return {"success": True, "message": "User registered successfully", "token": access_token, "user": user_dict}

@app.post("/api/auth/login")
async def login(username: str = Body(...), password: str = Body(...)):
    user_doc = await users_collection.find_one({"username": username})
    if not user_doc or user_doc["hashed_password"] != password + "notarealhash": # Replace with actual hashing check
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = await create_access_token(data={"sub": user_doc["user_id"]})
    
    # Return user data without hashed password
    user_doc.pop("hashed_password")
    return {"success": True, "message": "Login successful", "token": access_token, "user": user_doc}

# --- User Endpoints ---

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    # Fetch latest user data to ensure activation status, balance are up-to-date
    user_doc = await users_collection.find_one({"user_id": current_user.user_id})
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user_data = User(**user_doc)

    total_tasks_completed = await task_completions_collection.count_documents({"user_id": current_user.user_id, "status": "approved"}) # Only count approved tasks
    
    # Placeholder for referral stats (can be expanded)
    referral_stats = {
        "total_referred": user_data.referral_count,
        "total_referral_earnings": user_data.referral_earnings
    }

    user_data_dict = user_data.dict(by_alias=True, exclude_none=True)
    user_data_dict.pop("hashed_password", None) # Ensure hashed_password is not sent

    return {
        "success": True,
        "user": user_data_dict,
        "task_completions": total_tasks_completed,
        "referral_stats": referral_stats
    }

@app.put("/api/user/profile")
async def update_user_profile(
    updated_profile: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user)
):
    """
    Allows users to update their profile information.
    Specifically, this is used for updating the 'theme' preference.
    """
    user_id = current_user.user_id
    
    # Filter allowed fields to update to prevent arbitrary changes
    allowed_fields = {"theme"} # Only theme is explicitly allowed for now
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User profile not updated. Data might be the same or user not found."
        )
    
    updated_user_doc = await users_collection.find_one({"user_id": user_id})
    updated_user_data = User(**updated_user_doc)
    updated_user_data_dict = updated_user_data.dict(by_alias=True, exclude_none=True)
    updated_user_data_dict.pop("hashed_password", None)

    return {"success": True, "message": "Profile updated successfully", "user": updated_user_data_dict}


# --- Task Endpoints ---

@app.post("/api/tasks", response_model=Task, status_code=status.HTTP_201_CREATED)
async def create_task(task: Task, current_user: User = Depends(get_current_admin_user)):
    """
    Creates a new task. Only accessible by admin users.
    """
    task.task_id = str(uuid.uuid4())
    task_dict = task.dict(by_alias=True, exclude_none=True)
    await tasks_collection.insert_one(task_dict)
    return task

@app.get("/api/tasks", response_model=Dict[str, Any])
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

    # Get all tasks
    all_tasks_cursor = tasks_collection.find({})
    all_tasks = await all_tasks_cursor.to_list(length=100) # Fetch up to 100 tasks

    # Get tasks already completed by the user
    completed_task_ids_cursor = task_completions_collection.find(
        {"user_id": current_user.user_id, "status": "approved"}, # Only consider approved tasks as completed
        {"task_id": 1} # Project only task_id
    )
    completed_task_ids = {doc["task_id"] for doc in await completed_task_ids_cursor.to_list(length=None)}

    # Filter out tasks that are already completed by the user
    available_tasks = [
        Task(**task_doc) for task_doc in all_tasks
        if task_doc["task_id"] not in completed_task_ids
    ]

    return {"success": True, "tasks": available_tasks}

@app.post("/api/tasks/complete")
async def complete_task(
    task_id: str = Body(...),
    completion_data: Dict[str, Any] = Body(...), # New: accepts completion data
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_activated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not activated. Please activate your account to complete tasks."
        )

    task_doc = await tasks_collection.find_one({"task_id": task_id})
    if not task_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    task = Task(**task_doc)

    # Check if user has already completed this task (and it's approved)
    existing_completion = await task_completions_collection.find_one(
        {"user_id": current_user.user_id, "task_id": task_id, "status": "approved"}
    )
    if existing_completion:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You have already completed this task.")

    if task.auto_approve:
        # Auto-approve: credit user instantly
        new_balance = current_user.wallet_balance + task.reward
        new_total_earned = current_user.total_earned + task.reward

        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned}}
        )

        # Record task completion
        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="approved",
            completion_data=completion_data, # Save the submitted data
            completed_at=datetime.utcnow(),
            reviewed_at=datetime.utcnow() # Auto-approved, so reviewed now
        )
        await task_completions_collection.insert_one(completion.dict(by_alias=True, exclude_none=True))

        # Record transaction for task reward
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

        # Notify user
        await notifications_collection.insert_one(Notification(
            notification_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            title="Task Completed!",
            message=f"You earned KSH {task.reward:.2f} for completing '{task.title}'.",
            type=NotificationType.SUCCESS
        ).dict(by_alias=True, exclude_none=True))

        return {"success": True, "message": f"Task '{task.title}' completed successfully! KSH {task.reward:.2f} added to your wallet."}
    else:
        # Requires manual approval: create a submission for admin review
        submission = TaskSubmission(
            submission_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            task_title=task.title,
            task_reward=task.reward,
            submitted_at=datetime.utcnow(),
            completion_data=completion_data, # Save the submitted data
            status="pending"
        )
        await task_submissions_collection.insert_one(submission.dict(by_alias=True, exclude_none=True))

        # Record task completion as pending
        completion = TaskCompletion(
            completion_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            task_id=task.task_id,
            status="pending_review",
            completion_data=completion_data, # Save the submitted data
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

        return {"success": True, "message": f"Task '{task.title}' submitted for review. You will be notified upon approval."}

# --- Payment Endpoints ---

@app.post("/api/payments/deposit")
async def deposit_money(
    amount: float = Body(..., gt=0),
    phone: str = Body(..., regex=r"^254\d{9}$"),
    current_user: User = Depends(get_current_user)
):
    # In a real app, this would integrate with an M-Pesa API (e.g., Daraja API)
    # For demonstration, we'll simulate success and handle activation.

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

    # Simulate M-Pesa STK Push (replace with actual API call)
    logger.info(f"Simulating M-Pesa STK Push for {phone} with amount {amount} for user {current_user.username}")
    
    # In a real scenario, you'd wait for the M-Pesa callback here.
    # For now, we'll auto-complete and activate if conditions are met.
    
    # Auto-complete transaction for demo purposes
    await transactions_collection.update_one(
        {"transaction_id": transaction_id},
        {"$set": {"status": TransactionStatus.COMPLETED, "completed_at": datetime.utcnow(), "mpesa_receipt": "SIMULATED_MPPESA_ABC123"}}
    )

    # Update user's wallet balance
    new_balance = current_user.wallet_balance + amount
    await users_collection.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"wallet_balance": new_balance}}
    )

    # Check for account activation
    if not current_user.is_activated and amount >= current_user.activation_amount:
        await users_collection.update_one(
            {"user_id": current_user.user_id},
            {"$set": {"is_activated": True}}
        )
        # Notify user of activation
        await notifications_collection.insert_one(Notification(
            notification_id=str(uuid.uuid4()),
            user_id=current_user.user_id,
            title="Account Activated!",
            message="Your account is now active. You can start earning tasks!",
            type=NotificationType.SUCCESS
        ).dict(by_alias=True, exclude_none=True))

        # If referred, give referral bonus
        if current_user.referred_by:
            referrer_doc = await users_collection.find_one({"user_id": current_user.referred_by})
            if referrer_doc:
                referrer = User(**referrer_doc)
                referral_bonus_amount = 50.0 # Example bonus
                new_referrer_balance = referrer.wallet_balance + referral_bonus_amount
                new_referrer_earnings = referrer.referral_earnings + referral_bonus_amount

                await users_collection.update_one(
                    {"user_id": referrer.user_id},
                    {"$set": {"wallet_balance": new_referrer_balance, "referral_earnings": new_referrer_earnings}}
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
                # Notify referrer
                await notifications_collection.insert_one(Notification(
                    notification_id=str(uuid.uuid4()),
                    user_id=referrer.user_id,
                    title="Referral Bonus!",
                    message=f"You earned KSH {referral_bonus_amount:.2f} for {current_user.username}'s account activation!",
                    type=NotificationType.SUCCESS
                ).dict(by_alias=True, exclude_none=True))


    return {"success": True, "message": "Deposit initiated. Check your phone for M-Pesa prompt."}

@app.post("/api/payments/withdraw")
async def withdraw_money(
    amount: float = Body(..., gt=0),
    phone: str = Body(..., regex=r"^254\d{9}$"),
    current_user: User = Depends(get_current_user)
):
    if current_user.wallet_balance < amount:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance.")
    if not current_user.is_activated:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account not activated. Cannot withdraw.")
    if amount < 100: # Minimum withdrawal amount
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Minimum withdrawal amount is KSH 100.")

    transaction_id = str(uuid.uuid4())
    
    # Create a pending withdrawal transaction
    transaction = Transaction(
        transaction_id=transaction_id,
        user_id=current_user.user_id,
        type=TransactionType.WITHDRAWAL,
        amount=amount,
        status=TransactionStatus.PENDING,
        method="M-Pesa"
    )
    await transactions_collection.insert_one(transaction.dict(by_alias=True, exclude_none=True))

    # Deduct from user's balance immediately
    new_balance = current_user.wallet_balance - amount
    new_total_withdrawn = current_user.total_withdrawn + amount
    await users_collection.update_one(
        {"user_id": current_user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_withdrawn": new_total_withdrawn}}
    )

    # In a real app, this would trigger an M-Pesa Payout API call
    logger.info(f"Simulating M-Pesa Payout for {phone} with amount {amount} from user {current_user.username}")

    # For demo, auto-complete after a short delay (simulate processing)
    # In real app, M-Pesa callback would update status to COMPLETED/FAILED
    await transactions_collection.update_one(
        {"transaction_id": transaction_id},
        {"$set": {"status": TransactionStatus.COMPLETED, "completed_at": datetime.utcnow()}}
    )

    # Notify user
    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=current_user.user_id,
        title="Withdrawal Requested",
        message=f"Your withdrawal of KSH {amount:.2f} to {phone} is being processed. It may take 24-48 hours.",
        type=NotificationType.INFO
    ).dict(by_alias=True, exclude_none=True))

    return {"success": True, "message": "Withdrawal request submitted successfully."}

# --- Notification Endpoints ---

@app.get("/api/notifications", response_model=Dict[str, Any])
async def get_user_notifications(current_user: User = Depends(get_current_user)):
    """
    Retrieves notifications for the current user.
    """
    notifications_cursor = notifications_collection.find({"user_id": current_user.user_id}).sort("created_at", -1)
    notifications = await notifications_cursor.to_list(length=100) # Fetch latest 100
    return {"success": True, "notifications": notifications}

@app.put("/api/notifications/{notification_id}/read")
async def mark_notification_as_read(notification_id: str, current_user: User = Depends(get_current_user)):
    """
    Marks a specific notification as read for the current user.
    """
    result = await notifications_collection.update_one(
        {"notification_id": notification_id, "user_id": current_user.user_id},
        {"$set": {"read": True}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found or already read.")
    return {"success": True, "message": "Notification marked as read."}

# --- Admin Endpoints ---

@app.get("/api/admin/users", response_model=List[User])
async def get_all_users(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all users. Only accessible by admin users.
    """
    users_cursor = users_collection.find({})
    users = await users_cursor.to_list(length=1000) # Fetch up to 1000 users
    # Remove hashed passwords before sending
    for user_doc in users:
        user_doc.pop("hashed_password", None)
    return users

@app.put("/api/admin/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    new_role: str = Body(..., embed=True, alias="new_role"), # Expects {"new_role": "admin" or "user"}
    current_user: User = Depends(get_current_admin_user)
):
    """
    Updates a user's role. Only accessible by admin users.
    """
    if new_role not in ["user", "admin"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified.")
    
    # Prevent admin from changing their own role via this endpoint (optional security measure)
    if user_id == current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot change your own role.")

    result = await users_collection.update_one(
        {"user_id": user_id},
        {"$set": {"role": UserRole(new_role)}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found or role is already the same.")
    return {"success": True, "message": f"User {user_id} role updated to {new_role}."}

@app.get("/api/admin/transactions", response_model=Dict[str, Any])
async def get_all_transactions(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all transactions. Only accessible by admin users.
    """
    transactions_cursor = transactions_collection.find({}).sort("created_at", -1)
    transactions = await transactions_cursor.to_list(length=1000) # Fetch up to 1000 transactions
    return {"success": True, "transactions": transactions}

@app.post("/api/admin/notifications/broadcast")
async def broadcast_notification(
    title: str = Body(...),
    message: str = Body(...),
    type: NotificationType = Body(NotificationType.INFO),
    current_user: User = Depends(get_current_admin_user)
):
    """
    Sends a broadcast notification to all users. Only accessible by admin users.
    """
    notification = Notification(
        notification_id=str(uuid.uuid4()),
        user_id=None, # Null user_id indicates broadcast
        title=title,
        message=message,
        type=type
    )
    # For a true broadcast, you might want a separate mechanism or a background task
    # to insert this into each user's notification list or a global feed.
    # For now, it's inserted as a general notification without a specific user_id.
    # The frontend is designed to fetch ALL notifications, so this will be seen.
    await notifications_collection.insert_one(notification.dict(by_alias=True, exclude_none=True))
    return {"success": True, "message": "Broadcast notification sent."}

# --- New Admin Task Submission Endpoints ---

@app.get("/api/admin/task-submissions/pending", response_model=Dict[str, Any])
async def get_pending_task_submissions(current_user: User = Depends(get_current_admin_user)):
    """
    Retrieves all pending task submissions for admin review.
    """
    submissions_cursor = task_submissions_collection.find({"status": "pending"}).sort("submitted_at", -1)
    submissions = await submissions_cursor.to_list(length=100)
    return {"success": True, "submissions": submissions}

@app.put("/api/admin/task-submissions/{submission_id}/approve")
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User for submission not found.")
    
    user = User(**user_doc)
    
    # Update submission status
    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "approved", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    # Update corresponding TaskCompletion status
    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "approved", "reviewed_at": datetime.utcnow()}}
    )

    # Credit user's wallet
    new_balance = user.wallet_balance + submission.task_reward
    new_total_earned = user.total_earned + submission.task_reward
    await users_collection.update_one(
        {"user_id": user.user_id},
        {"$set": {"wallet_balance": new_balance, "total_earned": new_total_earned}}
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

    return {"success": True, "message": "Task submission approved and user credited."}

@app.put("/api/admin/task-submissions/{submission_id}/reject")
async def reject_task_submission(submission_id: str, current_user: User = Depends(get_current_admin_user)):
    """
    Rejects a pending task submission and updates its status.
    """
    submission_doc = await task_submissions_collection.find_one({"submission_id": submission_id, "status": "pending"})
    if not submission_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending submission not found.")
    
    submission = TaskSubmission(**submission_doc)

    # Update submission status
    await task_submissions_collection.update_one(
        {"submission_id": submission_id},
        {"$set": {"status": "rejected", "reviewed_by": current_user.user_id, "reviewed_at": datetime.utcnow()}}
    )

    # Update corresponding TaskCompletion status
    await task_completions_collection.update_one(
        {"user_id": submission.user_id, "task_id": submission.task_id, "status": "pending_review"},
        {"$set": {"status": "rejected", "reviewed_at": datetime.utcnow()}}
    )

    # Notify user of rejection
    await notifications_collection.insert_one(Notification(
        notification_id=str(uuid.uuid4()),
        user_id=submission.user_id,
        title="Task Submission Rejected",
        message=f"Your submission for '{submission.task_title}' was rejected. Please review the task requirements.",
        type=NotificationType.ERROR
    ).dict(by_alias=True, exclude_none=True))

    return {"success": True, "message": "Task submission rejected."}

# --- Root Endpoint (for health check) ---
@app.get("/")
async def read_root():
    return {"message": "EarnPlatform Backend is running!"}
