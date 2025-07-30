from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# Helper to convert MongoDB ObjectId to string
# This is crucial for handling MongoDB's default _id field, which is an ObjectId,
# and converting it to a string for Pydantic's compatibility.
class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, (str, bytes)):
            raise ValueError("ObjectId must be string or bytes")
        # You might want to add more robust ObjectId validation here if needed
        return str(v)

# Enum for user roles, ensuring consistent role assignments.
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

# User model: Defines the structure for user accounts.
class User(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None) # MongoDB's _id field
    user_id: str = Field(..., unique=True) # Unique identifier for the user
    username: str = Field(..., min_length=3, max_length=20, unique=True)
    email: EmailStr = Field(...)
    hashed_password: str = Field(...) # Stores bcrypt hash for security
    full_name: str = Field(...)
    phone: str = Field(..., regex=r"^254\d{9}$") # Kenyan phone number format validation
    wallet_balance: float = Field(default=0.0)
    total_earned: float = Field(default=0.0)
    total_withdrawn: float = Field(default=0.0)
    referral_code: str = Field(..., unique=True)
    referred_by: Optional[str] = None # User ID of the referrer
    referral_count: int = Field(default=0)
    referral_earnings: float = Field(default=0.0)
    is_activated: bool = Field(default=False)
    activation_amount: float = Field(default=500.0) # Amount required for account activation
    role: UserRole = Field(default=UserRole.USER)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    theme: str = Field(default="light") # User's theme preference (e.g., "light", "dark")

    class Config:
        allow_population_by_field_name = True # Allow fields to be populated by their alias name (_id)
        arbitrary_types_allowed = True # Allow PyObjectId
        json_encoders = {PyObjectId: str} # Encode PyObjectId to string when converting to JSON
        schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "password": "securepassword", # This will be hashed before storage
                "full_name": "John Doe",
                "phone": "254712345678",
                "referral_code": "JOHNDOE123"
            }
        }

# UserInDB model: Used specifically for handling incoming user registration/login data.
# It includes a 'password' field that will be hashed into 'hashed_password' before saving to DB.
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
    reward: float = Field(..., gt=0) # Reward must be greater than 0
    type: TaskType = Field(...)
    # 'requirements' is a list of dictionaries defining input fields for task completion.
    # This allows for dynamic forms based on task type.
    requirements: List[Dict[str, Any]] = Field(default_factory=list)
    auto_approve: bool = Field(default=True) # If true, reward instantly; else, requires admin review
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
                "requirements": [ # Example of dynamic requirements
                    {"type": "text", "label": "What is your favorite color?", "field_name": "favorite_color", "required": True},
                    {"type": "number", "label": "How many hours did you spend?", "field_name": "hours_spent", "required": False, "min": 0}
                ],
                "auto_approve": False
            }
        }

# TaskCompletion model: Records a user's attempt to complete a task.
# This tracks the status of their completion (e.g., approved, pending review).
class TaskCompletion(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    completion_id: str = Field(..., unique=True)
    user_id: str = Field(...)
    task_id: str = Field(...)
    status: str = Field(default="completed") # Can be 'completed', 'pending_review', 'approved', 'rejected'
    completion_data: Dict[str, Any] = Field(default_factory=dict) # Stores the actual data submitted by the user
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None # Timestamp for when the task was reviewed (if applicable)

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
# This acts as a queue for admins to review.
class TaskSubmission(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    submission_id: str = Field(..., unique=True)
    user_id: str = Field(...)
    task_id: str = Field(...)
    task_title: str = Field(...) # Denormalized for easier display in admin panel
    task_reward: float = Field(...) # Denormalized
    submitted_at: datetime = Field(default_factory=datetime.utcnow)
    completion_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="pending") # "pending", "approved", "rejected"
    reviewed_by: Optional[str] = None # Admin user_id who reviewed the submission
    reviewed_at: Optional[datetime] = None # Timestamp for when the submission was reviewed

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
    method: Optional[str] = None # e.g., "M-Pesa", "System"
    mpesa_receipt: Optional[str] = None # For M-Pesa transactions, store the receipt number
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None # Timestamp for when the transaction was completed

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
    user_id: Optional[str] = None # Null for broadcast notifications (sent to all users)
    title: str = Field(...)
    message: str = Field(...)
    type: NotificationType = Field(default=NotificationType.INFO)
    read: bool = Field(default=False) # Tracks if the user has read the notification
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
