from fastapi import FastAPI, HTTPException, Depends, Request, Form, UploadFile, File, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any, Annotated
import os
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta
import base64
import secrets
import asyncio
import json
import requests
from bson import ObjectId
from dotenv import load_dotenv
import logging

# Set up basic logging for better visibility in production
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file.
# IMPORTANT: For Render deployment, these variables MUST be set in Render's environment settings.
load_dotenv()

# --- Environment Variables ---
# These are loaded from .env locally, but will be provided by Render in production.
# Ensure these are set securely in your Render service environment variables.

MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-please-change-this-in-production-to-a-long-random-string') # CHANGE THIS IN PRODUCTION!
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30 # For production, consider shorter lifetimes and refresh tokens

# M-Pesa STK Push Credentials
# Obtain these from your Safaricom Daraja API application (production credentials for live app).
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', 'your_mpesa_consumer_key')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', 'your_mpesa_consumer_secret')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE', '174379') # Your Paybill or Till Number
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY', 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919') # Your Lipa Na M-Pesa Online Passkey

# M-Pesa API Endpoints (Production URLs)
# For production, change these from sandbox to live API URLs.
MPESA_AUTH_URL = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials" # Production Auth URL
MPESA_STK_PUSH_URL = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest" # Production STK Push URL
MPESA_B2C_URL = "https://api.safaricom.co.ke/mpesa/b2c/v1/paymentrequest" # Production B2C URL

# M-Pesa Callback URLs - These MUST be your public Render domain URLs.
# Configure these exact URLs in your Daraja API application settings.
MPESA_CALLBACK_URL = os.environ.get('MPESA_CALLBACK_URL', 'https://your-render-app-name.onrender.com/api/payments/stk-callback')
MPESA_B2C_RESULT_URL = os.environ.get('MPESA_B2C_RESULT_URL', 'https://your-render-app-name.onrender.com/api/payments/b2c-callback')
MPESA_B2C_TIMEOUT_URL = os.environ.get('MPESA_B2C_TIMEOUT_URL', 'https://your-render-app-name.onrender.com/api/payments/b2c-timeout')

# M-Pesa B2C (Withdrawal) Credentials
# MPESA_INITIATOR is the username for B2C (usually your paybill number's shortcode)
# MPESA_SECURITY_CREDENTIAL is the encrypted initiator password (generated from Daraja portal)
# For production, this MUST be generated from the LIVE Daraja portal using your production certificate.
MPESA_INITIATOR = os.environ.get('MPESA_INITIATOR', 'your_b2c_initiator_name')
MPESA_SECURITY_CREDENTIAL = os.environ.get('MPESA_SECURITY_CREDENTIAL', 'your_encrypted_b2c_initiator_password') # This is a long, encrypted string

ACTIVATION_AMOUNT = 500.0 # Constant for activation amount
REFERRAL_REWARD_AMOUNT = 50.0 # Reward for referrer upon referred user activation

app = FastAPI(title="EarnPlatform API", version="1.0.0")

# --- CORS Middleware ---
# In production, restrict allow_origins to your frontend domain(s) for security.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Example: ["https://your-frontend-domain.com", "http://localhost:3000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- MongoDB Connection ---
client = AsyncIOMotorClient(MONGO_URL)
db = client.earnplatform # Access the 'earnplatform' database

# --- Pydantic Models ---
# User Models
class UserRegister(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: str
    phone: str # E.164 format (e.g., 2547XXXXXXXX)
    referral_code: Optional[str] = None
    role: str = "user" # Default role for new registrations

class UserLogin(BaseModel):
    username: str
    password: str

class UserProfile(BaseModel):
    user_id: str = Field(alias="_id") # Map MongoDB's _id to user_id
    email: EmailStr
    username: str
    full_name: str
    phone: str
    referral_code: str
    referred_by: Optional[str] = None
    wallet_balance: float
    is_activated: bool
    activation_amount: float
    total_earned: float
    total_withdrawn: float
    referral_earnings: float
    task_earnings: float
    referral_count: int
    role: str # User's role (e.g., "user", "admin")
    created_at: datetime
    last_login: datetime
    notifications_enabled: bool
    theme: str

    class Config:
        populate_by_name = True # Allow mapping _id to user_id
        json_encoders = {datetime: lambda dt: dt.isoformat()}
        arbitrary_types_allowed = True # Needed for ObjectId if not converted immediately

# Transaction Models
class DepositRequest(BaseModel):
    amount: float
    phone: str # Expected in E.164 format (e.g., 2547XXXXXXXX)

class WithdrawalRequest(BaseModel):
    amount: float
    phone: str # Expected in E.164 format (e.g., 2547XXXXXXXX)
    reason: Optional[str] = "Withdrawal request"

# Task Models
class TaskCreate(BaseModel):
    title: str
    description: str
    reward: float
    type: str  # survey, ad, writing, referral, social
    requirements: Dict[str, Any]
    auto_approve: bool = True # New field: if True, reward is instant

class TaskCompletion(BaseModel):
    task_id: str
    completion_data: Dict[str, Any]

# Notification Model
class NotificationCreate(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None  # None means broadcast to all users

# --- Utility Functions ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role, # Include role in JWT payload
        'exp': datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def generate_referral_code() -> str:
    return secrets.token_urlsafe(8).upper()

def fix_mongo_ids(doc):
    """Recursively converts ObjectId to string in MongoDB dictionaries/lists for JSON serialization."""
    if isinstance(doc, list):
        return [fix_mongo_ids(item) for item in doc]
    elif isinstance(doc, dict):
        return {k: fix_mongo_ids(v) for k, v in doc.items()}
    elif isinstance(doc, ObjectId):
        return str(doc)
    else:
        return doc

# --- M-Pesa Access Token Cache ---
_mpesa_access_token_cache = {"token": None, "expiry": None}

async def get_mpesa_access_token() -> Optional[str]:
    """
    Fetches a new M-Pesa API access token or returns a cached one if not expired.
    Tokens are typically valid for 1 hour (3600 seconds). We refresh a bit early.
    """
    current_time = datetime.utcnow()

    if _mpesa_access_token_cache["token"] and _mpesa_access_token_cache["expiry"] and \
       _mpesa_access_token_cache["expiry"] > current_time + timedelta(minutes=5):
        return _mpesa_access_token_cache["token"]

    try:
        response = requests.get(
            MPESA_AUTH_URL, # Use production auth URL
            auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET),
            timeout=10
        )
        response.raise_for_status()
        token_data = response.json()
        token = token_data.get("access_token")

        expires_in_raw = token_data.get("expires_in", 3599)
        try:
            expires_in = int(expires_in_raw)
        except (ValueError, TypeError):
            logging.warning(f"Warning: 'expires_in' from M-Pesa was not an integer: {expires_in_raw}. Defaulting to 3599 seconds.")
            expires_in = 3599

        if token:
            _mpesa_access_token_cache["token"] = token
            _mpesa_access_token_cache["expiry"] = current_time + timedelta(seconds=expires_in)
            logging.info(f"M-Pesa access token refreshed. Expires at: {_mpesa_access_token_cache['expiry']}")
            return token
        else:
            logging.error(f"M-Pesa token response did not contain 'access_token': {token_data}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error getting M-Pesa access token: {e}")
        return None

def generate_stk_password(timestamp: str) -> str:
    """Generates the M-Pesa STK Push password required for the API call."""
    data_to_encode = f"{MPESA_BUSINESS_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    encoded_password = base64.b64encode(data_to_encode.encode("utf-8")).decode("utf-8")
    return encoded_password

def generate_b2c_security_credential() -> str:
    """Returns the pre-generated B2C SecurityCredential."""
    # For production, this value is generated from Daraja portal's "Encrypt Initiator Password" utility
    # using your production certificate. It's stored as an environment variable.
    return MPESA_SECURITY_CREDENTIAL

# --- Dependency to Get Current User ---
async def get_current_user(request: Request):
    token = request.headers.get('Authorization')
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No token provided")
    if token.startswith('Bearer '):
        token = token[7:]
    
    payload = verify_jwt_token(token)
    user_id = payload.get('user_id')
    user_email = payload.get('email')
    user_role = payload.get('role', 'user') # Default to 'user' if role is missing in token

    if user_id is None or user_email is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    # Fetch user from DB to get the most up-to-date user data, including current role
    user_doc = await db.users.find_one({"user_id": user_id})
    if not user_doc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    # Ensure the role from the token matches the role in the database for security
    # If roles can change, you might want to force re-login or re-issue token on role change.
    # For now, we'll use the role from the DB as the source of truth.
    user_doc['role'] = user_doc.get('role', 'user') # Ensure role exists in DB doc

    return user_doc

# --- Role-Based Access Control (RBAC) Dependency ---
class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    async def __call__(self, current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
        if current_user.get('role') not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions to access this resource."
            )
        return True # User has the required role

# --- Internal Helper Functions (for notifications and referrals) ---
async def create_notification(notification_data: Dict[str, Any]):
    """Creates a notification in the database."""
    notification_doc = {
        "notification_id": str(uuid.uuid4()),
        "title": notification_data.get("title", "Notification"),
        "message": notification_data.get("message", ""),
        "user_id": notification_data.get("user_id"),
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    await db.notifications.insert_one(notification_doc)
    logging.info(f"Notification created for user {notification_data.get('user_id')}: {notification_data.get('title')}")

async def process_referral_reward(referred_user_id: str, referrer_user_id: str):
    """
    Processes the referral reward when a referred user activates their account.
    """
    referral_record = await db.referrals.find_one({
        "referred_id": referred_user_id,
        "referrer_id": referrer_user_id,
        "status": "pending"
    })

    if referral_record:
        reward_amount = referral_record.get('reward_amount', REFERRAL_REWARD_AMOUNT)
        referrer = await db.users.find_one({"user_id": referrer_user_id})

        if referrer:
            # Update referrer's wallet balance and referral earnings
            await db.users.update_one(
                {"user_id": referrer_user_id},
                {"$inc": {
                    "wallet_balance": reward_amount,
                    "referral_earnings": reward_amount,
                    "referral_count": 1
                }}
            )
            # Update referral record status
            await db.referrals.update_one(
                {"_id": referral_record['_id']},
                {"$set": {
                    "status": "completed",
                    "activation_date": datetime.utcnow()
                }}
            )

            # Create notification for the referrer
            await create_notification({
                "title": "Referral Reward Earned!",
                "message": f"Great news! Your referred user has activated their account. You've earned KSH {reward_amount:.2f}.",
                "user_id": referrer_user_id
            })
            logging.info(f"Referral reward of KSH {reward_amount} processed for referrer {referrer_user_id}.")
        else:
            logging.error(f"Referrer user {referrer_user_id} not found for referral entry {referral_record['_id']}")
    else:
        logging.info(f"No pending referral record found for referred user {referred_user_id} by referrer {referrer_user_id}.")


# --- Database Startup Event (for indexing) ---
@app.on_event("startup")
async def startup_db_client():
    # Ensure unique indexes for critical fields
    await db.users.create_index([("email", 1)], unique=True)
    await db.users.create_index([("phone", 1)], unique=True)
    await db.users.create_index([("username", 1)], unique=True)
    await db.users.create_index([("user_id", 1)], unique=True)
    await db.users.create_index([("referral_code", 1)], unique=True)
    await db.users.create_index([("role", 1)]) # Index for role lookups

    # Indexes for transactions
    await db.transactions.create_index([("transaction_id", 1)], unique=True)
    await db.transactions.create_index([("user_id", 1)])
    await db.transactions.create_index([("CheckoutRequestID", 1)], unique=True, sparse=True) # For STK Push
    await db.transactions.create_index([("b2c_originator_id", 1)], unique=True, sparse=True) # For B2C
    await db.transactions.create_index([("created_at", -1)])

    # Indexes for referrals
    await db.referrals.create_index([("referred_id", 1)], unique=True)
    await db.referrals.create_index([("referrer_id", 1)])
    await db.referrals.create_index([("status", 1)])

    # Indexes for notifications
    await db.notifications.create_index([("user_id", 1)])
    await db.notifications.create_index([("created_at", -1)])

    logging.info("MongoDB indexes ensured.")

# --- Auth Routes ---
@app.post("/api/auth/register", summary="Register a new user")
async def register(user_data: UserRegister):
    existing_user_email = await db.users.find_one({"email": user_data.email})
    if existing_user_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    existing_user_phone = await db.users.find_one({"phone": user_data.phone})
    if existing_user_phone:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered")
    existing_user_username = await db.users.find_one({"username": user_data.username})
    if existing_user_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")

    # Basic phone format validation (2547XXXXXXXX)
    if not user_data.phone.startswith("254") or not user_data.phone[3:].isdigit() or len(user_data.phone) != 12:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number format. Use E.164 (e.g., 2547XXXXXXXX).")

    user_id = str(uuid.uuid4())
    referral_code = generate_referral_code()
    referred_by = None
    if user_data.referral_code:
        referrer = await db.users.find_one({"referral_code": user_data.referral_code})
        if referrer:
            referred_by = referrer['user_id']
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid referral code.")

    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "username": user_data.username,
        "password": hash_password(user_data.password),
        "full_name": user_data.full_name,
        "phone": user_data.phone,
        "referral_code": referral_code,
        "referred_by": referred_by,
        "wallet_balance": 0.0,
        "is_activated": False,
        "activation_amount": ACTIVATION_AMOUNT,
        "total_earned": 0.0,
        "total_withdrawn": 0.0,
        "referral_earnings": 0.0,
        "task_earnings": 0.0,
        "referral_count": 0,
        "role": user_data.role, # Role from Pydantic model (defaults to "user")
        "created_at": datetime.utcnow(),
        "last_login": datetime.utcnow(),
        "notifications_enabled": True,
        "theme": "light"
    }
    await db.users.insert_one(user_doc)

    if referred_by:
        await db.referrals.insert_one({
            "referral_id": str(uuid.uuid4()),
            "referrer_id": referred_by,
            "referred_id": user_id,
            "status": "pending",
            "created_at": datetime.utcnow(),
            "activation_date": None,
            "reward_amount": REFERRAL_REWARD_AMOUNT
        })

    token = create_jwt_token(user_id, user_data.email, user_data.role)
    return {
        "success": True,
        "message": f"Registration successful! Please deposit KSH {ACTIVATION_AMOUNT} to activate your account.",
        "token": token,
        "user": fix_mongo_ids({
            "user_id": user_id,
            "email": user_data.email,
            "username": user_data.username,
            "full_name": user_data.full_name,
            "referral_code": referral_code,
            "is_activated": False,
            "wallet_balance": 0.0,
            "role": user_data.role
        })
    }

@app.post("/api/auth/login", summary="Login user")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"username": user_data.username})
    if not user or not verify_password(user_data.password, user['password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    await db.users.update_one(
        {"user_id": user['user_id']},
        {"$set": {"last_login": datetime.utcnow()}}
    )

    token = create_jwt_token(user['user_id'], user['email'], user.get('role', 'user'))
    return {
        "success": True,
        "message": "Login successful!",
        "token": token,
        "user": fix_mongo_ids({
            "user_id": user['user_id'],
            "email": user['email'],
            "username": user['username'],
            "full_name": user['full_name'],
            "referral_code": user['referral_code'],
            "is_activated": user['is_activated'],
            "wallet_balance": user['wallet_balance'],
            "role": user.get('role', 'user'),
            "theme": user.get('theme', 'light')
        })
    }

# --- Dashboard & User Data ---
@app.get("/api/dashboard/stats", response_model=Dict[str, Any], summary="Get user dashboard stats")
async def get_dashboard_stats(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    user_id = current_user['user_id']

    transactions = await db.transactions.find(
        {"user_id": user_id}
    ).sort("created_at", -1).limit(10).to_list(10)

    referral_stats = await db.referrals.aggregate([
        {"$match": {"referrer_id": user_id}},
        {"$group": {
            "_id": "$status",
            "count": {"$sum": 1},
            "total_reward": {"$sum": "$reward_amount"}
        }}
    ]).to_list(10)

    task_completions = await db.task_completions.count_documents({"user_id": user_id})

    notifications = await db.notifications.find(
        {"$or": [{"user_id": user_id}, {"user_id": None}]}
    ).sort("created_at", -1).limit(5).to_list(5)

    return {
        "success": True,
        "user": fix_mongo_ids({
            "full_name": current_user['full_name'],
            "wallet_balance": current_user['wallet_balance'],
            "is_activated": current_user['is_activated'],
            "activation_amount": current_user.get('activation_amount', ACTIVATION_AMOUNT),
            "total_earned": current_user.get('total_earned', 0.0),
            "total_withdrawn": current_user.get('total_withdrawn', 0.0),
            "referral_earnings": current_user.get('referral_earnings', 0.0),
            "task_earnings": current_user.get('task_earnings', 0.0),
            "referral_count": current_user.get('referral_count', 0),
            "referral_code": current_user['referral_code'],
            "role": current_user.get('role', 'user')
        }),
        "recent_transactions": fix_mongo_ids(transactions),
        "referral_stats": fix_mongo_ids(referral_stats),
        "task_completions": task_completions,
        "notifications": fix_mongo_ids(notifications)
    }

# --- Payment Routes (STK Push for Deposits, B2C for Withdrawals) ---
@app.post("/api/payments/deposit", summary="Initiate M-Pesa STK Push for deposit")
async def initiate_deposit(
    deposit_data: DepositRequest,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    # Only 'user' and 'admin' roles can initiate deposits
    has_permission: Annotated[bool, Depends(RoleChecker(["user", "admin"]))]
):
    if not deposit_data.phone.startswith("254") or len(deposit_data.phone) != 12 or not deposit_data.phone[3:].isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number format. Must be 254xxxxxxxxxx (E.164).")

    if deposit_data.amount <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Deposit amount must be greater than zero.")

    # For security, ensure the phone number for deposit matches the user's registered phone
    if deposit_data.phone != current_user['phone']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Deposit can only be initiated for your registered phone number.")

    transaction_id = str(uuid.uuid4())

    transaction_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "deposit",
        "amount": deposit_data.amount,
        "phone": deposit_data.phone,
        "status": "pending_mpesa_stk",
        "method": "mpesa_stk_push",
        "created_at": datetime.utcnow(),
        "completed_at": None,
        "mpesa_receipt": None,
        "MerchantRequestID": None,
        "CheckoutRequestID": None
    }
    await db.transactions.insert_one(transaction_doc)

    access_token = await get_mpesa_access_token()
    if not access_token:
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "completed_at": datetime.utcnow(), "mpesa_response_error": "Failed to get M-Pesa access token"}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to connect to M-Pesa. Please try again later.")

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = generate_stk_password(timestamp)

    payload = {
        "BusinessShortCode": MPESA_BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(deposit_data.amount),
        "PartyA": deposit_data.phone,
        "PartyB": MPESA_BUSINESS_SHORTCODE,
        "PhoneNumber": deposit_data.phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": transaction_id,
        "TransactionDesc": f"Deposit to EarnPlatform for User {current_user['user_id']}"
    }

    try:
        response = requests.post(MPESA_STK_PUSH_URL, headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}, json=payload, timeout=30)
        response.raise_for_status()
        stk_response = response.json()

        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {
                "MerchantRequestID": stk_response.get("MerchantRequestID"),
                "CheckoutRequestID": stk_response.get("CheckoutRequestID"),
                "mpesa_response_code": stk_response.get("ResponseCode"),
                "mpesa_response_description": stk_response.get("ResponseDescription"),
                "customer_message": stk_response.get("CustomerMessage")
            }}
        )

        if stk_response.get("ResponseCode") == "0":
            return {
                "success": True,
                "message": "STK Push initiated successfully. Please check your phone for the M-Pesa prompt.",
                "transaction_id": transaction_id,
                "MerchantRequestID": stk_response.get("MerchantRequestID"),
                "CheckoutRequestID": stk_response.get("CheckoutRequestID")
            }
        else:
            await db.transactions.update_one(
                {"transaction_id": transaction_id},
                {"$set": {"status": "failed_stk_init", "completed_at": datetime.utcnow()}}
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=stk_response.get("ResponseDescription", "STK Push initiation failed. Please try again."))

    except requests.exceptions.RequestException as e:
        logging.error(f"STK Push API call error: {e}")
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "completed_at": datetime.utcnow(), "mpesa_response_error": str(e)}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to communicate with M-Pesa. Error: {e}")

@app.post("/api/payments/stk-callback", summary="M-Pesa STK Push Callback Endpoint (Internal)")
async def mpesa_stk_callback(request: Request):
    callback_data = await request.json()
    logging.info(f"M-Pesa STK Callback Received: {json.dumps(callback_data, indent=2)}")

    try:
        stk_callback_body = callback_data['Body']['stkCallback']
        result_code = stk_callback_body['ResultCode']
        checkout_request_id = stk_callback_body['CheckoutRequestID']

        transaction = await db.transactions.find_one({
            "CheckoutRequestID": checkout_request_id,
            "status": "pending_mpesa_stk"
        })

        if not transaction:
            logging.warning(f"STK Callback: Transaction not found for CheckoutRequestID: {checkout_request_id}. Maybe already processed or invalid.")
            return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)

        user = await db.users.find_one({"user_id": transaction['user_id']})
        if not user:
            logging.error(f"STK Callback: User not found for transaction {transaction['transaction_id']}. Cannot update balance/status.")
            return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)

        update_fields = {
            "completed_at": datetime.utcnow(),
            "mpesa_result_code": result_code,
            "mpesa_result_description": stk_callback_body.get('ResultDesc'),
            "mpesa_raw_callback": callback_data # Store raw callback for auditing
        }

        if result_code == 0: # Payment was successful
            callback_metadata = stk_callback_body.get('CallbackMetadata', {}).get('Item', [])

            mpesa_receipt_number = next((item['Value'] for item in callback_metadata if item['Name'] == 'MpesaReceiptNumber'), None)
            transaction_amount = next((item['Value'] for item in callback_metadata if item['Name'] == 'Amount'), transaction['amount'])
            phone_number_paid = next((item['Value'] for item in callback_metadata if item['Name'] == 'PhoneNumber'), transaction['phone'])

            update_fields.update({
                "status": "completed",
                "mpesa_receipt": mpesa_receipt_number,
                "amount_received": float(transaction_amount),
                "phone_number_paid": phone_number_paid
            })

            new_balance = user['wallet_balance'] + float(transaction_amount)
            user_update_data = {"wallet_balance": new_balance}

            if not user['is_activated'] and float(transaction_amount) >= user.get('activation_amount', ACTIVATION_AMOUNT):
                user_update_data['is_activated'] = True
                if user.get('referred_by'):
                    await process_referral_reward(user['user_id'], user['referred_by'])

            await db.users.update_one({"user_id": user['user_id']}, {"$set": user_update_data})

            await create_notification({
                "title": "Deposit Successful!",
                "message": f"Your deposit of KSH {float(transaction_amount):.2f} has been processed successfully. Your new balance is KSH {new_balance:.2f}.",
                "user_id": user['user_id']
            })
            logging.info(f"STK Push Success: CheckoutRequestID={checkout_request_id}, Receipt={mpesa_receipt_number}, Amount={transaction_amount}")

        else: # Payment failed or was cancelled by user
            update_fields["status"] = "failed"
            logging.warning(f"STK Push Failed: CheckoutRequestID={checkout_request_id}, ResultCode={result_code}, ResultDesc={stk_callback_body.get('ResultDesc')}")

            await create_notification({
                "title": "Deposit Failed",
                "message": f"Your deposit of KSH {transaction['amount']} failed. Reason: {stk_callback_body.get('ResultDesc', 'Unknown error')}",
                "user_id": user['user_id']
            })

        await db.transactions.update_one(
            {"_id": transaction['_id']},
            {"$set": update_fields}
        )

    except KeyError as e:
        logging.error(f"Error parsing M-Pesa STK callback data: Missing key {e}. Full data: {json.dumps(callback_data, indent=2)}")
    except Exception as e:
        logging.error(f"An unexpected error occurred processing STK callback: {e}. Full data: {json.dumps(callback_data, indent=2)}")

    return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)

@app.post("/api/payments/withdraw", summary="Initiate M-Pesa B2C Withdrawal")
async def request_withdrawal(
    withdrawal_data: WithdrawalRequest,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    # Only 'user' and 'admin' roles can initiate withdrawals
    has_permission: Annotated[bool, Depends(RoleChecker(["user", "admin"]))]
):
    if not current_user['is_activated']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account must be activated before withdrawal.")

    if withdrawal_data.amount > current_user['wallet_balance']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance for withdrawal.")

    if withdrawal_data.amount < 100:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Minimum withdrawal amount is KSH 100.")

    if not withdrawal_data.phone.startswith("254") or len(withdrawal_data.phone) != 12 or not withdrawal_data.phone[3:].isdigit():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number format. Must be 254xxxxxxxxxx (E.164).")

    # For security, ensure the phone number for withdrawal matches the user's registered phone
    if withdrawal_data.phone != current_user['phone']:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Withdrawal can only be initiated to your registered phone number.")

    transaction_id = str(uuid.uuid4())
    withdrawal_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "withdrawal",
        "amount": withdrawal_data.amount,
        "phone": withdrawal_data.phone,
        "reason": withdrawal_data.reason,
        "status": "pending_b2c_init",
        "method": "mpesa_b2c",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "b2c_conversation_id": None,
        "b2c_originator_id": None
    }
    await db.transactions.insert_one(withdrawal_doc)

    # Immediately deduct from user's balance to prevent overdrafts.
    # If B2C fails, the amount will be refunded in the callback.
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$inc": {"wallet_balance": -withdrawal_data.amount}}
    )

    b2c_access_token = await get_mpesa_access_token()
    if not b2c_access_token:
        await db.users.update_one(
            {"user_id": current_user['user_id']},
            {"$inc": {"wallet_balance": withdrawal_data.amount}}
        )
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "processed_at": datetime.utcnow(), "error_message": "Failed to get B2C access token."}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to process withdrawal: M-Pesa access token unavailable.")

    b2c_response = requests.post(
        MPESA_B2C_URL, # Use production B2C URL
        json={
            "InitiatorName": MPESA_INITIATOR,
            "SecurityCredential": generate_b2c_security_credential(),
            "CommandID": "BusinessPayment",
            "Amount": withdrawal_data.amount,
            "PartyA": MPESA_BUSINESS_SHORTCODE,
            "PartyB": withdrawal_data.phone,
            "Remarks": withdrawal_data.reason,
            "QueueTimeOutURL": MPESA_B2C_TIMEOUT_URL,
            "ResultURL": MPESA_B2C_RESULT_URL,
            "Occasion": transaction_id
        },
        headers={"Authorization": f"Bearer {b2c_access_token}", "Content-Type": "application/json"},
        timeout=30
    ).json()

    if b2c_response and b2c_response.get("ResponseCode") == "0":
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {
                "status": "pending_b2c_callback",
                "b2c_conversation_id": b2c_response.get('ConversationID'),
                "b2c_originator_id": b2c_response.get('OriginatorConversationID'),
                "mpesa_raw_init_response": b2c_response # Store initial response
            }}
        )
        return {
            "success": True,
            "message": f"Withdrawal request of KSH {withdrawal_data.amount} submitted. You will receive your funds shortly.",
            "transaction_id": transaction_id,
            "b2c_response_details": b2c_response
        }
    else:
        logging.error(f"B2C initiation failed for transaction {transaction_id}: {b2c_response}")
        await db.users.update_one(
            {"user_id": current_user['user_id']},
            {"$inc": {"wallet_balance": withdrawal_data.amount}}
        )
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "processed_at": datetime.utcnow(), "error_message": b2c_response.get("ResponseDescription", "Unknown B2C initiation error")}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initiate withdrawal with M-Pesa. Please try again.")

@app.post("/api/payments/b2c-callback", summary="M-Pesa B2C Result Callback Endpoint (Internal)")
async def mpesa_b2c_callback(request: Request):
    payload = await request.json()
    logging.info(f"M-Pesa B2C Callback Received: {json.dumps(payload, indent=2)}")

    result = payload.get("Result", {})
    originator_conversation_id = result.get("OriginatorConversationID")
    result_code = result.get("ResultCode")
    result_desc = result.get("ResultDesc")

    # The Occasion field from the initial request is often found in ResultParameters
    result_parameters = result.get("ResultParameters", {}).get("ResultParameter", [])
    transaction_id_from_occasion = next((item['Value'] for item in result_parameters if item['Key'] == 'Occasion'), None)

    # Use the transaction_id from Occasion or OriginatorConversationID for lookup
    transaction = await db.transactions.find_one({
        "$or": [
            {"transaction_id": transaction_id_from_occasion},
            {"b2c_originator_id": originator_conversation_id}
        ],
        "status": "pending_b2c_callback"
    })

    if not transaction:
        logging.warning(f"B2C Callback: Transaction not found for Occasion/OriginatorConversationID: {transaction_id_from_occasion}/{originator_conversation_id}. Maybe already processed or invalid.")
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Callback received"}, status_code=200)

    user = await db.users.find_one({"user_id": transaction['user_id']})
    if not user:
        logging.error(f"B2C Callback: User not found for transaction {transaction['transaction_id']}. Cannot update wallet.")
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Callback received"}, status_code=200)

    update_fields = {
        "processed_at": datetime.utcnow(),
        "b2c_callback_received": True,
        "b2c_result_code": result_code,
        "b2c_result_description": result_desc,
        "mpesa_raw_callback": payload # Store raw callback for auditing
    }

    if result_code == 0: # B2C withdrawal was successful
        amount_withdrawn = next((item['Value'] for item in result_parameters if item['Key'] == 'Amount'), None)
        mpesa_receipt_number = next((item['Value'] for item in result_parameters if item['Key'] == 'TransactionID'), None)

        update_fields["status"] = "completed"
        update_fields["mpesa_receipt"] = mpesa_receipt_number
        update_fields["amount_processed"] = float(amount_withdrawn) if amount_withdrawn else transaction['amount']

        await db.users.update_one(
            {"user_id": user['user_id']},
            {"$inc": {"total_withdrawn": update_fields['amount_processed']}}
        )

        await create_notification({
            "title": "Withdrawal Successful!",
            "message": f"Your withdrawal of KSH {update_fields['amount_processed']:.2f} has been sent to your M-Pesa. Receipt: {mpesa_receipt_number}.",
            "user_id": user['user_id']
        })
        logging.info(f"B2C Success: Transaction {transaction['transaction_id']} for User {user['user_id']} completed. Amount: {update_fields['amount_processed']:.2f}, Receipt: {mpesa_receipt_number}")

    else: # B2C withdrawal failed
        update_fields["status"] = "failed"
        update_fields["error_message"] = result_desc

        refund_amount = transaction['amount']
        await db.users.update_one(
            {"user_id": user['user_id']},
            {"$inc": {"wallet_balance": refund_amount}}
        )

        await create_notification({
            "title": "Withdrawal Failed",
            "message": f"Your withdrawal of KSH {refund_amount:.2f} failed. Funds have been returned to your wallet. Reason: {result_desc}.",
            "user_id": user['user_id']
        })
        logging.warning(f"B2C Failed: Transaction {transaction['transaction_id']} for User {user['user_id']} failed. Reason: {result_desc}. Amount {refund_amount:.2f} refunded.")

    await db.transactions.update_one(
        {"_id": transaction['_id']},
        {"$set": update_fields}
    )

    return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Callback received"}, status_code=200)

@app.post("/api/payments/b2c-timeout", summary="M-Pesa B2C Timeout Callback Endpoint (Internal)")
async def mpesa_b2c_timeout_callback(request: Request):
    payload = await request.json()
    logging.warning(f"M-Pesa B2C Timeout Callback Received: {json.dumps(payload, indent=2)}")

    timeout_data = payload.get("Result", {})
    originator_conversation_id = timeout_data.get("OriginatorConversationID")
    result_code = timeout_data.get("ResultCode")
    result_desc = timeout_data.get("ResultDesc")
    transaction_id_from_occasion = timeout_data.get("Occasion")

    transaction = await db.transactions.find_one({
        "$or": [
            {"transaction_id": transaction_id_from_occasion},
            {"b2c_originator_id": originator_conversation_id}
        ],
        "status": "pending_b2c_callback"
    })

    if not transaction:
        logging.warning(f"B2C Timeout: Transaction not found for Occasion/OriginatorConversationID: {transaction_id_from_occasion}/{originator_conversation_id}. Maybe already processed or invalid.")
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Timeout Callback received"}, status_code=200)

    user = await db.users.find_one({"user_id": transaction['user_id']})
    if not user:
        logging.error(f"B2C Timeout: User not found for transaction {transaction['transaction_id']}. Cannot update wallet.")
        return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Timeout Callback received"}, status_code=200)

    update_fields = {
        "processed_at": datetime.utcnow(),
        "status": "timeout_or_unknown_failed",
        "b2c_timeout_callback_received": True,
        "b2c_result_code": result_code,
        "b2c_result_description": result_desc,
        "mpesa_raw_callback": payload, # Store raw callback for auditing
        "error_message": "M-Pesa B2C request timed out or final status unknown."
    }

    refund_amount = transaction['amount']
    await db.users.update_one(
        {"user_id": user['user_id']},
        {"$inc": {"wallet_balance": refund_amount}}
    )

    await db.transactions.update_one(
        {"_id": transaction['_id']},
        {"$set": update_fields}
    )

    await create_notification({
        "title": "Withdrawal Status Unknown",
        "message": f"Your withdrawal of KSH {refund_amount:.2f} had an unknown issue with M-Pesa or timed out. Funds have been returned to your wallet. Please check your M-Pesa statement and try again later.",
        "user_id": user['user_id']
    })
    logging.warning(f"B2C Timeout: Transaction {transaction['transaction_id']} for User {user['user_id']} timed out. Amount {refund_amount:.2f} refunded.")

    return JSONResponse(content={"ResultCode": 0, "ResultDesc": "Timeout Callback received"}, status_code=200)

# --- Task Management Routes ---
@app.post("/api/tasks", status_code=status.HTTP_201_CREATED, summary="Create a new task (Admin Only)")
async def create_task(
    task_data: TaskCreate,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    # Only 'admin' role can create tasks
    has_admin_role: Annotated[bool, Depends(RoleChecker(["admin"]))]
):
    task_doc = task_data.dict()
    task_doc["task_id"] = str(uuid.uuid4())
    task_doc["created_at"] = datetime.utcnow()
    task_doc["created_by"] = current_user['user_id']
    await db.tasks.insert_one(task_doc)
    return {"success": True, "message": "Task created successfully", "task_id": task_doc["task_id"]}

@app.get("/api/tasks", summary="Get all available tasks")
async def get_tasks(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    tasks = await db.tasks.find({}).to_list(100)
    return {"success": True, "tasks": fix_mongo_ids(tasks)}

@app.post("/api/tasks/complete", summary="Submit task completion")
async def complete_task(
    completion_data: TaskCompletion,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)]
):
    user_id = current_user['user_id']

    if not current_user['is_activated']:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please activate your account to complete tasks and earn.")

    task = await db.tasks.find_one({"task_id": completion_data.task_id})
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    existing_completion = await db.task_completions.find_one({
        "user_id": user_id,
        "task_id": completion_data.task_id,
        "status": {"$in": ["pending", "completed"]}
    })
    if existing_completion:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You have already completed this task.")

    completion_doc = {
        "completion_id": str(uuid.uuid4()),
        "user_id": user_id,
        "task_id": completion_data.task_id,
        "completion_data": completion_data.completion_data,
        "status": "pending",
        "reward_amount": task['reward'],
        "completed_at": datetime.utcnow()
    }
    await db.task_completions.insert_one(completion_doc)

    if task.get("auto_approve", True):
        new_balance = current_user['wallet_balance'] + task['reward']
        await db.users.update_one(
            {"user_id": user_id},
            {"$set": {"wallet_balance": new_balance}, "$inc": {"task_earnings": task['reward']}}
        )
        await db.task_completions.update_one(
            {"_id": completion_doc['_id']},
            {"$set": {"status": "completed", "approved_at": datetime.utcnow()}}
        )
        await create_notification({
            "title": "Task Completed!",
            "message": f"You've successfully completed '{task['title']}' and earned KSH {task['reward']:.2f}.",
            "user_id": user_id
        })
        return {"success": True, "message": "Task completed and reward credited!", "reward": task['reward']}
    else:
        await create_notification({
            "title": "Task Submitted for Review",
            "message": f"Your completion for '{task['title']}' has been submitted for review. Reward will be credited upon approval.",
            "user_id": user_id
        })
        return {"success": True, "message": "Task submitted for review. Reward will be credited after approval."}

# --- Notifications Routes ---
@app.get("/api/notifications", summary="Get user-specific and broadcast notifications")
async def get_notifications(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    user_id = current_user['user_id']
    notifications = await db.notifications.find(
        {"$or": [{"user_id": user_id}, {"user_id": None}]}
    ).sort("created_at", -1).to_list(20)

    return {"success": True, "notifications": fix_mongo_ids(notifications)}

@app.post("/api/notifications/{notification_id}/read", summary="Mark a notification as read")
async def mark_notification_as_read(
    notification_id: str,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)]
):
    result = await db.notifications.update_one(
        {"notification_id": notification_id, "user_id": current_user['user_id']},
        {"$set": {"is_read": True}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found or not authorized.")
    return {"success": True, "message": "Notification marked as read."}

@app.post("/api/admin/notifications/broadcast", summary="Broadcast a notification (Admin Only)")
async def broadcast_notification(
    notification_data: NotificationCreate,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    # Only 'admin' role can broadcast notifications
    has_admin_role: Annotated[bool, Depends(RoleChecker(["admin"]))]
):
    notification_data.user_id = None # Explicitly set to None for broadcast
    await create_notification(notification_data.dict())
    return {"success": True, "message": "Broadcast notification sent."}

# --- User Profile & Settings ---
@app.get("/api/user/profile", response_model=UserProfile, summary="Get current user profile")
async def get_user_profile(current_user: Annotated[Dict[str, Any], Depends(get_current_user)]):
    return UserProfile(**current_user)

@app.put("/api/user/profile", response_model=UserProfile, summary="Update current user profile")
async def update_user_profile(
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)], # Moved to the start
    full_name: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    notifications_enabled: Optional[bool] = Form(None),
    theme: Optional[str] = Form(None)
):
    update_data = {}
    if full_name:
        update_data["full_name"] = full_name
    if phone:
        if not phone.startswith("254") or len(phone) != 12 or not phone[3:].isdigit():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone number format. Use E.164 (e.g., 2547XXXXXXXX).")
        update_data["phone"] = phone
    if notifications_enabled is not None:
        update_data["notifications_enabled"] = notifications_enabled
    if theme:
        if theme not in ["light", "dark"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid theme. Must be 'light' or 'dark'.")
        update_data["theme"] = theme

    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided.")

    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$set": update_data}
    )
    updated_user = await db.users.find_one({"user_id": current_user['user_id']})
    return UserProfile(**updated_user)

@app.put("/api/user/change-password", summary="Change user password")
async def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)]
):
    if not verify_password(old_password, current_user['password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid old password.")

    if len(new_password) < 6:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must be at least 6 characters long.")

    hashed_new_password = hash_password(new_password)
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$set": {"password": hashed_new_password}}
    )
    return {"success": True, "message": "Password changed successfully."}

# --- Admin Endpoints (Protected by RoleChecker) ---
@app.get("/api/admin/users", response_model=List[UserProfile], summary="Get all users (Admin Only)")
async def get_all_users(
    skip: int = 0,
    limit: int = 100,
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    has_admin_role: Annotated[bool, Depends(RoleChecker(["admin"]))] # Requires 'admin' role
):
    users_cursor = db.users.find({}).skip(skip).limit(limit)
    users = []
    async for user_doc in users_cursor:
        users.append(UserProfile(**user_doc))
    return users

@app.put("/api/admin/users/{user_id}/role", response_model=UserProfile, summary="Update user role (Admin Only)")
async def update_user_role(
    user_id: str,
    new_role: str = Form(...),
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    has_admin_role: Annotated[bool, Depends(RoleChecker(["admin"]))] # Requires 'admin' role
):
    if new_role not in ["user", "admin"]: # Define allowed roles
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified. Must be 'user' or 'admin'.")

    update_result = await db.users.update_one(
        {"user_id": user_id},
        {"$set": {"role": new_role, "last_login": datetime.utcnow()}} # Use last_login as a simple update timestamp
    )
    if update_result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    updated_user = await db.users.find_one({"user_id": user_id})
    return UserProfile(**updated_user)


@app.get("/api/admin/transactions", summary="Get all transactions (Admin Only)")
async def get_all_transactions(
    skip: int = 0,
    limit: int = 100,
    transaction_type: Optional[str] = None,
    status_filter: Optional[str] = None, # Renamed to avoid conflict with HTTP status
    current_user: Annotated[Dict[str, Any], Depends(get_current_user)],
    has_admin_role: Annotated[bool, Depends(RoleChecker(["admin"]))] # Requires 'admin' role
):
    query = {}
    if transaction_type:
        query["type"] = transaction_type
    if status_filter:
        query["status"] = status_filter
    
    transactions = await db.transactions.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return {"success": True, "transactions": fix_mongo_ids(transactions)}


# --- Root Endpoint ---
@app.get("/", summary="API Root")
async def read_root():
    return {"message": "Welcome to the EarnPlatform API! Visit /docs for API documentation."}

