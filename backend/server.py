from fastapi import FastAPI, HTTPException, Depends, Request, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import os
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta
import base64
import secrets
import asyncio
from urllib.parse import urlparse
import json
import requests
from bson import ObjectId

# === Environment Variables ===
# IMPORTANT: These should be set in your actual environment or in a .env file
# (e.g., using `python-dotenv` library, which you'd need to `pip install python-dotenv`
# and add `load_dotenv()` at the top of the file if you are using a .env file).
# For production, always use environment variables, not hardcoded values or .env files directly.

MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here') # CHANGE THIS IN PRODUCTION!

# M-Pesa STK Push Credentials
# You get these from your Safaricom Daraja API application.
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', 'default_consumer_key') # Replace with your actual key
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', 'default_consumer_secret') # Replace with your actual secret
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE', '174379') # Your Paybill or Till Number
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY', 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b107ed920d16f34607ff7b') # Your Lipa Na M-Pesa Online Passkey

# This is the public URL M-Pesa will call to send you transaction results.
# For local development, use an Ngrok HTTPS URL. For production, use your domain.
MPESA_CALLBACK_URL = os.environ.get('MPESA_CALLBACK_URL', 'https://your-ngrok-url.ngrok.io/api/payments/stk-callback') # *** MUST BE UPDATED ***

# M-Pesa B2C (Withdrawal) Credentials
# MPESA_INITIATOR is the username for B2C (usually your paybill number's shortcode)
# MPESA_SECURITY_CREDENTIAL is the encrypted initiator password (generated from Daraja portal)
MPESA_INITIATOR = os.environ.get('MPESA_INITIATOR', 'default_initiator') # From Daraja
MPESA_SECURITY_CREDENTIAL = os.environ.get('MPESA_SECURITY_CREDENTIAL', 'default_security_credential') # From Daraja
MPESA_B2C_URL = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest" # Sandbox URL

# B2C Result and Timeout URLs - These also need to be public for production
MPESA_B2C_RESULT_URL = os.environ.get('MPESA_B2C_RESULT_URL', 'https://yourdomain.com/api/payments/b2c-callback')
MPESA_B2C_TIMEOUT_URL = os.environ.get('MPESA_B2C_TIMEOUT_URL', 'https://yourdomain.com/api/payments/b2c-timeout')


ACTIVATION_AMOUNT = 500.0 # Constant for activation amount

app = FastAPI(title="EarnPlatform API", version="1.0.0")

# === CORS Middleware ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Consider restricting this to your frontend domain(s) in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === MongoDB Connection ===
client = AsyncIOMotorClient(MONGO_URL)
db = client.earnplatform

# === Pydantic Models ===
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    phone: str # Consider a custom validator for E.164 format
    referral_code: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class DepositRequest(BaseModel):
    amount: float
    phone: str # Expected in E.164 format (e.g., 2547XXXXXXXX)

class WithdrawalRequest(BaseModel):
    amount: float
    phone: str # Expected in E.164 format (e.g., 2547XXXXXXXX)
    reason: Optional[str] = "Withdrawal request"

class Task(BaseModel):
    title: str
    description: str
    reward: float
    type: str  # survey, ad, writing, referral, social
    requirements: Dict[str, Any]

class TaskCompletion(BaseModel):
    task_id: str
    completion_data: Dict[str, Any]

class NotificationCreate(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None  # None means broadcast to all users

# === Utility Functions ===
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=30) # Token valid for 30 days
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def generate_referral_code() -> str:
    return secrets.token_urlsafe(8).upper() # Generates a URL-safe random string

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

# --- M-Pesa STK Push and B2C Helper Functions ---

# Global cache for M-Pesa access token. In a larger application, consider Redis or similar.
_mpesa_access_token_cache = {"token": None, "expiry": None}

async def get_mpesa_access_token() -> Optional[str]:
    """
    Fetches a new M-Pesa API access token or returns a cached one if not expired.
    Tokens are typically valid for 1 hour (3600 seconds). We refresh a bit early.
    """
    current_time = datetime.utcnow()
    
    # Check if token exists and is still valid (e.g., refresh 5 minutes before actual expiry)
    if _mpesa_access_token_cache["token"] and _mpesa_access_token_cache["expiry"] and \
       _mpesa_access_token_cache["expiry"] > current_time + timedelta(minutes=5):
        return _mpesa_access_token_cache["token"]

    # If no token or expired, fetch a new one
    auth_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    try:
        response = requests.get(
            auth_url,
            auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET),
            timeout=10 # Set a timeout for the request
        )
        response.raise_for_status() # Raises HTTPError for 4xx/5xx responses
        token_data = response.json()
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3599) # Default to 1 hour if not provided

        if token:
            _mpesa_access_token_cache["token"] = token
            _mpesa_access_token_cache["expiry"] = current_time + timedelta(seconds=expires_in)
            print(f"M-Pesa access token refreshed. Expires at: {_mpesa_access_token_cache['expiry']}")
            return token
        else:
            print(f"M-Pesa token response did not contain 'access_token': {token_data}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting M-Pesa access token: {e}")
        return None

def generate_stk_password(timestamp: str) -> str:
    """Generates the M-Pesa STK Push password required for the API call."""
    # The formula is: BusinessShortCode + Passkey + Timestamp
    data_to_encode = f"{MPESA_BUSINESS_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    encoded_password = base64.b64encode(data_to_encode.encode("utf-8")).decode("utf-8")
    return encoded_password

def generate_b2c_security_credential(initiator_password: str) -> str:
    """
    Generates the SecurityCredential for B2C.
    This is usually done via Daraja portal to get an encrypted password.
    In a real scenario, you'd integrate with Safaricom's public key for encryption.
    For sandbox, MPESA_SECURITY_CREDENTIAL from .env is typically the base64 encoded,
    encrypted password you generate on Daraja portal.
    """
    # For Sandbox, you get this pre-generated from Daraja portal (Encrypt Initiator Password utility)
    # For production, you'd use a certificate for encryption.
    # The MPESA_SECURITY_CREDENTIAL environment variable should hold this pre-generated value.
    return MPESA_SECURITY_CREDENTIAL


# === Dependency to Get Current User ===
async def get_current_user(request: Request):
    token = request.headers.get('Authorization')
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    if token.startswith('Bearer '):
        token = token[7:]
    payload = verify_jwt_token(token)
    user = await db.users.find_one({"user_id": payload['user_id']})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# --- Auth Routes ---
@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing_phone = await db.users.find_one({"phone": user_data.phone})
    if existing_phone:
        raise HTTPException(status_code=400, detail="Phone number already registered")
    
    # Basic phone format validation (2547XXXXXXXX)
    if not user_data.phone.startswith("254") or not user_data.phone[3:].isdigit() or len(user_data.phone) != 12:
        raise HTTPException(status_code=400, detail="Invalid phone number format. Use E.164 (e.g., 2547XXXXXXXX).")

    user_id = str(uuid.uuid4())
    referral_code = generate_referral_code()
    referred_by = None
    if user_data.referral_code:
        referrer = await db.users.find_one({"referral_code": user_data.referral_code})
        if referrer:
            referred_by = referrer['user_id']
    
    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
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
            "reward_amount": 50.0 # Reward for referrer upon activation
        })
    
    token = create_jwt_token(user_id, user_data.email)
    return {
        "success": True,
        "message": f"Registration successful! Please deposit KSH {ACTIVATION_AMOUNT} to activate your account.",
        "token": token,
        "user": {
            "user_id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "referral_code": referral_code,
            "is_activated": False,
            "wallet_balance": 0.0
        }
    }

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    await db.users.update_one(
        {"user_id": user['user_id']},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    token = create_jwt_token(user['user_id'], user['email'])
    return {
        "success": True,
        "message": "Login successful!",
        "token": token,
        "user": {
            "user_id": user['user_id'],
            "email": user['email'],
            "full_name": user['full_name'],
            "referral_code": user['referral_code'],
            "is_activated": user['is_activated'],
            "wallet_balance": user['wallet_balance'],
            "theme": user.get('theme', 'light') # Default theme to 'light'
        }
    }

---

## Dashboard & User Data

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    user_id = current_user['user_id']
    
    # Fetch recent transactions
    transactions = await db.transactions.find(
        {"user_id": user_id}
    ).sort("created_at", -1).limit(10).to_list(10)
    
    # Aggregate referral statistics
    referral_stats = await db.referrals.aggregate([
        {"$match": {"referrer_id": user_id}},
        {"$group": {
            "_id": "$status",
            "count": {"$sum": 1},
            "total_reward": {"$sum": "$reward_amount"}
        }}
    ]).to_list(10)
    
    # Count task completions
    task_completions = await db.task_completions.count_documents({"user_id": user_id})
    
    # Fetch recent notifications (user-specific or broadcast)
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
            "referral_code": current_user['referral_code']
        }),
        "recent_transactions": fix_mongo_ids(transactions),
        "referral_stats": fix_mongo_ids(referral_stats),
        "task_completions": task_completions,
        "notifications": fix_mongo_ids(notifications)
    }

---

## Payment Routes (STK Push for Deposits, B2C for Withdrawals)

@app.post("/api/payments/deposit")
async def initiate_deposit(deposit_data: DepositRequest, current_user: dict = Depends(get_current_user)):
    """
    Initiates an M-Pesa STK Push transaction for deposits.
    """
    # Validate phone number format (E.164: 2547XXXXXXXX)
    if not deposit_data.phone.startswith("254") or len(deposit_data.phone) != 12 or not deposit_data.phone[3:].isdigit():
        raise HTTPException(status_code=400, detail="Invalid phone number format. Must be 254xxxxxxxxxx (E.164).")
    
    if deposit_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Deposit amount must be greater than zero.")

    transaction_id = str(uuid.uuid4())
    
    # Store the transaction as pending initially, with fields to be updated by M-Pesa callback
    transaction_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "deposit",
        "amount": deposit_data.amount,
        "phone": deposit_data.phone,
        "status": "pending_mpesa_stk", # New status to indicate STK Push is initiated
        "method": "mpesa_stk_push",
        "created_at": datetime.utcnow(),
        "completed_at": None,
        "mpesa_receipt": None,
        "MerchantRequestID": None, # Will be filled by M-Pesa's initial response
        "CheckoutRequestID": None    # Will be filled by M-Pesa's initial response
    }
    await db.transactions.insert_one(transaction_doc)

    access_token = await get_mpesa_access_token()
    if not access_token:
        # If token acquisition fails, mark transaction as failed and return error
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "completed_at": datetime.utcnow(), "mpesa_response_error": "Failed to get M-Pesa access token"}}
        )
        raise HTTPException(status_code=500, detail="Failed to connect to M-Pesa. Please try again later.")

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = generate_stk_password(timestamp)

    stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "BusinessShortCode": MPESA_BUSINESS_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline", # Or "CustomerBuyGoodsOnline" if applicable
        "Amount": int(deposit_data.amount), # Amount must be an integer for M-Pesa STK Push
        "PartyA": deposit_data.phone, # Customer's phone number
        "PartyB": MPESA_BUSINESS_SHORTCODE, # Your Paybill/Till Number
        "PhoneNumber": deposit_data.phone, # Customer's phone number
        "CallBackURL": MPESA_CALLBACK_URL, # The URL M-Pesa sends the transaction result to
        "AccountReference": transaction_id, # Your internal unique identifier for the transaction
        "TransactionDesc": f"Deposit to EarnPlatform for User {current_user['user_id']}"
    }

    try:
        response = requests.post(stk_push_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        stk_response = response.json()

        # Update the transaction with M-Pesa's immediate response IDs
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

        if stk_response.get("ResponseCode") == "0": # STK Push initiated successfully
            return {
                "success": True,
                "message": "STK Push initiated successfully. Please check your phone for the M-Pesa prompt.",
                "transaction_id": transaction_id,
                "MerchantRequestID": stk_response.get("MerchantRequestID"),
                "CheckoutRequestID": stk_response.get("CheckoutRequestID")
            }
        else: # STK Push initiation failed (e.g., invalid phone number, insufficient funds)
            await db.transactions.update_one(
                {"transaction_id": transaction_id},
                {"$set": {"status": "failed_stk_init", "completed_at": datetime.utcnow()}}
            )
            raise HTTPException(status_code=400, detail=stk_response.get("ResponseDescription", "STK Push initiation failed. Please try again."))

    except requests.exceptions.RequestException as e:
        print(f"STK Push API call error: {e}")
        # Mark transaction as failed if the API call itself fails
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "completed_at": datetime.utcnow(), "mpesa_response_error": str(e)}}
        )
        raise HTTPException(status_code=500, detail=f"Failed to communicate with M-Pesa. Please check your network or try again later. Error: {e}")

@app.post("/api/payments/stk-callback")
async def mpesa_stk_callback(request: Request):
    """
    Handles the asynchronous M-Pesa STK Push callback from Safaricom.
    This endpoint receives the final status of the STK Push transaction.
    """
    callback_data = await request.json()
    print(f"M-Pesa STK Callback Received: {json.dumps(callback_data, indent=2)}")

    try:
        stk_callback_body = callback_data['Body']['stkCallback']
        result_code = stk_callback_body['ResultCode']
        checkout_request_id = stk_callback_body['CheckoutRequestID']
        merchant_request_id = stk_callback_body['MerchantRequestID']
        
        # Find the pending transaction using CheckoutRequestID
        transaction = await db.transactions.find_one({
            "CheckoutRequestID": checkout_request_id,
            "status": "pending_mpesa_stk"
        })

        if not transaction:
            print(f"Warning: Transaction not found for CheckoutRequestID: {checkout_request_id}. Maybe already processed or invalid.")
            # Still return 200 OK to M-Pesa even if we can't find our transaction
            return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)

        user = await db.users.find_one({"user_id": transaction['user_id']})
        if not user:
            print(f"Error: User not found for transaction {transaction['transaction_id']}. Cannot update balance/status.")
            return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)

        update_fields = {
            "completed_at": datetime.utcnow(),
            "mpesa_result_code": result_code,
            "mpesa_result_description": stk_callback_body.get('ResultDesc')
        }
        
        if result_code == 0: # Payment was successful
            callback_metadata = stk_callback_body.get('CallbackMetadata', {}).get('Item', [])
            
            mpesa_receipt_number = next((item['Value'] for item in callback_metadata if item['Name'] == 'MpesaReceiptNumber'), None)
            transaction_amount = next((item['Value'] for item in callback_metadata if item['Name'] == 'Amount'), transaction['amount'])
            phone_number_paid = next((item['Value'] for item in callback_metadata if item['Name'] == 'PhoneNumber'), transaction['phone'])

            update_fields.update({
                "status": "completed",
                "mpesa_receipt": mpesa_receipt_number,
                "amount_received": float(transaction_amount), # Ensure it's a float
                "phone_number_paid": phone_number_paid
            })
            
            # Update user's wallet balance
            new_balance = user['wallet_balance'] + float(transaction_amount)
            user_update_data = {"wallet_balance": new_balance}

            # Check for account activation if the deposit meets the activation amount
            if not user['is_activated'] and float(transaction_amount) >= user.get('activation_amount', ACTIVATION_AMOUNT):
                user_update_data['is_activated'] = True
                if user.get('referred_by'):
                    await process_referral_reward(user['user_id'], user['referred_by'])

            await db.users.update_one({"user_id": user['user_id']}, {"$set": user_update_data})

            # Create notification for the user
            await create_notification({
                "title": "Deposit Successful!",
                "message": f"Your deposit of KSH {float(transaction_amount):.2f} has been processed successfully. Your new balance is KSH {new_balance:.2f}.",
                "user_id": user['user_id']
            })
            print(f"STK Push Success: CheckoutRequestID={checkout_request_id}, Receipt={mpesa_receipt_number}, Amount={transaction_amount}")

        else: # Payment failed or was cancelled by user
            update_fields["status"] = "failed"
            print(f"STK Push Failed: CheckoutRequestID={checkout_request_id}, ResultCode={result_code}, ResultDesc={stk_callback_body.get('ResultDesc')}")
            
            # Create notification for the user about the failure
            await create_notification({
                "title": "Deposit Failed",
                "message": f"Your deposit of KSH {transaction['amount']} failed. Reason: {stk_callback_body.get('ResultDesc', 'Unknown error')}",
                "user_id": user['user_id']
            })

        # Finally, update the transaction document in the database
        await db.transactions.update_one(
            {"_id": transaction['_id']}, # Use _id for direct update for atomicity
            {"$set": update_fields}
        )

    except KeyError as e:
        print(f"Error parsing M-Pesa STK callback data: Missing key {e}. Full data: {json.dumps(callback_data, indent=2)}")
    except Exception as e:
        print(f"An unexpected error occurred processing STK callback: {e}. Full data: {json.dumps(callback_data, indent=2)}")

    # Always return a 200 OK JSON response to M-Pesa to acknowledge receipt of the callback.
    # This prevents M-Pesa from retrying the callback.
    return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B Request Processed"}, status_code=200)


async def send_mpesa_b2c(phone: str, amount: float, transaction_id: str, access_token: str, remarks: str = "Withdrawal"):
    """
    Sends a B2C (Business to Customer) payment request via M-Pesa.
    Requires an access_token.
    """
    if not access_token:
        print("Error: B2C access token is missing.")
        return {"error": "B2C access token is missing."}

    payload = {
        "InitiatorName": MPESA_INITIATOR,
        "SecurityCredential": generate_b2c_security_credential(MPESA_SECURITY_CREDENTIAL), # Uses the pre-generated credential
        "CommandID": "BusinessPayment", # Or "SalaryPayment", "PromotionPayment"
        "Amount": amount,
        "PartyA": MPESA_BUSINESS_SHORTCODE, # Your Paybill/Till number
        "PartyB": phone, # Customer's phone number
        "Remarks": remarks,
        "QueueTimeOutURL": MPESA_B2C_TIMEOUT_URL, # Callback for timeout
        "ResultURL": MPESA_B2C_RESULT_URL, # Callback for final result
        "Occassion": transaction_id # Your internal transaction ID
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(MPESA_B2C_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"B2C API error during request: {e}")
        return {"error": str(e)}

@app.post("/api/payments/withdraw")
async def request_withdrawal(withdrawal_data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    """
    Handles a user's withdrawal request, initiating an M-Pesa B2C transaction.
    """
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated before withdrawal.")
    
    if withdrawal_data.amount > current_user['wallet_balance']:
        raise HTTPException(status_code=400, detail="Insufficient balance for withdrawal.")
    
    if withdrawal_data.amount < 100: # Minimum withdrawal amount
        raise HTTPException(status_code=400, detail="Minimum withdrawal amount is KSH 100.")
    
    # Validate phone number format (E.164: 2547XXXXXXXX)
    if not withdrawal_data.phone.startswith("254") or len(withdrawal_data.phone) != 12 or not withdrawal_data.phone[3:].isdigit():
        raise HTTPException(status_code=400, detail="Invalid phone number format. Must be 254xxxxxxxxxx (E.164).")

    transaction_id = str(uuid.uuid4())
    withdrawal_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "withdrawal",
        "amount": withdrawal_data.amount,
        "phone": withdrawal_data.phone,
        "reason": withdrawal_data.reason,
        "status": "pending_b2c_init", # Initial status for B2C withdrawal
        "method": "mpesa_b2c",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "approved_by": None,
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
        # If token acquisition fails, refund user and mark transaction failed
        await db.users.update_one(
            {"user_id": current_user['user_id']},
            {"$inc": {"wallet_balance": withdrawal_data.amount}}
        )
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "processed_at": datetime.utcnow(), "error_message": "Failed to get B2C access token."}}
        )
        raise HTTPException(status_code=500, detail="Failed to process withdrawal: M-Pesa access token unavailable.")

    # Send the B2C request to M-Pesa
    b2c_response = await send_mpesa_b2c(withdrawal_data.phone, withdrawal_data.amount, transaction_id, b2c_access_token, withdrawal_data.reason)
    
    if b2c_response and not b2c_response.get("error"):
        # B2C request successfully sent to Safaricom. The actual payment status
        # will come via the b2c-callback.
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {
                "status": "pending_b2c_callback", # Awaiting callback for final status
                "b2c_conversation_id": b2c_response.get('ConversationID'),
                "b2c_originator_id": b2c_response.get('OriginatorConverstionID')
            }}
        )
        return {
            "success": True,
            "message": f"Withdrawal request of KSH {withdrawal_data.amount} submitted. You will receive your funds shortly.",
            "transaction_id": transaction_id,
            "b2c_response_details": b2c_response # Include for debugging if needed
        }
    else:
        # B2C request failed to be sent to Safaricom. Refund user and mark transaction failed.
        print(f"B2C initiation failed for transaction {transaction_id}: {b2c_response}")
        await db.users.update_one(
            {"user_id": current_user['user_id']},
            {"$inc": {"wallet_balance": withdrawal_data.amount}} # Refund
        )
        await db.transactions.update_one(
            {"transaction_id": transaction_id},
            {"$set": {"status": "failed", "processed_at": datetime.utcnow(), "error_message": b2c_response.get("error", "Unknown B2C initiation error")}}
        )
        raise HTTPException(status_code=500, detail="Failed to initiate withdrawal with M-Pesa. Please try again.")

@app.post("/api/payments/b2c-callback")
async def mpesa_b2c_callback(request: Request):
    """
    Handles the asynchronous M-Pesa B2C (withdrawal) callback from Safaricom.
    This endpoint receives the final status of the B2C transaction.
    """
    payload = await request.json()
    print(f"M-Pesa B2C Callback Received: {json.dumps(payload, indent=2)}")

    result = payload.get("Result", {})
    
    # Extract transaction_id from the ResultParameters (your 'Occassion' value)
    transaction_id = None
    if "ResultParameters" in result and "ResultParameter" in result["ResultParameters"]:
        for param in result["ResultParameters"]["ResultParameter"]:
            if param.get("Key") == "Occasion": # Note: M-Pesa might return "Occasion" not "Occassion"
                transaction_id = param.get("Value")
                break
    
    # Also try to extract from 'ReferenceData' if 'Occasion' is not directly in ResultParameters
    if not transaction_id and "ReferenceData" in result and "ReferenceItem" in result["ReferenceData"]:
        for item in result["ReferenceData"]["ReferenceItem"]:
            if item.get("Key") == "Occasion":
                transaction_id = item.get("Value")
                break

    if not transaction_id:
        print("Error: B2C callback received without identifiable transaction_id ('Occasion').")
        return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Callback Processed"}, status_code=200)

    result_code = int(result.get("ResultCode", 1)) # 0 = success, others are errors

    transaction = await db.transactions.find_one({"transaction_id": transaction_id, "type": "withdrawal"})
    if not transaction:
        print(f"Warning: Withdrawal transaction not found for transaction_id: {transaction_id}. Cannot process callback.")
        return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Callback Processed"}, status_code=200)

    user = await db.users.find_one({"user_id": transaction['user_id']})
    if not user:
        print(f"Error: User not found for withdrawal transaction {transaction['transaction_id']}. Cannot update user data.")
        return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Callback Processed"}, status_code=200)

    update_fields = {
        "processed_at": datetime.utcnow(),
        "mpesa_result_code": result_code,
        "mpesa_result_description": result.get("ResultDesc"),
        "mpesa_conversation_id": payload.get("ConversationID"), # Store the ConversationID from the callback
        "mpesa_originator_id": payload.get("OriginatorConversationID") # Store the OriginatorConversationID
    }

    if result_code == 0: # Withdrawal was successful
        update_fields["status"] = "completed"
        # Extract specific details like MpesaReceiptNumber if available and needed
        mpesa_receipt_number = next((item['Value'] for item in result.get("ResultParameters", {}).get("ResultParameter", []) if item['Key'] == 'MpesaReceiptNumber'), None)
        if mpesa_receipt_number:
            update_fields["mpesa_receipt"] = mpesa_receipt_number
        
        await db.transactions.update_one(
            {"_id": transaction['_id']},
            {"$set": update_fields}
        )
        await create_notification({
            "title": "Withdrawal Successful!",
            "message": f"Your withdrawal of KSH {transaction['amount']:.2f} has been processed.",
            "user_id": transaction['user_id']
        })
        print(f"B2C Withdrawal Success: Transaction ID={transaction_id}, Receipt={mpesa_receipt_number}")
    else: # Withdrawal failed
        update_fields["status"] = "failed"
        
        # Refund the user's wallet balance if the withdrawal failed
        current_wallet_balance_before_refund = user['wallet_balance'] # Get current balance before adding back
        await db.users.update_one(
            {"user_id": transaction['user_id']},
            {"$inc": {"wallet_balance": transaction['amount']}}
        )
        print(f"B2C Withdrawal Failed: Transaction ID={transaction_id}. Refunded KSH {transaction['amount']:.2f} to user {user['user_id']}. Old balance: {current_wallet_balance_before_refund}, New balance: {current_wallet_balance_before_refund + transaction['amount']}.")

        await db.transactions.update_one(
            {"_id": transaction['_id']},
            {"$set": update_fields}
        )
        await create_notification({
            "title": "Withdrawal Failed!",
            "message": f"Your withdrawal of KSH {transaction['amount']:.2f} could not be processed and has been refunded. Reason: {result.get('ResultDesc', 'Unknown error')}",
            "user_id": transaction['user_id']
        })
        print(f"B2C Withdrawal Failed: Transaction ID={transaction_id}, ResultCode={result_code}, ResultDesc={result.get('ResultDesc')}")
    
    # Always return 200 OK to M-Pesa to acknowledge receipt of the callback.
    return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Callback Processed"}, status_code=200)

# Optional: B2C Timeout URL (M-Pesa calls this if the transaction takes too long/times out)
@app.post("/api/payments/b2c-timeout")
async def mpesa_b2c_timeout(request: Request):
    payload = await request.json()
    print(f"M-Pesa B2C Timeout Callback Received: {json.dumps(payload, indent=2)}")
    # Here you would typically mark the transaction as 'timed_out' or 'failed'
    # and potentially refund the user if the initial deduction happened.
    # Logic similar to b2c-callback but specifically for timeouts.
    return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Timeout Processed"}, status_code=200)

---

## Task Management

@app.on_event("startup")
async def startup_event():
    """
    Populates initial task templates if the collection is empty.
    This runs once when the FastAPI application starts up.
    """
    template_count = await db.tasks_template.count_documents({})
    if template_count == 0:
        templates = [
            {
                "template_id": str(uuid.uuid4()),
                "title": "Complete Daily Survey",
                "description": "Answer 10 questions about consumer preferences",
                "reward": 25.0,
                "type": "survey",
                "requirements": {"questions": 10, "time_limit": 300, "file_upload": False},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "template_id": str(uuid.uuid4()),
                "title": "Watch Advertisement",
                "description": "Watch a 30-second advertisement completely",
                "reward": 5.0,
                "type": "ad",
                "requirements": {"duration": 30, "interaction": True, "file_upload": False},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "template_id": str(uuid.uuid4()),
                "title": "Write Online Article",
                "description": "Write a 300-word article and upload as DOC or PDF.",
                "reward": 50.0,
                "type": "writing",
                "requirements": {"min_words": 300, "file_upload": True},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "template_id": str(uuid.uuid4()),
                "title": "Share on Social Media",
                "description": "Share our platform on your social media",
                "reward": 15.0,
                "type": "social",
                "requirements": {"platforms": ["facebook", "twitter", "whatsapp"], "file_upload": False},
                "is_active": True,
                "created_at": datetime.utcnow()
            }
        ]
        await db.tasks_template.insert_many(templates)
        print("Task templates initialized in MongoDB.")

@app.get("/api/tasks/available")
async def get_available_tasks(current_user: dict = Depends(get_current_user)):
    """
    Retrieves tasks available for the current user to complete.
    Users must be activated and tasks not completed within the last 24 hours.
    """
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated to access tasks.")
    
    now = datetime.utcnow()
    # Find tasks completed by this user in the last 24 hours
    recent_completions = await db.task_completions.find({
        "user_id": current_user['user_id'],
        "created_at": {"$gte": now - timedelta(hours=24)}
    }).distinct("template_id") # Get unique template_ids completed

    # Find active tasks not in the recently completed list
    tasks = await db.tasks_template.find({
        "template_id": {"$nin": recent_completions},
        "is_active": True
    }).to_list(20) # Limit to 20 available tasks

    return {
        "success": True,
        "tasks": fix_mongo_ids(tasks)
    }

@app.post("/api/tasks/complete")
async def complete_task(
    request: Request,
    task_id: str = Form(...),
    completion_data: str = Form(None), # JSON string for survey answers, etc.
    file: UploadFile = File(None), # For tasks requiring file uploads
    current_user: dict = Depends(get_current_user)
):
    """
    Allows a user to complete a task and receive a reward.
    Handles file uploads for specific task types.
    """
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated to complete tasks.")
    
    task = await db.tasks_template.find_one({"template_id": task_id, "is_active": True})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or inactive.")
    
    now = datetime.utcnow()
    # Check if the user already completed this specific task today
    existing_completion = await db.task_completions.find_one({
        "user_id": current_user['user_id'],
        "template_id": task_id,
        "created_at": {"$gte": now - timedelta(hours=24)}
    })
    if existing_completion:
        raise HTTPException(status_code=400, detail="Task already completed today. Please try again tomorrow.")
    
    completion_doc = {
        "completion_id": str(uuid.uuid4()),
        "user_id": current_user['user_id'],
        "template_id": task_id,
        "completion_data": json.loads(completion_data) if completion_data else {},
        "reward_amount": task['reward'],
        "status": "completed", # Assuming auto-approval for now
        "created_at": datetime.utcnow()
    }
    
    # Handle file uploads if required by the task
    if task['requirements'].get('file_upload', False):
        if not file:
            raise HTTPException(status_code=400, detail="File upload required for this task.")
        
        file_ext = os.path.splitext(file.filename)[-1].lower()
        if file_ext not in [".doc", ".docx", ".pdf", ".jpg", ".jpeg", ".png"]: # Extended allowed file types
            raise HTTPException(status_code=400, detail="Invalid file type. Only DOC, DOCX, PDF, JPG, PNG allowed.")
        
        # Define upload directory and create if it doesn't exist
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save the file with a unique name
        file_id = str(uuid.uuid4())
        file_path = os.path.join(upload_dir, f"{file_id}{file_ext}")
        
        try:
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)
            completion_doc['file_path'] = file_path
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")

    await db.task_completions.insert_one(completion_doc)
    
    # Update user's wallet and earnings
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {
            "$inc": {
                "wallet_balance": task['reward'],
                "task_earnings": task['reward'],
                "total_earned": task['reward']
            }
        }
    )
    
    await create_notification({
        "title": "Task Completed!",
        "message": f"You earned KSH {task['reward']:.2f} for completing '{task['title']}'",
        "user_id": current_user['user_id']
    })
    
    return {
        "success": True,
        "message": f"Task completed! You earned KSH {task['reward']:.2f}.",
        "reward": task['reward'],
        "new_balance": current_user['wallet_balance'] + task['reward'] # Return updated balance for immediate client update
    }

---

## Referral System

@app.get("/api/referrals/stats")
async def get_referral_stats(current_user: dict = Depends(get_current_user)):
    """
    Retrieves statistics about a user's referrals.
    """
    referrals = await db.referrals.find({"referrer_id": current_user['user_id']}).to_list(100)
    
    # Calculate aggregated stats
    stats = {
        "total_referrals": len(referrals),
        "pending_referrals": len([r for r in referrals if r['status'] == 'pending']),
        "activated_referrals": len([r for r in referrals if r['status'] in ['activated', 'rewarded']]),
        "total_earnings": sum(r.get('reward_amount', 0) for r in referrals if r['status'] == 'rewarded'),
        "referral_code": current_user['referral_code'],
        "referrals": fix_mongo_ids(referrals) # Return detailed list of referrals
    }
    return {"success": True, "stats": stats}

async def process_referral_reward(referred_user_id: str, referrer_id: str):
    """
    Awards the referrer when a referred user activates their account.
    """
    referral = await db.referrals.find_one({
        "referred_id": referred_user_id,
        "referrer_id": referrer_id,
        "status": "pending"
    })
    
    if referral:
        reward_amount = referral['reward_amount']
        
        # Update referral status to 'rewarded'
        await db.referrals.update_one(
            {"referral_id": referral['referral_id']},
            {
                "$set": {
                    "status": "rewarded",
                    "activation_date": datetime.utcnow()
                }
            }
        )
        
        # Update referrer's wallet balance and earnings
        await db.users.update_one(
            {"user_id": referrer_id},
            {
                "$inc": {
                    "wallet_balance": reward_amount,
                    "referral_earnings": reward_amount,
                    "total_earned": reward_amount,
                    "referral_count": 1
                }
            }
        )
        
        await create_notification({
            "title": "Referral Bonus!",
            "message": f"You earned KSH {reward_amount:.2f} from a successful referral!",
            "user_id": referrer_id
        })
        print(f"Referral reward processed: User {referrer_id} earned KSH {reward_amount} from {referred_user_id}'s activation.")

---

## Notification System

async def create_notification(notification_data: dict):
    """
    Helper function to create a new notification in the database.
    Can be user-specific or a broadcast.
    """
    notification_doc = {
        "notification_id": str(uuid.uuid4()),
        "title": notification_data['title'],
        "message": notification_data['message'],
        "user_id": notification_data.get('user_id'), # Optional: if None, it's a broadcast
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    await db.notifications.insert_one(notification_doc)

@app.post("/api/notifications/create")
async def create_notification_endpoint(notification_data: NotificationCreate):
    """
    API endpoint to manually create a notification (e.g., by admin).
    """
    await create_notification(notification_data.dict())
    return {"success": True, "message": "Notification created."}

@app.get("/api/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    """
    Retrieves notifications relevant to the current user (user-specific or broadcasts).
    """
    notifications = await db.notifications.find(
        {"$or": [{"user_id": current_user['user_id']}, {"user_id": None}]}
    ).sort("created_at", -1).limit(20).to_list(20)
    return {"success": True, "notifications": fix_mongo_ids(notifications)}

@app.put("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    """
    Marks a specific notification as read for the user.
    """
    # Optional: Add a check to ensure current_user['user_id'] matches notification['user_id']
    # to prevent one user from marking another's notification as read.
    await db.notifications.update_one(
        {"notification_id": notification_id},
        {"$set": {"is_read": True}}
    )
    return {"success": True, "message": "Notification marked as read."}

---

## User Settings

@app.put("/api/settings/theme")
async def update_theme(theme: str, current_user: dict = Depends(get_current_user)):
    """
    Allows a user to update their preferred theme (light/dark).
    """
    if theme not in ['light', 'dark']:
        raise HTTPException(status_code=400, detail="Invalid theme. Must be 'light' or 'dark'.")
    
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$set": {"theme": theme}}
    )
    return {"success": True, "message": f"Theme updated to {theme}."}

---

## Main Entrypoint

if __name__ == "__main__":
    import uvicorn
    # Make sure your MongoDB is running and accessible
    # This will run the FastAPI app on 0.0.0.0:8001
    uvicorn.run(app, host="0.0.0.0", port=8001)
