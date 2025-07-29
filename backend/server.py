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
import requests  # Needed for B2C withdrawals

# Environment variables (update these for production!)
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', '')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', '')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE', '')
MPESA_INITIATOR = os.environ.get('MPESA_INITIATOR', '')
MPESA_SECURITY_CREDENTIAL = os.environ.get('MPESA_SECURITY_CREDENTIAL', '')
MPESA_B2C_URL = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest"
MPESA_B2C_TOKEN = os.environ.get('MPESA_B2C_TOKEN', '')  # Must be refreshed automatically
ACTIVATION_AMOUNT = 500.0

app = FastAPI(title="EarnPlatform API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client.earnplatform

# Pydantic models ...
# ... (unchanged, same as before)

# Utility functions ...
# ... (unchanged)

# Dependency to get current user ...
# ... (unchanged)

# --- Deposit Initiation ---
@app.post("/api/payments/deposit")
async def initiate_deposit(deposit_data: DepositRequest, current_user: dict = Depends(get_current_user)):
    transaction_id = str(uuid.uuid4())
    transaction_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "deposit",
        "amount": deposit_data.amount,
        "phone": deposit_data.phone,
        "status": "pending",
        "method": "mpesa",
        "created_at": datetime.utcnow(),
        "completed_at": None,
        "mpesa_receipt": None
    }
    await db.transactions.insert_one(transaction_doc)
    return {
        "success": True,
        "message": f"Deposit of KSH {deposit_data.amount} initiated. Please complete payment on your phone.",
        "transaction_id": transaction_id,
        "amount": deposit_data.amount,
        "phone": deposit_data.phone
    }

# === REAL MPESA C2B CALLBACK FOR DEPOSIT/ACTIVATION ===
@app.post("/api/payments/mpesa-callback")
async def mpesa_callback(request: Request):
    """
    This is the real Safaricom C2B confirmation endpoint.
    """
    payload = await request.json()
    transaction_id = payload.get('TransID')
    amount = float(payload.get('TransAmount'))
    phone = payload.get('MSISDN')
    result_code = int(payload.get('ResultCode', 1))  # 0 = Success

    transaction = await db.transactions.find_one({"transaction_id": transaction_id, "status": "pending"})
    if not transaction or transaction['amount'] != amount or transaction['phone'] != phone:
        return {"success": False, "message": "Transaction not found or invalid details."}

    if result_code != 0:
        return {"success": False, "message": "Mpesa payment failed."}

    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {"$set": {"status": "completed", "completed_at": datetime.utcnow(), "mpesa_receipt": transaction_id}}
    )

    user = await db.users.find_one({"user_id": transaction['user_id']})
    update_data = {"wallet_balance": user['wallet_balance'] + amount}
    if not user['is_activated'] and amount >= user.get('activation_amount', ACTIVATION_AMOUNT):
        update_data['is_activated'] = True
        if user.get('referred_by'):
            await process_referral_reward(user['user_id'], user['referred_by'])
    await db.users.update_one({"user_id": user['user_id']}, {"$set": update_data})

    await create_notification({
        "title": "Deposit Successful!",
        "message": f"Your deposit of KSH {amount} has been processed successfully.",
        "user_id": user['user_id']
    })
    return {"success": True, "message": "Deposit processed and account activated if applicable."}


# === COMMENTED OUT: SIMULATED DEPOSIT SUCCESS ENDPOINT ===
# @app.post("/api/payments/simulate-deposit-success")
# async def simulate_deposit_success(transaction_id: str, current_user: dict = Depends(get_current_user)):
#     """Simulate successful M-Pesa deposit for testing (commented out for production)"""
#     transaction = await db.transactions.find_one({"transaction_id": transaction_id, "user_id": current_user['user_id']})
#     if not transaction:
#         raise HTTPException(status_code=404, detail="Transaction not found")
#     if transaction['status'] != 'pending':
#         raise HTTPException(status_code=400, detail="Transaction already processed")
#     # Update transaction
#     await db.transactions.update_one(
#         {"transaction_id": transaction_id},
#         {
#             "$set": {
#                 "status": "completed",
#                 "completed_at": datetime.utcnow(),
#                 "mpesa_receipt": f"MPESA{secrets.token_hex(4).upper()}"
#             }
#         }
#     )
#     # Update user wallet
#     new_balance = current_user['wallet_balance'] + transaction['amount']
#     update_data = {"wallet_balance": new_balance}
#     # Check if this activates the account
#     if not current_user['is_activated'] and transaction['amount'] >= current_user.get('activation_amount', 500.0):
#         update_data['is_activated'] = True
#         # Process referral reward if user was referred
#         if current_user.get('referred_by'):
#             await process_referral_reward(current_user['user_id'], current_user['referred_by'])
#     await db.users.update_one(
#         {"user_id": current_user['user_id']},
#         {"$set": update_data}
#     )
#     # Create notification
#     await create_notification({
#         "title": "Deposit Successful!",
#         "message": f"Your deposit of KSH {transaction['amount']} has been processed successfully.",
#         "user_id": current_user['user_id']
#     )
#     return {
#         "success": True,
#         "message": f"Deposit of KSH {transaction['amount']} completed successfully!",
#         "new_balance": new_balance,
#         "is_activated": update_data.get('is_activated', current_user['is_activated'])
#     }

# --- Withdrawal Request (AUTOMATIC B2C) ---
def send_mpesa_b2c(phone, amount, transaction_id, remarks="Withdrawal"):
    payload = {
        "InitiatorName": MPESA_INITIATOR,
        "SecurityCredential": MPESA_SECURITY_CREDENTIAL,
        "CommandID": "BusinessPayment",
        "Amount": amount,
        "PartyA": MPESA_BUSINESS_SHORTCODE,
        "PartyB": phone,
        "Remarks": remarks,
        "QueueTimeOutURL": "https://yourdomain.com/api/payments/b2c-timeout",
        "ResultURL": "https://yourdomain.com/api/payments/b2c-callback",
        "Occassion": transaction_id
    }
    headers = {
        "Authorization": f"Bearer {MPESA_B2C_TOKEN}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(MPESA_B2C_URL, json=payload, headers=headers, timeout=30)
        return response.json()
    except Exception as e:
        print("B2C API error:", e)
        return {"error": str(e)}

@app.post("/api/payments/withdraw")
async def request_withdrawal(withdrawal_data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated before withdrawal")
    if withdrawal_data.amount > current_user['wallet_balance']:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    if withdrawal_data.amount < 100:
        raise HTTPException(status_code=400, detail="Minimum withdrawal amount is KSH 100")
    transaction_id = str(uuid.uuid4())
    withdrawal_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "withdrawal",
        "amount": withdrawal_data.amount,
        "phone": withdrawal_data.phone,
        "reason": withdrawal_data.reason,
        "status": "pending",
        "method": "mpesa",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "approved_by": None
    }
    await db.transactions.insert_one(withdrawal_doc)
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$inc": {"wallet_balance": -withdrawal_data.amount}}
    )
    send_mpesa_b2c(withdrawal_data.phone, withdrawal_data.amount, transaction_id)
    return {
        "success": True,
        "message": f"Withdrawal request of KSH {withdrawal_data.amount} submitted. You will receive your funds shortly.",
        "transaction_id": transaction_id
    }

# --- Safaricom B2C Result Callback ---
@app.post("/api/payments/b2c-callback")
async def mpesa_b2c_callback(request: Request):
    payload = await request.json()
    result = payload.get("Result", {})
    transaction_id = None
    amount = None
    for param in result.get("ResultParameters", {}).get("ResultParameter", []):
        if param.get("Key") == "Occassion":
            transaction_id = param.get("Value")
        elif param.get("Key") == "Amount":
            amount = float(param.get("Value"))
    result_code = int(result.get("ResultCode", 1))  # 0 = success

    transaction = await db.transactions.find_one({"transaction_id": transaction_id, "type": "withdrawal"})
    if not transaction:
        return {"success": False, "message": "Withdrawal transaction not found."}

    user = await db.users.find_one({"user_id": transaction['user_id']})

    if result_code == 0:
        await db.transactions.update_one(
            {"transaction_id": transaction_id, "type": "withdrawal"},
            {"$set": {"status": "completed", "processed_at": datetime.utcnow()}}
        )
        await create_notification({
            "title": "Withdrawal Successful!",
            "message": f"Your withdrawal of KSH {amount} has been processed.",
            "user_id": transaction['user_id']
        })
    else:
        await db.transactions.update_one(
            {"transaction_id": transaction_id, "type": "withdrawal"},
            {"$set": {"status": "failed", "processed_at": datetime.utcnow()}}
        )
        await db.users.update_one(
            {"user_id": transaction['user_id']},
            {"$inc": {"wallet_balance": transaction['amount']}}
        )
        await create_notification({
            "title": "Withdrawal Failed!",
            "message": "Your withdrawal could not be processed and has been refunded.",
            "user_id": transaction['user_id']
        })
    return {"success": True}

# --- Referral bonus helper ---
async def process_referral_reward(referred_user_id: str, referrer_id: str):
    referral = await db.referrals.find_one({
        "referred_id": referred_user_id,
        "referrer_id": referrer_id,
        "status": "pending"
    })
    if referral:
        reward_amount = referral['reward_amount']
        await db.referrals.update_one(
            {"referral_id": referral['referral_id']},
            {"$set": {"status": "rewarded", "activation_date": datetime.utcnow()}}
        )
        await db.users.update_one(
            {"user_id": referrer_id},
            {"$inc": {
                "wallet_balance": reward_amount,
                "referral_earnings": reward_amount,
                "total_earned": reward_amount,
                "referral_count": 1
            }}
        )
        await create_notification({
            "title": "Referral Bonus!",
            "message": f"You earned KSH {reward_amount} from a successful referral!",
            "user_id": referrer_id
        })

# --- Notification helper ---
async def create_notification(notification_data: dict):
    notification_doc = {
        "notification_id": str(uuid.uuid4()),
        "title": notification_data['title'],
        "message": notification_data['message'],
        "user_id": notification_data.get('user_id'),  # None for broadcast
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    await db.notifications.insert_one(notification_doc)

# --- Other unchanged endpoints below (tasks, dashboard, etc) ---
# ... (keep your other code here)

#if __name__ == "__main__":
#    import uvicorn
#    uvicorn.run(app, host="0.0.0.0", port=8001)

