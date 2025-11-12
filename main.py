import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

app = FastAPI(title="PayLink API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Helpers
# ----------------------

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, digest = hashed.split('$')
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()
        return hmac.compare_digest(digest, new_hash)
    except Exception:
        return False


def require_auth(authorization: Optional[str] = Header(None)) -> Dict:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(' ', 1)[1]
    session = db['session'].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    if session.get('expires_at') and session['expires_at'] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    user = db['user'].find_one({"_id": session['user_id']}) if isinstance(session.get('user_id'), dict) else db['user'].find_one({"_id": session.get('user_id')})
    # If stored as string id, resolve
    if not user:
        # try by string id
        user = db['user'].find_one({"_id": session.get('user_id')})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"user": user, "session": session}


# ----------------------
# Schemas
# ----------------------

class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class UpdateProfileBody(BaseModel):
    username: Optional[str] = None
    iban: Optional[str] = None
    two_fa_enabled: Optional[bool] = None


class PinBody(BaseModel):
    pin: str


class SendBody(BaseModel):
    to: str  # username like @alex or IBAN
    amount: float
    note: Optional[str] = None
    pin: Optional[str] = None


class RequestBody(BaseModel):
    from_user: Optional[str] = None  # username or IBAN
    amount: float
    note: Optional[str] = None


class QRGenerateBody(BaseModel):
    amount: float
    note: Optional[str] = None


# ----------------------
# Basic Routes
# ----------------------

@app.get("/")
def root():
    return {"name": "PayLink API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ----------------------
# Auth
# ----------------------

@app.post("/api/auth/register")
def register(body: RegisterBody):
    if db['user'].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": body.name,
        "email": body.email,
        "phone": body.phone,
        "username": None,
        "password_hash": hash_password(body.password),
        "two_fa_enabled": False,
        "two_fa_secret": None,
        "transaction_pin_hash": None,
        "iban": None,
        "balance": 0.0,
        "avatar_url": None,
        "created_at": datetime.now(timezone.utc),
    }
    user_id = db['user'].insert_one(user_doc).inserted_id

    token = secrets.token_urlsafe(32)
    session_doc = {
        "user_id": user_id,
        "token": token,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7)
    }
    db['session'].insert_one(session_doc)
    return {"token": token, "user": {"id": str(user_id), "email": body.email, "name": body.name}}


@app.post("/api/auth/login")
def login(body: LoginBody):
    user = db['user'].find_one({"email": body.email})
    if not user or not user.get('password_hash'):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_urlsafe(32)
    session_doc = {
        "user_id": user['_id'],
        "token": token,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7)
    }
    db['session'].insert_one(session_doc)
    return {"token": token, "user": {"id": str(user['_id']), "email": user['email'], "name": user['name'], "username": user.get('username'), "iban": user.get('iban')}}


# ----------------------
# Users
# ----------------------

@app.get("/api/users/me")
def get_me(auth=Depends(require_auth)):
    user = auth['user']
    user["id"] = str(user["_id"])  # type: ignore
    user.pop("_id", None)
    return user


@app.put("/api/users/me")
def update_me(body: UpdateProfileBody, auth=Depends(require_auth)):
    user = auth['user']
    updates = {}
    if body.username:
        if not body.username.startswith('@'):
            body.username = f"@{body.username}"
        if db['user'].find_one({"username": body.username, "_id": {"$ne": user['_id']}}):
            raise HTTPException(status_code=400, detail="Username already taken")
        updates['username'] = body.username
    if body.iban:
        updates['iban'] = body.iban
    if body.two_fa_enabled is not None:
        updates['two_fa_enabled'] = body.two_fa_enabled
    if not updates:
        return {"updated": False}
    db['user'].update_one({"_id": user['_id']}, {"$set": updates})
    return {"updated": True, "updates": updates}


@app.post("/api/users/me/pin")
def set_pin(body: PinBody, auth=Depends(require_auth)):
    if len(body.pin) < 4 or len(body.pin) > 6 or not body.pin.isdigit():
        raise HTTPException(status_code=400, detail="PIN must be 4-6 digits")
    pin_hash = hash_password(body.pin)
    db['user'].update_one({"_id": auth['user']['_id']}, {"$set": {"transaction_pin_hash": pin_hash}})
    return {"ok": True}


# ----------------------
# Transactions
# ----------------------

def find_user_by_identifier(identifier: str):
    if identifier.startswith('@'):
        return db['user'].find_one({"username": identifier})
    # IBAN lookup
    return db['user'].find_one({"iban": identifier})


@app.get("/api/transactions/feed")
def feed(limit: int = 25, auth=Depends(require_auth)):
    uid = auth['user']['_id']
    txs = list(db['transaction'].find({"$or": [{"sender_id": str(uid)}, {"receiver_id": str(uid)}]}).sort("created_at", -1).limit(limit))
    for t in txs:
        t['id'] = str(t.pop('_id'))
    return txs


@app.get("/api/balance")
def balance(auth=Depends(require_auth)):
    user = db['user'].find_one({"_id": auth['user']['_id']})
    return {"balance": round(float(user.get('balance', 0.0)), 2)}


@app.post("/api/transactions/send")
def send(body: SendBody, auth=Depends(require_auth)):
    sender = db['user'].find_one({"_id": auth['user']['_id']})
    if sender.get('transaction_pin_hash'):
        if not body.pin or not verify_password(body.pin, sender['transaction_pin_hash']):
            raise HTTPException(status_code=403, detail="Invalid PIN")
    if body.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")

    receiver = find_user_by_identifier(body.to)
    if not receiver:
        raise HTTPException(status_code=404, detail="Recipient not found")

    if float(sender.get('balance', 0.0)) < body.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # Update balances atomically-ish (simplified for demo)
    db['user'].update_one({"_id": sender['_id']}, {"$inc": {"balance": -body.amount}})
    db['user'].update_one({"_id": receiver['_id']}, {"$inc": {"balance": body.amount}})

    tx = {
        "sender_id": str(sender['_id']),
        "receiver_id": str(receiver['_id']),
        "amount": float(body.amount),
        "message": body.note,
        "status": "completed",
        "reference": None,
        "created_at": datetime.now(timezone.utc)
    }
    tx_id = db['transaction'].insert_one(tx).inserted_id

    # Notifications
    db['notification'].insert_one({
        "user_id": str(receiver['_id']),
        "title": "Payment received",
        "body": f"+€{body.amount:.2f} from {sender.get('username') or sender.get('email')}",
        "type": "payment_in",
        "created_at": datetime.now(timezone.utc)
    })
    db['notification'].insert_one({
        "user_id": str(sender['_id']),
        "title": "Payment sent",
        "body": f"-€{body.amount:.2f} to {receiver.get('username') or receiver.get('email')}",
        "type": "payment_out",
        "created_at": datetime.now(timezone.utc)
    })

    return {"ok": True, "transaction_id": str(tx_id)}


@app.post("/api/transactions/request")
def request_payment(body: RequestBody, auth=Depends(require_auth)):
    requester = auth['user']
    payload = {
        "type": "request",
        "from": body.from_user,
        "to": str(requester['_id']),
        "amount": body.amount,
        "note": body.note,
        "ts": int(datetime.now(timezone.utc).timestamp())
    }
    # Store as pending notification
    db['notification'].insert_one({
        "user_id": str(requester['_id']),
        "title": "Payment request created",
        "body": f"€{body.amount:.2f} request",
        "type": "request",
        "created_at": datetime.now(timezone.utc)
    })
    return {"qr_payload": payload}


@app.post("/api/qr/generate")
def generate_qr(body: QRGenerateBody, auth=Depends(require_auth)):
    user = auth['user']
    payload = {
        "type": "paylink",
        "to": user.get('username') or user.get('iban') or str(user['_id']),
        "amount": body.amount,
        "note": body.note,
        "currency": "EUR",
        "ts": int(datetime.now(timezone.utc).timestamp())
    }
    return {"payload": payload}


@app.get("/api/notifications")
def notifications(limit: int = 20, auth=Depends(require_auth)):
    items = list(db['notification'].find({"user_id": str(auth['user']['_id'])}).sort("created_at", -1).limit(limit))
    for n in items:
        n['id'] = str(n.pop('_id'))
    return items


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
