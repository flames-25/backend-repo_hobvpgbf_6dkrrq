"""
Database Schemas for PayLink

Each Pydantic model represents a MongoDB collection. Collection name will be the lowercase of the class name.

Collections:
- User
- Transaction
- Card
- Session
- Notification
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import datetime


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    phone: Optional[str] = Field(None, description="E.164 phone number")
    username: Optional[str] = Field(None, description="Unique public handle like @alex")
    password_hash: Optional[str] = Field(None, description="Password hash")
    two_fa_enabled: bool = Field(False, description="Whether 2FA is enabled")
    two_fa_secret: Optional[str] = Field(None, description="Secret seed for 2FA (TOTP)")
    transaction_pin_hash: Optional[str] = Field(None, description="Hash of 4-6 digit PIN")
    iban: Optional[str] = Field(None, description="Linked IBAN")
    balance: float = Field(0.0, ge=0, description="EUR balance")
    avatar_url: Optional[str] = Field(None, description="Profile photo URL")
    created_at: Optional[datetime] = None


class Transaction(BaseModel):
    sender_id: Optional[str] = Field(None, description="Mongo _id of sender")
    receiver_id: Optional[str] = Field(None, description="Mongo _id of receiver")
    amount: float = Field(..., gt=0, description="Amount in EUR")
    message: Optional[str] = Field(None, max_length=140)
    status: Literal['pending', 'completed', 'failed', 'cancelled'] = 'completed'
    reference: Optional[str] = Field(None, description="Optional reference / QR payload")
    created_at: Optional[datetime] = None


class Card(BaseModel):
    user_id: str = Field(..., description="Owner user _id")
    card_number: str = Field(..., description="Masked PAN, e.g., **** **** **** 1234")
    expiry: str = Field(..., description="MM/YY")
    type: Literal['visa', 'mastercard', 'amex', 'other'] = 'visa'
    created_at: Optional[datetime] = None


class Session(BaseModel):
    user_id: str = Field(...)
    token: str = Field(...)
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class Notification(BaseModel):
    user_id: str
    title: str
    body: str
    type: Literal['payment_in', 'payment_out', 'request', 'system'] = 'system'
    created_at: Optional[datetime] = None
