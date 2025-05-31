from fastapi import FastAPI, APIRouter, Body, logger
from fastapi.responses import JSONResponse
from typing import Annotated
from .models import User
from sqlmodel import create_engine, Session, select
import os
from dotenv import load_dotenv
from pathlib import Path
import hashlib
import base64
import hmac
import json
from datetime import datetime, timedelta, timezone

status = load_dotenv(dotenv_path=Path('.env'))

DBUSER = os.getenv('DBUSER')
DBPASSWORD= os.getenv('DBPASSWORD')
DBNAME= os.getenv('DBNAME')
PASSWORDKEY=os.getenv('PASSWORDKEY')

DBURL =  f"postgresql+psycopg2://{DBUSER}:{DBPASSWORD}@localhost:5432/{DBNAME}"

router = APIRouter()

ENGINE = create_engine(DBURL, echo=True)

User.metadata.create_all(ENGINE)

async def _userExists(reg_user: User):
    with Session(ENGINE) as session:
        statement = select(User).where(User.username == reg_user.username)
        user = session.exec(statement=statement).first()
        return {"user": user}
    
async def _hash_pass(password: str) -> str:
    return hashlib.sha3_256(password.encode("utf-8")).hexdigest()

async def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

async def _base64url_decode(input_str: str) -> bytes:
    padding = '=' * (-len(input_str) % 4)  # Add padding if needed
    return base64.urlsafe_b64decode(input_str + padding)

async def verify_jwt(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise ValueError("Invalid token format")

    # Recompute signature
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_signature = hmac.new(PASSWORDKEY.encode("utf-8"), message, hashlib.sha256).digest()
    expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).rstrip(b"=").decode("utf-8")

    payload_json = json.loads((await _base64url_decode(payload_b64)).decode('utf-8'))


    if not hmac.compare_digest(expected_signature_b64, signature_b64) or datetime.now(timezone.utc) > datetime.fromtimestamp(payload_json['exp'], tz=timezone.utc) :
        return False

    return True




@router.post("/auth/register")
async def register(reg_user: Annotated[User, Body()]):
    existingUser = await _userExists(reg_user)
    if (existingUser['user']): return {"success": False, "message": "Username already exists."}
    reg_user.password = await _hash_pass(reg_user.password)
    user = User(username=reg_user.username, password=reg_user.password, isAdmin=reg_user.isAdmin)
    with Session(ENGINE) as session:
        session.add(user)
        session.commit()
    return {"success": True, "message": "User registered successfully"}

@router.post("/auth/login")
async def auth(reg_user: Annotated[User, Body()]):
    existingUser = await _userExists(reg_user)
    if (not existingUser['user']): return {"success":False, "message": "No user exists with this username."}

    received_hash = await _hash_pass(reg_user.password)
    if (received_hash == existingUser["user"].password):
        headers = {
            'alg':'hs256',
            'typ': "JWT"
        }
        content = {
            "sub": "jwtauth", 
            "name": reg_user.username, 
            "admin": False, 
            "exp":int((datetime.now() + timedelta(minutes=5)).timestamp())
        }
        header_bytes = json.dumps(headers, separators=(",", ":")).encode("utf-8")
        payload_bytes = json.dumps(content, separators=(",", ":")).encode("utf-8")
        header_b64 = await _base64url_encode(header_bytes)
        payload_b64 = await _base64url_encode(payload_bytes)
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = await _base64url_encode(hmac.new(PASSWORDKEY.encode("utf-8"), message, hashlib.sha256).digest()) 
        jwt_token = f"{header_b64}.{payload_b64}.{signature}"
        return {"successs": True, "jwt_token": jwt_token}
    return {"success": False, "message": "Wrong Password"}

