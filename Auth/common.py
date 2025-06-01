
from fastapi import FastAPI, APIRouter, Body
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

status = load_dotenv(dotenv_path=Path('.env')) # laod the env file

# load db configurations
DBUSER = os.getenv('DBUSER')
DBPASSWORD= os.getenv('DBPASSWORD')
DBNAME= os.getenv('DBNAME')
PASSWORDKEY=os.getenv('PASSWORDKEY')

# load jwt configuration
JWTEXPTIME=int(os.getenv('JWTEXPTIME')) # stored in minutes
JWTISSUER=os.getenv('JWTISSUER') # it is the part of the jwt payload
JWTSIGNALGO=os.getenv('JWTSIGNALGO') # alogirthm for signing the jwt token

DBURL =  f"postgresql+psycopg2://{DBUSER}:{DBPASSWORD}@localhost:5432/{DBNAME}"

ENGINE = create_engine(DBURL, echo=True)

User.metadata.create_all(ENGINE)

async def _userExists(reg_user: User):
    with Session(ENGINE) as session:
        statement = select(User).where(User.username == reg_user.username)
        user = session.exec(statement=statement).first()
        return {"user": user}
    
async def _hash_pass(password: str) -> str:
    return hashlib.sha3_256(password.encode("utf-8")).hexdigest()

async def _hash_signature(message: str) -> str:
    if (JWTSIGNALGO == "HS256"):
        return hmac.new(PASSWORDKEY.encode("utf-8"), message, hashlib.sha256).digest()
    raise("Provided signature hashing algorithm doesn't exists.")

async def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

async def _base64url_decode(input_str: str) -> bytes:
    padding = '=' * (-len(input_str) % 4)  # Add padding if needed
    return base64.urlsafe_b64decode(input_str + padding)

async def _signature_to_json(base64str: str)->json:
    return json.loads((await _base64url_decode(base64str)).decode('utf-8'))

async def verify_jwt(token: str) -> bool:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise ValueError("Invalid token format")
    # Recompute signature
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    expected_signature = hmac.new(PASSWORDKEY.encode("utf-8"), message, hashlib.sha256).digest()
    expected_signature_b64 = base64.urlsafe_b64encode(expected_signature).rstrip(b"=").decode("utf-8")
    payload_json = await _signature_to_json(payload_b64)
    if not hmac.compare_digest(expected_signature_b64, signature_b64) or datetime.now(timezone.utc) > datetime.fromtimestamp(payload_json['exp'], tz=timezone.utc) :
        return False
    return True

async def _save(user: User) -> None:
    with Session(ENGINE) as session:
        session.add(user)
        session.commit()
