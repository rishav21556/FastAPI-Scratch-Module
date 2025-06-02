from fastapi import FastAPI, APIRouter, Body, Depends
from typing import Annotated
from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from Auth import common
from .models import User
from Database.database import Base, load_db
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
from pydantic import BaseModel, Field

router = APIRouter()

class UserRegisteration(BaseModel):
    email: str
    first_name: str
    last_name: str
    password: str
    confirm_password: str
    is_admin: bool = Field(default=False)

class UserLogin(BaseModel):
    email: str
    password: str


@router.post("/auth/register")
async def register(reg_user: Annotated[UserRegisteration, Body()], db: AsyncSession = Depends(load_db)) -> JSONResponse:
    # check if the user already exists
    query = select(User).where(User.email==reg_user.email)
    res = await db.execute(query)
    existingUser = res.scalar_one_or_none()  # or scalar() depending on what you want
    if (existingUser):
        return JSONResponse(headers={"Content-Type":"application/json"}, content={"success": False, "message": "Email is already registered", "id": None}) 
    if (reg_user.confirm_password != reg_user.password):
        return JSONResponse(headers={"Content-Type":"application/json"}, content={"success": False, "message": "Passwords aren't same", "id": None}) 
    user = User(
        email=reg_user.email, 
        first_name=reg_user.first_name, 
        last_name=reg_user.last_name, 
        is_admin=reg_user.is_admin,
        password= await common._hash_pass(reg_user.password)
    )
    await user.save(db=db)
    return JSONResponse(headers={"Content-Type":"application/json"}, content={"success": True,"id": str(user.id),"message": "User registered successfully"})

@router.post("/auth/login")
async def login(reg_user: Annotated[UserLogin, Body()], db: AsyncSession = Depends(load_db)) -> JSONResponse: 
    # find the user with corresponding email address
    query = select(User).where(User.email == reg_user.email)
    response = await db.execute(query)
    user = response.scalar_one_or_none()
    if (not user):
        return JSONResponse({"success": False, "message": "No user found with given email", "jwt_token": None})
    hashed_password = await common._hash_pass(reg_user.password)
    if (hashed_password==user.password):
        # define the jwt header
        headers = {
            'alg':common.JWTSIGNALGO,
            'typ': "JWT"
        }
        # define the jwt payload
        content = {
            "iss": common.JWTISSUER,
            "aud": "admin" if user.is_admin else "user",
            "id": str(user.id),
            "exp":int((datetime.now() + timedelta(minutes=common.JWTEXPTIME)).timestamp())
        }
        header_bytes = json.dumps(headers, separators=(",", ":")).encode("utf-8")
        payload_bytes = json.dumps(content, separators=(",", ":")).encode("utf-8")
        header_b64 = await common._base64url_encode(header_bytes)
        payload_b64 = await common._base64url_encode(payload_bytes)
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = await common._base64url_encode(await common._hash_signature(message)) 
        jwt_token = f"{header_b64}.{payload_b64}.{signature}"
        return JSONResponse({"successs": True, "message":"Login Successful", "jwt_token": jwt_token})
    return JSONResponse({"success": False, "message": "Incorrect Password Detected", "jwt_token": None})

