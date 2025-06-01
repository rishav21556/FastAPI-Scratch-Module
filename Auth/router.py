from fastapi import FastAPI, APIRouter, Body
from typing import Annotated
from Auth import common
from .models import User
import json
from datetime import datetime, timedelta, timezone

router = APIRouter()

@router.post("/auth/register")
async def register(reg_user: Annotated[User, Body()]):
    existingUser = await common._userExists(reg_user)
    if (existingUser['user']): return {"success": False, "message": "Username already exists."}
    reg_user.password = await common._hash_pass(reg_user.password)
    user = User(username=reg_user.username, password=reg_user.password, isAdmin=reg_user.isAdmin)
    await common._save(user)
    return {"success": True, "message": "User registered successfully"}

@router.post("/auth/login")
async def auth(reg_user: Annotated[User, Body()]):
    existingUser = await common._userExists(reg_user)
    if (not existingUser['user']): return {"success":False, "message": "No user exists with this username."}

    received_hash = await common._hash_pass(reg_user.password)
    if (received_hash == existingUser["user"].password):
        # define the jwt header
        headers = {
            'alg':'HS256',
            'typ': "JWT"
        }
        # define the jwt payload
        content = {
            "iss": common.JWTISSUER,
            "aud": "admin" if existingUser["user"].isAdmin else "user",
            "name": reg_user.username,
            "exp":int((datetime.now() + timedelta(minutes=common.JWTEXPTIME)).timestamp())
        }
        header_bytes = json.dumps(headers, separators=(",", ":")).encode("utf-8")
        payload_bytes = json.dumps(content, separators=(",", ":")).encode("utf-8")
        header_b64 = await common._base64url_encode(header_bytes)
        payload_b64 = await common._base64url_encode(payload_bytes)
        message = f"{header_b64}.{payload_b64}".encode("utf-8")
        signature = await common._base64url_encode(await common._hash_signature(message)) 
        jwt_token = f"{header_b64}.{payload_b64}.{signature}"
        return {"successs": True, "jwt_token": jwt_token}
    return {"success": False, "message": "Wrong Password"}

