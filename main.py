from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse
from Auth.router import router
from Auth.common import verify_jwt

app = FastAPI()

@app.middleware('http')
async def checkAuthorization(req: Request, callnext):
    # Example: JWT check on all routes except login/register
    if req.url.path not in ["/auth/login", "/auth/register"]:
        auth_header = req.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        token = auth_header.split(" ")[1]
        is_valid = await verify_jwt(token)
        if not is_valid:
            return JSONResponse(status_code=401, content={"detail": "Invalid token"})
    response = await callnext(req)
    return response


@app.get("/")
async def root():
    return {"message": "API is working"}

app.include_router(router=router)
