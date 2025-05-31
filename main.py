from fastapi import FastAPI, APIRouter, Request
from fastapi.responses import JSONResponse
from Auth.router import router, verify_jwt

app = FastAPI()

@app.get("/")
async def root(req: Request):
    header = req.headers
    jwt_verification = await verify_jwt(header['Authorization'].split(" ")[1])
    if(not jwt_verification):
        return JSONResponse(status_code=401, content={'message':"User not authorized"})
    return {"message": "API is working"}

app.include_router(router=router)
