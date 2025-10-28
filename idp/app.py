from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from jose import jwt
import os

APP = FastAPI(title="IdP")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

USERS = {
    "analyst" : {"password": "analyst", "role": "analyst", "clearance_level": "Internal"},              # Updated  by Group D: Added clearance_level for dynamic risk profile
    "contractor" : {"password": "contractor", "role": "contractor", "clearance_level": "Internal"},     # Updated  by Group D: Added clearance_level for dynamic risk profile
    "IT-Operator" : {"password": "admin", "role": "administrator", "clearance_level": "Confidential"},  # Added by Group D: Added Admin User to evaluate risk profiles
    "root" : {"password": "root", "role": "administrator", "clearance_level": "Restricted"}             # Added by Group D: Added Root User to evaluate risk profiles
}

class LoginIn(BaseModel):
    username: str
    password: str
    device_id: str | None = None

@APP.post("/login")
def login(inp: LoginIn):
    u = USERS.get(inp.username)
    if not u or u["password"] != inp.password:
        raise HTTPException(status_code=401, detail="invalid credentials")
    now = datetime.now(timezone.utc)
    claims = {
        "sub": inp.username,
        "role": u["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
        "typ": "access",
        "iss": "http://localhost:8001",         # Added by Group D New Claim: Issuer, identifies the IdP that issued the token. (to fulfill RFC 7519)
        "aud": "resource-api",                  # Added by Group D New Claim: Audience, Ressource Service (to fulfill RFC 7519).
        "nbf": int(now.timestamp()),            # Added by Group D New Claim: Not Before, token is invalid before this time. (to fulfill RFC 7519).    
        "jti": "uid-321",                       # Added by Group D New Claim: JWT ID, unique token identifier for replay protection. (to fulfill RFC 7519). 
        "organization": "bfh",                  # Added by Group D New Claim: Organization name
        "clearance_level": u["clearance_level"] # Added by Group D New Claim: Access clearance / classification
    }
    print("Secret: " + JWT_SECRET)
    print("Alg: " + JWT_ALG)
    if inp.device_id:
        claims["device_id"] = inp.device_id
    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type": "bearer"}
