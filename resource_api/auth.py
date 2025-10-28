from fastapi import Depends, HTTPException, Header
from jose import jwt, JWTError
import os

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

def get_claims(authorization: str = Header(..., alias="Authorization")):
    print("Secret: " + JWT_SECRET)
    print("Alg: " + JWT_ALG)
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1]
    print("Token: " + token)
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], audience="resource-api") # Updated by Group D: Added audience claim
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"token invalid: {e}")
    return claims
