from fastapi import FastAPI, HTTPException, Response, Request, Depends, status
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.hash import bcrypt
from typing import Optional, Dict
import secrets, time, os, logging
from dotenv import load_dotenv

# ============================================================================
# CONFIGURATION
# ============================================================================

load_dotenv()

APP = FastAPI(
    title="Local Service - Decentralised Authentication",
    description="Standalone authentication service independent from central IdP"
)

LOCAL_SECRET = os.getenv("LOCAL_SECRET", secrets.token_urlsafe(32))
LOCAL_ALG = os.getenv("LOCAL_ALG", "HS256")
ACCESS_MIN = int(os.getenv("ACCESS_MIN", "15"))
SESSION_MIN = int(os.getenv("SESSION_MIN", "30"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ============================================================================
# DATA STORES (in-memory for demo)
# ============================================================================

LOCAL_USERS: Dict[str, dict] = {
    "local_admin": {
        "password_hash": bcrypt.hash("admin123"),
        "role": "local_admin",
        "permissions": ["read", "write", "delete", "admin"],
        "mfa_enabled": True,
    },
    "local_user": {
        "password_hash": bcrypt.hash("user123"),
        "role": "local_user",
        "permissions": ["read", "write"],
        "mfa_enabled": False,
    },
    "local_viewer": {
        "password_hash": bcrypt.hash("viewer123"),
        "role": "viewer",
        "permissions": ["read"],
        "mfa_enabled": False,
    }
}

REGISTERED_DEVICES = {
    "local-device-001": {"owner": "local_admin", "trusted": True, "type": "workstation"},
    "local-device-002": {"owner": "local_user", "trusted": True, "type": "laptop"},
    "local-device-003": {"owner": "local_viewer", "trusted": False, "type": "mobile"},
}

SESSIONS: Dict[str, dict] = {}
LOGIN_ATTEMPTS: Dict[str, tuple] = {}
MFA_TOKENS: Dict[str, str] = {}

# ============================================================================
# MODELS
# ============================================================================

class LocalLoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    device_id: Optional[str] = None
    remember_me: Optional[bool] = False

class LocalTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    session_id: str
    trust_score: int
    requires_mfa: bool = False

class MfaVerifyRequest(BaseModel):
    username: str
    code: str

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.verify(plain, hashed)

def check_rate_limit(username: str) -> None:
    now = time.time()
    if username in LOGIN_ATTEMPTS:
        attempts, last = LOGIN_ATTEMPTS[username]
        if now - last > 300:
            LOGIN_ATTEMPTS[username] = (0, now)
            return
        if attempts >= 3:
            raise HTTPException(status_code=429, detail="Too many attempts, try again later.")

def calculate_trust_score(username: str, device_id: Optional[str]) -> int:
    score = 50
    device = REGISTERED_DEVICES.get(device_id)
    if device:
        if device["owner"] == username and device["trusted"]:
            score += 40
        elif device["trusted"]:
            score += 20
        else:
            score -= 10
    else:
        score -= 20
    hour = datetime.now(timezone.utc).hour
    score += 10 if 7 <= hour <= 19 else -10
    if LOCAL_USERS[username]["role"] == "local_admin":
        score += 10
    return max(0, min(score, 100))

def create_local_token(username: str, device_id: Optional[str], extended: bool = False):
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=SESSION_MIN if extended else ACCESS_MIN)
    session_id = secrets.token_urlsafe(24)
    trust_score = calculate_trust_score(username, device_id)

    claims = {
        "sub": username,
        "role": LOCAL_USERS[username]["role"],
        "permissions": LOCAL_USERS[username]["permissions"],
        "trust_score": trust_score,
        "device_id": device_id,
        "session_id": session_id,
        "iss": "local-service",
        "aud": "local-resources",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp())
    }

    SESSIONS[session_id] = {
        "username": username,
        "created": now.isoformat(),
        "expires": exp.isoformat(),
        "trust_score": trust_score,
        "device_id": device_id,
        "active": True,
        "mfa_verified": not LOCAL_USERS[username]["mfa_enabled"]
    }

    token = jwt.encode(claims, LOCAL_SECRET, algorithm=LOCAL_ALG)
    return token, session_id, trust_score, int((exp - now).total_seconds())

def verify_local_token(token: str) -> dict:
    try:
        claims = jwt.decode(
            token,
            LOCAL_SECRET,
            algorithms=[LOCAL_ALG],
            audience="local-resources",
            issuer="local-service"
        )
        session = SESSIONS.get(claims.get("session_id"))
        if not session or not session["active"]:
            raise HTTPException(status_code=401, detail="Session expired or invalidated.")
        session["last_activity"] = datetime.now(timezone.utc).isoformat()
        return claims
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

# ============================================================================
# DECORATORS
# ============================================================================

from fastapi import Request, Depends, HTTPException

def _extract_token(request: Request) -> str:
    """Token aus Cookie oder Authorization-Header extrahieren"""
    token = request.cookies.get("local_session")
    if token:
        return token
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header.split(" ", 1)[1]
    raise HTTPException(status_code=401, detail="Missing token")

def token_dep(request: Request):
    """Hilfsfunktion als Dependency für Tokenprüfung"""
    return verify_local_token(_extract_token(request))

def require_perm(perm: str):
    """Decorator zur Prüfung von Berechtigungen"""
    def checker(claims=Depends(token_dep)):
        if perm not in claims.get("permissions", []):
            raise HTTPException(status_code=403, detail=f"Permission '{perm}' required.")
        return claims
    return checker

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@APP.post("/local-login", response_model=LocalTokenResponse)
async def local_login(req: LocalLoginRequest, response: Response):
    check_rate_limit(req.username)
    user = LOCAL_USERS.get(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        LOGIN_ATTEMPTS[req.username] = (LOGIN_ATTEMPTS.get(req.username, (0, time.time()))[0] + 1, time.time())
        raise HTTPException(status_code=401, detail="Invalid username or password")
    LOGIN_ATTEMPTS.pop(req.username, None)

    token, sid, score, exp_sec = create_local_token(req.username, req.device_id, req.remember_me)

    response.set_cookie(
        key="local_session",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=exp_sec
    )

    # MFA Step (if enabled)
    if user["mfa_enabled"]:
        mfa_code = str(secrets.randbelow(1000000)).zfill(6)
        MFA_TOKENS[req.username] = mfa_code
        logging.info(f"[MFA] Code for {req.username}: {mfa_code} (demo only!)")

    return LocalTokenResponse(
        access_token=token,
        expires_in=exp_sec,
        session_id=sid,
        trust_score=score,
        requires_mfa=user["mfa_enabled"]
    )

@APP.post("/mfa/verify")
async def mfa_verify(req: MfaVerifyRequest):
    expected = MFA_TOKENS.get(req.username)
    if not expected or expected != req.code:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA code.")
    for sid, sdata in SESSIONS.items():
        if sdata["username"] == req.username:
            sdata["mfa_verified"] = True
    MFA_TOKENS.pop(req.username, None)
    return {"status": "MFA verified", "username": req.username}

@APP.post("/local-logout")
async def local_logout(request: Request, response: Response):
    token = _extract_token(request)
    try:
        claims = jwt.decode(token, LOCAL_SECRET, algorithms=[LOCAL_ALG], audience="local-resources", issuer="local-service")
        sid = claims.get("session_id")
        if sid in SESSIONS:
            SESSIONS[sid]["active"] = False
    except:
        pass
    response.delete_cookie("local_session")
    return {"status": "success", "message": "Logged out"}

# ============================================================================
# PROTECTED ENDPOINTS
# ============================================================================

def get_current_user(request: Request) -> dict:
    token = _extract_token(request)
    return verify_local_token(token)

@APP.get("/local-resource")
async def local_resource(claims: dict = Depends(get_current_user)):
    session = SESSIONS[claims["session_id"]]
    if not session["mfa_verified"]:
        raise HTTPException(status_code=403, detail="MFA required before accessing resources")
    score = claims["trust_score"]
    if score < 30:
        raise HTTPException(status_code=403, detail="Trust score too low")
    access = "full_access" if score >= 70 else "limited_access"
    return {"status": access, "user": claims["sub"], "role": claims["role"], "trust_score": score}

@APP.get("/local-admin")
async def local_admin_resource(claims: dict = Depends(require_perm("admin"))):
    score = claims["trust_score"]
    if score < 90:
        raise HTTPException(status_code=403, detail="Insufficient trust score for admin")
    return {
        "status": "admin_access_granted",
        "users": len(LOCAL_USERS),
        "active_sessions": len([s for s in SESSIONS.values() if s["active"]]),
        "registered_devices": len(REGISTERED_DEVICES)
    }

# ============================================================================
# INFO ENDPOINT
# ============================================================================

@APP.get("/")
async def root():
    return {
        "service": "Local Authentication Service",
        "description": "Decentralised authentication independent from central IdP",
        "features": [
            "Local user management",
            "Session-based JWT authentication",
            "Trust scoring system",
            "Device registration",
            "Rate limiting",
            "MFA verification",
            "Context-aware access control"
        ]
    }
