from typing import Literal
from datetime import datetime, timezone

Decision = Literal["allow", "challenge", "deny"]

now = datetime.now(timezone.utc)  # Added by Group D: used for evaluate BUSINESS_HOURS Rule
hour = now.hour                   # Added by Group D: used for evaluate BUSINESS_HOURS Rule

SENSITIVE_PATHS = {"/export"}  # students can extend
BUSINESS_HOURS = range(7, 20)  # 07:00–19:59

def evaluate_request_context(claims: dict, path: str, method: str) -> Decision:
    # Minimal baseline: if sensitive endpoint and non-admin -> challenge
    role = claims.get("role")
    clearance_level = claims.get("clearance_level")  # Added by Group D: used for evaluate access to SENSITIVE_PATHS
    if path in SENSITIVE_PATHS and role != "administrator" and clearance_level == "Restricted": #Updated by Group D: Role name is administrator and clearance_level must be "Restricted" (Task 1; Sensitive endpoints with stricter checks)
        return "challenge"  # later: simulate MFA required
    
    # Added by Group D: Admins may be allowed outside normal business hours, as they sometimes work at night (Task 1; Time-based access)
    if hour not in BUSINESS_HOURS:
        if role == "administrator":
            return "allow"
        else:
            return "deny"
    
    # Added by Group D: Device check unknown or missing DeviceID -> deny (Taks 1; Device-based rules)
    if not claims.get("device_id"):
        return "deny"
    
    return "allow"
