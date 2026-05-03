"""
otp_auth.py  -  2FA / OTP Login System
Generates time-based 6-digit OTP codes (TOTP) — no external libs needed
"""
import hmac, hashlib, struct, time, secrets, base64, json, os
from datetime import datetime

OTP_FILE  = "otp_config.json"
OTP_STEP  = 30   # seconds per code
OTP_DIGITS = 6

def _hotp(secret_bytes: bytes, counter: int) -> int:
    msg = struct.pack(">Q", counter)
    h   = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return code % (10 ** OTP_DIGITS)

def generate_totp(secret_b32: str) -> tuple:
    """Returns (code_str, seconds_remaining)."""
    try:
        secret_bytes = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
        counter = int(time.time()) // OTP_STEP
        code    = _hotp(secret_bytes, counter)
        remaining = OTP_STEP - (int(time.time()) % OTP_STEP)
        return f"{code:06d}", remaining
    except Exception as e:
        return "000000", 0

def verify_totp(secret_b32: str, user_code: str, window: int = 1) -> bool:
    """Verify code — checks current + adjacent windows for clock drift."""
    try:
        secret_bytes = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
        counter = int(time.time()) // OTP_STEP
        for i in range(-window, window + 1):
            if _hotp(secret_bytes, counter + i) == int(user_code):
                return True
        return False
    except Exception:
        return False

def generate_secret() -> str:
    """Generate a new random Base32 secret key."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode().rstrip("=")

def save_otp_config(username: str, secret: str, enabled: bool = True):
    config = {}
    if os.path.exists(OTP_FILE):
        try:
            with open(OTP_FILE) as f: config = json.load(f)
        except Exception: pass
    config[username] = {"secret": secret, "enabled": enabled,
                        "created": datetime.now().isoformat()}
    with open(OTP_FILE, "w") as f:
        json.dump(config, f, indent=2)

def load_otp_config(username: str) -> dict:
    if not os.path.exists(OTP_FILE): return {}
    try:
        with open(OTP_FILE) as f:
            return json.load(f).get(username, {})
    except Exception: return {}

def get_qr_uri(username: str, secret: str, issuer: str = "FYP-SecuritySuite") -> str:
    """Return otpauth URI (for QR code generation or Google Authenticator)."""
    return f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&digits=6&period=30"
