"""
reset_credentials.py
Run this script to reset login to: Shahid / Shahid123
"""
import json, hashlib, os

creds = {
    "users": {
        "Shahid": {
            "password": hashlib.sha256("Shahid123".encode()).hexdigest(),
            "role": "admin",
            "created": "2026-01-01"
        }
    }
}
with open("credentials.json", "w") as f:
    json.dump(creds, f, indent=2)

print("=" * 40)
print("Credentials reset!")
print("Username: Shahid")
print("Password: Shahid123")
print("=" * 40)
