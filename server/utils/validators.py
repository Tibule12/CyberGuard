"""
Validation utilities for CyberGuard Server.
Contains functions for validating input data and ensuring data integrity.
"""

import re
from fastapi import HTTPException

def validate_username(username: str) -> None:
    """Validate username format."""
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        raise HTTPException(status_code=400, detail="Invalid username. Must be 3-30 characters long and can only contain letters, numbers, and underscores.")

def validate_password(password: str) -> None:
    """Validate password strength."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character.")

def validate_email(email: str) -> None:
    """Validate email format."""
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise HTTPException(status_code=400, detail="Invalid email format.")

def validate_ip(ip: str) -> None:
    """Validate IP address format."""
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format.")
    octets = ip.split('.')
    for octet in octets:
        if not (0 <= int(octet) <= 255):
            raise HTTPException(status_code=400, detail="IP address octets must be between 0 and 255.")
