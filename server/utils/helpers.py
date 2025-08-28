"""
Helper functions and utilities for CyberGuard Server.
Common functions used across the application.
"""

import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import uuid
import re

logger = logging.getLogger(__name__)

def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())

def hash_data(data: str) -> str:
    """Generate SHA-256 hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()

def validate_email(email: str) -> bool:
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    # Check each octet
    octets = ip.split('.')
    for octet in octets:
        if not (0 <= int(octet) <= 255):
            return False
    
    return True

def format_timestamp(timestamp: Optional[datetime] = None) -> str:
    """Format timestamp to ISO format."""
    if timestamp is None:
        timestamp = datetime.utcnow()
    return timestamp.isoformat() + 'Z'

def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO format timestamp."""
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        return datetime.utcnow()

def calculate_time_difference(start: datetime, end: datetime) -> str:
    """Calculate time difference in human-readable format."""
    delta = end - start
    days = delta.days
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def sanitize_input(input_data: Union[str, Dict, List]) -> Union[str, Dict, List]:
    """Sanitize input data to prevent injection attacks."""
    if isinstance(input_data, str):
        # Basic HTML/script sanitization
        sanitized = input_data.replace('<', '<').replace('>', '>')
        sanitized = sanitized.replace('"', '"').replace("'", '&#x27;')
        return sanitized
    
    elif isinstance(input_data, dict):
        return {k: sanitize_input(v) for k, v in input_data.items()}
    
    elif isinstance(input_data, list):
        return [sanitize_input(item) for item in input_data]
    
    return input_data

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    if size_bytes == 0:
        return "0B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.2f}{size_names[i]}"

def generate_random_string(length: int = 16) -> str:
    """Generate a random string of specified length."""
    import random
    import string
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def is_valid_json(data: str) -> bool:
    """Check if string is valid JSON."""
    try:
        json.loads(data)
        return True
    except (json.JSONDecodeError, TypeError):
        return False

def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if (key in result and isinstance(result[key], dict) 
            and isinstance(value, dict)):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

def get_current_utc_time() -> datetime:
    """Get current UTC time."""
    return datetime.utcnow()

def format_duration(seconds: int) -> str:
    """Format duration in seconds to human-readable format."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

def truncate_string(text: str, max_length: int = 100, ellipsis: str = "...") -> str:
    """Truncate string to specified length with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(ellipsis)] + ellipsis

def validate_password_strength(password: str) -> Dict[str, Any]:
    """Validate password strength."""
    result = {
        "valid": True,
        "issues": [],
        "score": 0
    }
    
    # Check length
    if len(password) < 8:
        result["valid"] = False
        result["issues"].append("Password must be at least 8 characters long")
    
    # Check for uppercase
    if not any(c.isupper() for c in password):
        result["issues"].append("Password should contain uppercase letters")
        result["score"] -= 1
    
    # Check for lowercase
    if not any(c.islower() for c in password):
        result["issues"].append("Password should contain lowercase letters")
        result["score"] -= 1
    
    # Check for digits
    if not any(c.isdigit() for c in password):
        result["issues"].append("Password should contain numbers")
        result["score"] -= 1
    
    # Check for special characters
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/' for c in password):
        result["issues"].append("Password should contain special characters")
        result["score"] -= 1
    
    # Calculate score (0-4)
    result["score"] = max(0, 4 + result["score"])
    
    if not result["valid"]:
        result["score"] = 0
    
    return result
