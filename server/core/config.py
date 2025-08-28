"""
Configuration management for CyberGuard Server.
Handles environment variables and application settings.
"""

import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Server Configuration
    server_host: str = Field(default="0.0.0.0", env="SERVER_HOST")
    server_port: int = Field(default=8000, env="SERVER_PORT")
    debug: bool = Field(default=False, env="DEBUG")
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # Database Configuration
    mongodb_uri: str = Field(default="mongodb://localhost:27017/cyberguard", env="MONGODB_URI")
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    database_name: str = Field(default="cyberguard_dev", env="DATABASE_NAME")
    
    # Security Configuration
    secret_key: str = Field(default="change-this-in-production", env="SECRET_KEY")
    jwt_secret_key: str = Field(default="change-this-jwt-secret", env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=60, env="JWT_EXPIRE_MINUTES")
    
    # ML Configuration
    ml_model_path: str = Field(default="./ml-module/models/threat_detection_model.h5", env="ML_MODEL_PATH")
    ml_threshold: float = Field(default=0.85, env="ML_THRESHOLD")
    ml_update_interval: int = Field(default=3600, env="ML_UPDATE_INTERVAL")
    
    # Threat Intelligence
    threat_intelligence_api_key: Optional[str] = Field(default=None, env="THREAT_INTELLIGENCE_API_KEY")
    threat_update_interval: int = Field(default=1800, env="THREAT_UPDATE_INTERVAL")
    
    # External APIs
    virus_total_api_key: Optional[str] = Field(default=None, env="VIRUS_TOTAL_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, env="ABUSEIPDB_API_KEY")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

def get_settings() -> Settings:
    """Get application settings instance."""
    return Settings()

# Global settings instance
settings = get_settings()
