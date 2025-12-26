"""
Configuration settings for the Mobile Security Backend
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # MobSF Configuration
    mobsf_url: str = "http://localhost:8000"
    mobsf_username: str = "mobsf"
    mobsf_password: str = "mobsf"
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8001
    debug: bool = True
    
    # File Storage
    upload_dir: str = "uploads"
    reports_dir: str = "reports"
    
    # CORS
    cors_origins: list = ["http://localhost:5173", "http://localhost:3000"]
    
    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
