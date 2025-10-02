# app/config.py
import os
import secrets
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Get secret key from environment, generate one if not set
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    if not SECRET_KEY:
        # Generate a temporary key for development
        SECRET_KEY = secrets.token_hex(32)
    
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 3600

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}