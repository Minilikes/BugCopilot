"""Application configuration — loaded from .env file."""

import os
from dotenv import load_dotenv

load_dotenv()

# LLM settings
LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL: str = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")

# App settings
APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
DB_PATH: str = os.getenv("DB_PATH", "bugcopilot.db")

# Rate limiting (seconds between passive recon requests)
RATE_LIMIT_DELAY: float = float(os.getenv("RATE_LIMIT_DELAY", "1.5"))

# NVD API key (optional)
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
