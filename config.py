import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

class Settings:
    # Load allowed origins as a list
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    API_SECRET_KEY = os.getenv("API_SECRET_KEY", "defaultsecret")

settings = Settings()


