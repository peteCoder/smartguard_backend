from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
# from dotenv import load_dotenv
from pydantic import Field, field_validator
from typing import Union

# Optional: If you still want to load .env manually
# load_dotenv()

class Settings(BaseSettings):
    API_SECRET_KEY: str = Field("defaultsecret", env="API_SECRET_KEY")
    # ALLOWED_ORIGINS: List[str] = Field(["*"], env="ALLOWED_ORIGINS")
    ML_MODEL_PATH: str = Field("models/phishing_model.pkl", env="ML_MODEL_PATH")
    REPORT_OUTPUT_DIR: str = Field("static/reports", env="REPORT_OUTPUT_DIR")
    DEBUG: bool = Field(True, env="DEBUG")
    ENVIRONMENT: str = Field("development", env="ENVIRONMENT")
    ALLOWED_ORIGINS: Union[List[str], str] = Field(["*"], env="ALLOWED_ORIGINS")

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def split_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.strip("[]").split(",")]
        return v

    class Config:
        env_file = ".env"

settings = Settings()


