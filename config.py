from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from pydantic import Field, field_validator
from typing import Union


class Settings(BaseSettings):
    # External API keys
    GOOGLE_SAFE_BROWSING_API_KEY: str = Field(..., env="GOOGLE_SAFE_BROWSING_API_KEY")
    URL_SCANNER_API_KEY: Union[List[str], str] = Field(..., env="URL_SCANNER_API_KEY")

    # Other Settings
    API_SECRET_KEY: str = Field(..., env="API_SECRET_KEY")
    ML_MODEL_PATH: str = Field(..., env="ML_MODEL_PATH")
    REPORT_OUTPUT_DIR: str = Field(..., env="REPORT_OUTPUT_DIR")
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




