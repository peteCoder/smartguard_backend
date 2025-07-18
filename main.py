from typing import Union
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from mangum import Mangum
import os


# os.add_dll_directory(r"C:\msys64\ucrt64\bin")

app = FastAPI()

from routers import checker_router

app = FastAPI(
    title="Domain Checker API",
    description="Backend service for domain checking and QR scanning",
    version="1.0.0",
    debug=settings.DEBUG,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    # allow_origins=settings.ALLOWED_ORIGINS if settings.ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def main_home():
    return {"message": "Welcome to our SMART Checker API"}


# Include API routes
app.include_router(checker_router.router, prefix="/api")


handler = Mangum(app)



