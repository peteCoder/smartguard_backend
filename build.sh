#!/bin/bash

echo "ENV is set to: $ENV"
apt-get update && apt-get install -y libzbar0

# Switch between development and production mode
if [ "$ENV" = "dev" ]; then
    echo "Running in development mode with FastAPI CLI..."
    fastapi dev main.py
else
    echo "Running in production mode with Uvicorn..."
    uvicorn main:app --host 0.0.0.0 --port 8000
fi