# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgl1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source code
COPY . .

# Expose port (for Render, this is ignored but still good practice)
EXPOSE 8000

# Make start script executable
RUN chmod +x start.sh

# Start script will decide dev or prod mode
CMD ["./start.sh"]
