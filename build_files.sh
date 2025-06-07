#!/bin/bash

# Update pip
echo "Updating pip..."
python3  pip install -U pip
python3 -m pip install --upgrade pip

# Install dependencies

echo "Installing project dependencies..."
python3  -m pip install -r requirements.txt


echo "Build process completed!"