#!/bin/bash

# SilentShot Installation Script
# Tested on Ubuntu/Debian, CentOS/RHEL, and macOS

echo -e "\033[1;34mInstalling SilentShot - Headless Web Screenshot Tool\033[0m"

# Check for Python 3.7+
if ! python3 -c 'import sys; assert sys.version_info >= (3,7)' > /dev/null 2>&1; then
    echo -e "\033[1;31mError: Python 3.7 or higher is required\033[0m"
    exit 1
fi

# Install system dependencies
echo -e "\033[1;33mInstalling system dependencies...\033[0m"
if command -v apt-get > /dev/null; then
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y \
        python3-pip \
        python3-venv \
        libicu66 \
        libjpeg8 \
        libwebp6 \
        libffi7 \
        libopus0 \
        libwoff1 \
        libharfbuzz-icu0 \
        libgstreamer-plugins-base1.0-0 \
        libgstreamer1.0-0 \
        libopenjp2-7
elif command -v yum > /dev/null; then
    # RHEL/CentOS
    sudo yum install -y \
        python3-pip \
        libicu \
        libjpeg-turbo \
        libwebp \
        libffi \
        opus \
        woff2 \
        harfbuzz-icu \
        gstreamer1 \
        gstreamer1-plugins-base \
        openjpeg2
elif command -v brew > /dev/null; then
    # macOS
    brew install python icu4c jpeg webp opus woff2 harfbuzz gstreamer openjpeg
else
    echo -e "\033[1;33mWarning: Could not detect package manager. You may need to install dependencies manually.\033[0m"
fi

# Create virtual environment
echo -e "\033[1;33mSetting up Python virtual environment...\033[0m"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "\033[1;33mInstalling Python packages...\033[0m"
pip install --upgrade pip wheel --break-system-packages
pip install -r requirements.txt --break-system-packages

# Install Playwright browsers
echo -e "\033[1;33mInstalling Playwright browsers...\033[0m"
python3 -m playwright install 
python3 -m playwright install-deps

# Make script executable
chmod +x SilentShot.py

echo -e "\033[1;32mInstallation complete!\033[0m"
echo -e "Run the tool with: \033[1;35m./SilentShot.py capture --help\033[0m"
echo -e "Activate virtual environment first with: \033[1;35msource venv/bin/activate\033[0m"