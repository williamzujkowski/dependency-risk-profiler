#!/bin/bash

# Simple installation script for Dependency Risk Profiler

set -e

echo "Installing Dependency Risk Profiler..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed. Please install Python 3 and try again."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is required but not installed. Please install pip and try again."
    exit 1
fi

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "Error: git is required but not installed. Please install git and try again."
    exit 1
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install package
echo "Installing package..."
pip install -e .

# Test installation
echo "Testing installation..."
dependency-risk-profiler --help

echo ""
echo "Installation complete! Dependency Risk Profiler is now available in the virtual environment."
echo ""
echo "To use it, activate the virtual environment first:"
echo "  source venv/bin/activate"
echo ""
echo "Then run the tool:"
echo "  dependency-risk-profiler --manifest /path/to/your/dependency/file"
echo ""
echo "For more information, see README.md"