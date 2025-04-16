#!/bin/bash

# Installation script for Dependency Risk Profiler with enhanced features

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

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
required_version="3.8"

python3 -c "import sys; sys.exit(not (sys.version_info.major == 3 and sys.version_info.minor >= 8))" || {
    echo "Error: Python version $python_version detected, but >= $required_version is required"
    exit 1
}

echo "Python version $python_version detected (required: >= $required_version)"

# Offer installation options
echo ""
echo "Choose an installation method:"
echo "1. Install directly using pip (global installation)"
echo "2. Install in a virtual environment (recommended)"
read -p "Enter your choice (1 or 2): " choice

if [ "$choice" == "1" ]; then
    # Direct installation
    echo "Installing globally..."
    pip3 install .
    
    echo "Installation complete!"
    echo "You can now use the dependency-risk-profiler command from anywhere."
else
    # Virtual environment installation
    echo "Creating virtual environment..."
    python3 -m venv venv
    
    # Activate virtual environment based on OS
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows
        source venv/Scripts/activate
    else
        # Unix/Linux/MacOS
        source venv/bin/activate
    fi

    # Install the package
    echo "Installing package in virtual environment..."
    pip install .

    # Test installation
    echo "Testing installation..."
    dependency-risk-profiler --help

    echo ""
    echo "Installation complete! Dependency Risk Profiler is now available in the virtual environment."
    echo ""
    echo "To use it, activate the virtual environment first:"
    
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        echo "  source venv/Scripts/activate"
    else
        echo "  source venv/bin/activate"
    fi
fi

# Display usage examples
echo ""
echo "Usage examples:"
echo "  dependency-risk-profiler --manifest /path/to/package-lock.json"
echo "  dependency-risk-profiler --manifest /path/to/requirements.txt --save-history"
echo "  dependency-risk-profiler --manifest /path/to/requirements.txt --analyze-trends"
echo "  dependency-risk-profiler --manifest /path/to/requirements.txt --generate-graph"
echo ""
echo "Enhanced features:"
echo "  - Historical trends analysis: Track risk changes over time"
echo "  - Supply chain visualization: Generate dependency graphs"
echo "  - Security metrics analysis: Evaluate OpenSSF Scorecard-inspired metrics"
echo ""
echo "For trend visualization, use the examples/trend_visualizer.html file in your browser."
echo ""
echo "For more information, see README.md"