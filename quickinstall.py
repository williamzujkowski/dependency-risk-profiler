#!/usr/bin/env python3
"""
Quick installer script for Dependency Risk Profiler.

This script allows users to install Dependency Risk Profiler directly from PyPI
without cloning the repository first.
"""
import os
import platform
import subprocess
import sys
import venv
from pathlib import Path

PACKAGE_NAME = "dependency-risk-profiler"


def check_python_version():
    """Check if the Python version meets requirements."""
    required_version = (3, 8)
    current_version = sys.version_info
    
    if current_version < required_version:
        print(f"Error: Python {required_version[0]}.{required_version[1]} or higher is required.")
        print(f"Current version is {current_version.major}.{current_version.minor}")
        return False
    
    print(f"Python {current_version.major}.{current_version.minor} detected (required: >= {required_version[0]}.{required_version[1]})")
    return True


def create_venv(venv_path):
    """Create a Python virtual environment."""
    print(f"Creating virtual environment at {venv_path}...")
    try:
        venv.create(venv_path, with_pip=True)
        return True
    except Exception as e:
        print(f"Error creating virtual environment: {e}")
        return False


def get_venv_bin_dir(venv_path):
    """Get the bin directory path based on the operating system."""
    if platform.system() == "Windows":
        return os.path.join(venv_path, "Scripts")
    else:
        return os.path.join(venv_path, "bin")


def install_from_pypi(package_name, venv_path=None):
    """Install the package from PyPI."""
    try:
        pip_cmd = "pip"
        if venv_path:
            bin_dir = get_venv_bin_dir(venv_path)
            pip_cmd = os.path.join(bin_dir, pip_cmd)
        
        print(f"Installing {package_name} from PyPI...")
        subprocess.run([pip_cmd, "install", package_name], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing package: {e}")
        return False


def test_installation(venv_path=None):
    """Test if the installation was successful."""
    try:
        cmd = "dependency-risk-profiler"
        if venv_path:
            bin_dir = get_venv_bin_dir(venv_path)
            cmd = os.path.join(bin_dir, cmd)
        
        print(f"Testing installation with {cmd}...")
        subprocess.run([cmd, "--help"], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error testing installation: {e}")
        return False


def main():
    """Main installer function."""
    print("Dependency Risk Profiler Quick Installer")
    print("=======================================")
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Ask installation method
    print("\nChoose an installation method:")
    print("1. Install directly using pip (global installation)")
    print("2. Install in a virtual environment (recommended)")
    
    while True:
        try:
            choice = input("Enter your choice (1 or 2): ")
            if choice in ["1", "2"]:
                break
            print("Invalid choice. Please enter 1 or 2.")
        except (KeyboardInterrupt, EOFError):
            print("\nInstallation cancelled.")
            return 1
    
    if choice == "1":
        # Direct installation
        print("\nInstalling globally...")
        if install_from_pypi(PACKAGE_NAME):
            print("\nInstallation complete!")
            print("You can now use the dependency-risk-profiler command from anywhere.")
            test_installation()
    else:
        # Virtual environment installation
        install_dir = os.path.join(os.getcwd(), "dependency-risk-profiler")
        os.makedirs(install_dir, exist_ok=True)
        
        venv_path = os.path.join(install_dir, "venv")
        
        if not create_venv(venv_path):
            return 1
        
        if install_from_pypi(PACKAGE_NAME, venv_path):
            print("\nInstallation complete!")
            print(f"Dependency Risk Profiler is now available in the virtual environment {venv_path}")
            print("\nTo use it, activate the virtual environment first:")
            
            if platform.system() == "Windows":
                print(f"  {venv_path}\\Scripts\\activate.bat")
            else:
                print(f"  source {venv_path}/bin/activate")
            
            test_installation(venv_path)
    
    # Display usage examples
    print("\nUsage examples:")
    print("  dependency-risk-profiler --manifest /path/to/package-lock.json")
    print("  dependency-risk-profiler --manifest /path/to/requirements.txt --save-history")
    print("  dependency-risk-profiler --manifest /path/to/requirements.txt --analyze-trends")
    print("  dependency-risk-profiler --manifest /path/to/requirements.txt --generate-graph")
    
    print("\nEnhanced features:")
    print("  - Historical trends analysis: Track risk changes over time")
    print("  - Supply chain visualization: Generate dependency graphs")
    print("  - Security metrics analysis: Evaluate OpenSSF Scorecard-inspired metrics")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())