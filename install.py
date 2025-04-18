#!/usr/bin/env python3
"""
Dependency Risk Profiler installer script.

This script provides an interactive way to install the Dependency Risk Profiler tool.
"""
import os
import platform
import subprocess
import sys
import venv
from pathlib import Path


def check_python_version():
    """Check if the Python version meets requirements."""
    required_version = (3, 8)
    current_version = sys.version_info

    if current_version < required_version:
        print(
            f"Error: Python {required_version[0]}.{required_version[1]} or higher is required."
        )
        print(f"Current version is {current_version.major}.{current_version.minor}")
        return False

    print(
        f"Python {current_version.major}.{current_version.minor} detected (required: >= {required_version[0]}.{required_version[1]})"
    )
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


def activate_venv(venv_path):
    """Activate the virtual environment in the current process."""
    bin_dir = get_venv_bin_dir(venv_path)

    # Set environment variables to "activate" the venv
    os.environ["VIRTUAL_ENV"] = str(venv_path)

    # Add the venv bin directory to PATH
    os.environ["PATH"] = os.pathsep.join([bin_dir, os.environ.get("PATH", "")])

    # Remove PYTHONHOME if set
    os.environ.pop("PYTHONHOME", None)

    # Update sys.path
    sys.path.insert(0, bin_dir)

    return bin_dir


def run_pip_install(package_path, bin_dir=None):
    """Run pip install on the package."""
    try:
        pip_exe = "pip"
        if bin_dir:
            # Use the pip from virtual environment
            pip_exe = os.path.join(bin_dir, pip_exe)

        print(f"Installing package with {pip_exe}...")
        subprocess.run([pip_exe, "install", "."], cwd=package_path, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing package: {e}")
        return False


def test_installation(bin_dir=None):
    """Test if the installation was successful."""
    try:
        cmd = "dependency-risk-profiler"
        if bin_dir:
            # Use the command from virtual environment
            cmd = os.path.join(bin_dir, cmd)

        print(f"Testing installation with {cmd}...")
        subprocess.run([cmd, "--help"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error testing installation: {e}")
        return False
    except FileNotFoundError:
        print(
            "Error: dependency-risk-profiler command not found. Installation may have failed."
        )
        return False


def main():
    """Main installer function."""
    print("Dependency Risk Profiler Installer")
    print("==================================")

    # Check Python version
    if not check_python_version():
        return 1

    # Get the package directory
    package_dir = Path(__file__).resolve().parent

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
        if run_pip_install(package_dir):
            print("\nInstallation complete!")
            print("You can now use the dependency-risk-profiler command from anywhere.")
            test_installation()
    else:
        # Virtual environment installation
        venv_path = package_dir / "venv"

        if not create_venv(venv_path):
            return 1

        bin_dir = activate_venv(venv_path)

        if run_pip_install(package_dir, bin_dir):
            print("\nInstallation complete!")
            print(
                f"Dependency Risk Profiler is now available in the virtual environment {venv_path}"
            )
            print("\nTo use it, activate the virtual environment first:")

            if platform.system() == "Windows":
                print(f"  {venv_path}\\Scripts\\activate.bat")
            else:
                print(f"  source {venv_path}/bin/activate")

            test_installation(bin_dir)

    # Display usage examples
    print("\nUsage examples:")
    print("  dependency-risk-profiler --manifest /path/to/package-lock.json")
    print(
        "  dependency-risk-profiler --manifest /path/to/requirements.txt --save-history"
    )
    print(
        "  dependency-risk-profiler --manifest /path/to/requirements.txt --analyze-trends"
    )
    print(
        "  dependency-risk-profiler --manifest /path/to/requirements.txt --generate-graph"
    )

    print("\nEnhanced features:")
    print("  - Historical trends analysis: Track risk changes over time")
    print("  - Supply chain visualization: Generate dependency graphs")
    print("  - Security metrics analysis: Evaluate OpenSSF Scorecard-inspired metrics")

    print(
        "\nFor trend visualization, use the examples/trend_visualizer.html file in your browser."
    )
    print("\nFor more information, see README.md")

    return 0


if __name__ == "__main__":
    sys.exit(main())
