#!/usr/bin/env python3
"""
Dependency Risk Profiler installer script.

This script provides a modern, flexible way to install the Dependency Risk Profiler tool.
It supports development mode, pre-commit hooks, and various installation options.
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
import venv
from pathlib import Path

def check_python_version():
    """Check if the Python version meets requirements."""
    required_version = (3, 9)  # Updated to match pyproject.toml
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

def is_venv():
    """Check if we're running in a virtual environment."""
    return hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)

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

def run_command(command, cwd=None, env=None, check=True):
    """Run a command and handle errors appropriately."""
    try:
        result = subprocess.run(
            command,
            check=check,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return e
    except Exception as e:
        print(f"Error executing command: {e}")
        return None

def install_package(venv_path=None, dev=True, editable=True):
    """Install the package with pip."""
    
    # Determine pip executable
    pip_exe = "pip"
    env = os.environ.copy()
    
    if venv_path:
        bin_dir = get_venv_bin_dir(venv_path)
        pip_exe = os.path.join(bin_dir, pip_exe)
        env["VIRTUAL_ENV"] = str(venv_path)
        env["PATH"] = os.pathsep.join([bin_dir, env.get("PATH", "")])
    
    # Upgrade pip, setuptools, wheel
    print("Upgrading pip, setuptools, and wheel...")
    run_command([pip_exe, "install", "--upgrade", "pip", "setuptools", "wheel"], cwd=package_dir, env=env)
    
    # Determine install flags
    install_args = [pip_exe, "install"]
    if editable:
        install_args.append("-e")
    
    if dev:
        install_args.append(".[dev]")
    else:
        install_args.append(".")
    
    # Run installation
    print(f"Installing package: {' '.join(install_args)}")
    result = run_command(install_args, cwd=package_dir, env=env)
    
    if result and result.returncode == 0:
        return True
    return False

def setup_precommit(venv_path=None):
    """Install and set up pre-commit hooks."""
    env = os.environ.copy()
    
    if venv_path:
        bin_dir = get_venv_bin_dir(venv_path)
        precommit_exe = os.path.join(bin_dir, "pre-commit")
        env["VIRTUAL_ENV"] = str(venv_path)
        env["PATH"] = os.pathsep.join([bin_dir, env.get("PATH", "")])
    else:
        precommit_exe = "pre-commit"
    
    # Check if pre-commit hooks exist
    if not os.path.exists(".pre-commit-config.yaml"):
        print("Warning: .pre-commit-config.yaml not found. Skipping pre-commit setup.")
        return False
    
    # Install pre-commit hooks
    print("Installing pre-commit hooks...")
    result = run_command([precommit_exe, "install"], env=env, check=False)
    
    if result and result.returncode == 0:
        print("Pre-commit hooks installed successfully")
        return True
    else:
        print("Warning: Failed to install pre-commit hooks")
        return False

def test_installation(venv_path=None):
    """Test if the installation was successful."""
    env = os.environ.copy()
    
    if venv_path:
        bin_dir = get_venv_bin_dir(venv_path)
        cmd_path = os.path.join(bin_dir, "dependency-risk-profiler")
        env["VIRTUAL_ENV"] = str(venv_path)
        env["PATH"] = os.pathsep.join([bin_dir, env.get("PATH", "")])
    else:
        cmd_path = "dependency-risk-profiler"
    
    # Run the command with --help flag
    print("Testing installation...")
    result = run_command([cmd_path, "--help"], env=env, check=False)
    
    if result and result.returncode == 0:
        print("Installation test successful!")
        return True
    else:
        print("Warning: Installation test failed. The tool might not be correctly installed.")
        return False

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Install Dependency Risk Profiler")
    parser.add_argument("--no-dev", dest="dev_mode", action="store_false", 
                        help="Don't install development dependencies")
    parser.add_argument("--no-venv", dest="create_venv", action="store_false",
                        help="Don't create a virtual environment")
    parser.add_argument("--no-editable", dest="editable", action="store_false",
                        help="Install in non-editable mode")
    parser.add_argument("--venv-path", default="venv",
                        help="Path to virtual environment (default: venv)")
    parser.add_argument("--reinstall", action="store_true",
                        help="Reinstall even if virtual environment exists")
    parser.add_argument("--no-hooks", dest="install_hooks", action="store_false",
                        help="Don't install Git hooks")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Use interactive installation mode")
    return parser.parse_args()

def print_success_message(venv_path=None):
    """Print a success message with usage instructions."""
    print("\n=== Installation Complete ===")
    
    if venv_path:
        print("\nTo activate the virtual environment:")
        if platform.system() == "Windows":
            print(f"  {venv_path}\\Scripts\\activate")
        else:
            print(f"  source {venv_path}/bin/activate")
    
    print("\nUsage examples:")
    print("  dependency-risk-profiler analyze requirements.txt")
    print("  dependency-risk-profiler analyze --manifest requirements.txt --save-history")
    print("  dependency-risk-profiler analyze requirements.txt --generate-graph")
    print("  dependency-risk-profiler analyze --recursive --manifest project_directory")
    
    print("\nNext steps:")
    print("1. Run tests:              pytest")
    print("2. Run with coverage:      pytest --cov=src")
    print("3. Code formatting:        black . && isort .")
    print("4. Check security:         bandit -r src")
    
    print("\nFor more information, see README.md")

def interactive_install():
    """Run the installer in interactive mode."""
    print("Dependency Risk Profiler Installer")
    print("=================================")
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Ask installation method
    print("\nChoose an installation method:")
    print("1. Install directly (no virtual environment)")
    print("2. Install in a virtual environment (recommended)")
    print("3. Install in development mode with all dev dependencies")
    
    try:
        choice = input("Enter your choice (1-3) [3]: ").strip() or "3"
        if choice not in ["1", "2", "3"]:
            print(f"Invalid choice: {choice}. Defaulting to option 3.")
            choice = "3"
    except (KeyboardInterrupt, EOFError):
        print("\nInstallation cancelled.")
        return 1
    
    # Install pre-commit hooks?
    try:
        install_hooks = input("Install pre-commit hooks? (y/n) [y]: ").strip().lower() or "y"
        install_hooks = install_hooks in ["y", "yes"]
    except (KeyboardInterrupt, EOFError):
        print("\nInstallation cancelled.")
        return 1
    
    # Process installation based on choice
    if choice == "1":
        # Direct installation
        if install_package(dev=False, editable=False):
            if install_hooks:
                setup_precommit()
            test_installation()
            print_success_message()
            return 0
        return 1
    
    elif choice == "2":
        # Virtual environment installation (no dev dependencies)
        venv_path = package_dir / "venv"
        
        # Check if venv exists
        if os.path.exists(venv_path):
            try:
                reinstall = input(f"Virtual environment already exists at {venv_path}. Recreate? (y/n) [n]: ").strip().lower() or "n"
                if reinstall in ["y", "yes"]:
                    shutil.rmtree(venv_path)
                    create_venv(venv_path)
            except (KeyboardInterrupt, EOFError):
                print("\nInstallation cancelled.")
                return 1
        else:
            create_venv(venv_path)
        
        if install_package(venv_path, dev=False):
            if install_hooks:
                setup_precommit(venv_path)
            test_installation(venv_path)
            print_success_message(venv_path)
            return 0
        return 1
    
    else:  # choice == "3"
        # Development mode with virtual environment
        venv_path = package_dir / "venv"
        
        # Check if venv exists
        if os.path.exists(venv_path):
            try:
                reinstall = input(f"Virtual environment already exists at {venv_path}. Recreate? (y/n) [n]: ").strip().lower() or "n"
                if reinstall in ["y", "yes"]:
                    shutil.rmtree(venv_path)
                    create_venv(venv_path)
            except (KeyboardInterrupt, EOFError):
                print("\nInstallation cancelled.")
                return 1
        else:
            create_venv(venv_path)
        
        if install_package(venv_path, dev=True, editable=True):
            if install_hooks:
                setup_precommit(venv_path)
            test_installation(venv_path)
            print_success_message(venv_path)
            return 0
        return 1

def main():
    """Main entry point for the installer."""
    args = parse_args()
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Run interactive mode if requested
    if args.interactive:
        return interactive_install()
    
    # Set venv path
    venv_path = Path(args.venv_path)
    
    # Handle virtual environment
    if args.create_venv:
        if os.path.exists(venv_path) and args.reinstall:
            print(f"Removing existing virtual environment: {venv_path}")
            shutil.rmtree(venv_path)
            create_venv(venv_path)
        elif not os.path.exists(venv_path):
            create_venv(venv_path)
        else:
            print(f"Using existing virtual environment: {venv_path}")
    else:
        if is_venv():
            print("Using current virtual environment")
            venv_path = None
        else:
            print("Installing without a virtual environment")
            venv_path = None
    
    # Install the package
    if install_package(venv_path, dev=args.dev_mode, editable=args.editable):
        if args.install_hooks:
            setup_precommit(venv_path)
        test_installation(venv_path)
        print_success_message(venv_path if args.create_venv else None)
        return 0
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
