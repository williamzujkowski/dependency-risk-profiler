# Installation Scripts

This directory contains scripts for installing the Dependency Risk Profiler.

## Scripts

- `install.py` - Python installation script for cross-platform use
- `install.sh` - Bash installation script for Unix/Linux systems
- `install.bat` - Batch installation script for Windows systems
- `quickinstall.py` - Simplified installation script that installs directly from PyPI

## Usage

### Python Installation (Cross-platform)
```bash
python scripts/install.py
```

### Unix/Linux Installation
```bash
bash scripts/install.sh
```

### Windows Installation
```batch
scripts\install.bat
```

### Quick Installation (from PyPI)
```bash
python scripts/quickinstall.py
```

## Notes

- The installation scripts will create a virtual environment by default
- Use the `--help` flag with any script to see available options
- The Python script works on all platforms but requires Python 3.8+