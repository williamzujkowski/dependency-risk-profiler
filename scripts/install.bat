@echo off
echo Installing Dependency Risk Profiler...

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is required but not installed. Please install Python and try again.
    exit /b 1
)

REM Check Python version
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python 3.8 or higher is required.
    exit /b 1
)

echo Python check passed

REM Offer installation options
echo.
echo Choose an installation method:
echo 1. Install directly using pip (global installation)
echo 2. Install in a virtual environment (recommended)
set /p choice="Enter your choice (1 or 2): "

if "%choice%"=="1" (
    REM Direct installation
    echo Installing globally...
    REM Navigate to the project root directory (parent of scripts directory)
    cd %~dp0\..
    pip install .
    
    echo Installation complete!
    echo You can now use the dependency-risk-profiler command from anywhere.
) else (
    REM Virtual environment installation
    echo Creating virtual environment...
    REM Navigate to the project root directory (parent of scripts directory)
    cd %~dp0\..
    python -m venv venv
    
    REM Activate virtual environment
    call venv\Scripts\activate.bat
    
    REM Install the package
    echo Installing package in virtual environment...
    pip install .
    
    REM Test installation
    echo Testing installation...
    dependency-risk-profiler --help
    
    echo.
    echo Installation complete! Dependency Risk Profiler is now available in the virtual environment.
    echo.
    echo To use it, activate the virtual environment first:
    echo   venv\Scripts\activate.bat
)

REM Display usage examples
echo.
echo Usage examples:
echo   dependency-risk-profiler --manifest path\to\package-lock.json
echo   dependency-risk-profiler --manifest path\to\requirements.txt --save-history
echo   dependency-risk-profiler --manifest path\to\requirements.txt --analyze-trends
echo   dependency-risk-profiler --manifest path\to\requirements.txt --generate-graph
echo.
echo Enhanced features:
echo   - Historical trends analysis: Track risk changes over time
echo   - Supply chain visualization: Generate dependency graphs
echo   - Security metrics analysis: Evaluate OpenSSF Scorecard-inspired metrics
echo.
echo For trend visualization, open the examples\trend_visualizer.html file in your browser.
echo.
echo For more information, see README.md

pause