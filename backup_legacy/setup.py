"""Setup script for the dependency-risk-profiler package."""

from setuptools import find_packages, setup

# Get version from package
with open("src/dependency_risk_profiler/__init__.py", "r") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().strip('"').strip("'")
            break
    else:
        version = "0.1.0"

# Get long description from README
with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="dependency-risk-profiler",
    version=version,
    description="A tool to evaluate the health and risk of a project's dependencies beyond vulnerability scanning",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="William Zujkowski",
    author_email="williamzujkowski@gmail.com",
    url="https://github.com/williamzujkowski/dependency-risk-profiler",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.32.2",  # Fixed CVE-2024-35195
        "packaging>=23.2",
        "colorama>=0.4.6;platform_system=='Windows'",
        "pyyaml>=6.0.1",
        "matplotlib>=3.7.0",  # For potential visualization
        "networkx>=2.8.8",  # For dependency graph analysis
        "cryptography>=42.0.0",  # For secure code signing, Fixed CVE-2023-50782 & others
        "urllib3>=2.2.2",  # Fixed CVE-2024-37891
        "jinja2>=3.1.5",  # Fixed CVE-2024-56201
        "certifi>=2024.7.4",  # Fixed CVE-2024-39689
        "werkzeug>=3.0.6",  # Fixed CVE-2024-49766, CVE-2024-49767
        "tomli>=2.0.1;python_version>='3.9' and python_version<'3.11'",  # TOML parsing (builtin in Python 3.11+)
        "pygments>=2.16.1",  # Fixed CVE-2023-41337
        "pillow>=10.2.0",  # Fixed CVE-2023-50447, CVE-2024-35219, etc.
        "typer>=0.9.0",  # CLI framework for better user experience
        "rich>=13.5.0",  # For rich terminal output and progress bars
        "aiohttp>=3.8.6",  # For async HTTP requests
        "httpx>=0.24.1",  # Modern HTTP client with sync and async support
        "pipdeptree>=2.13.0",  # For enhanced Python transitive dependency analysis
    ],
    entry_points={
        "console_scripts": [
            "dependency-risk-profiler=dependency_risk_profiler.cli.typer_cli:main",
            "dependency-risk-profiler-legacy=dependency_risk_profiler.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.2.0",
            "pytest-benchmark>=4.0.0",  # For performance benchmark tests
            "pytest-asyncio>=0.21.1",  # For testing async code
            "black>=24.4.0",
            "isort>=5.13.2",
            "flake8>=7.0.0",
            "mypy>=1.9.0",
            "responses>=0.25.0",  # For HTTP mocking in tests
            "aioresponses>=0.7.4",  # For mocking async HTTP requests
            "tomli>=2.0.1;python_version>='3.9' and python_version<'3.11'",  # For TOML parsing in tests (builtin in 3.11+)
            "tomli-w>=1.0.0",  # For TOML writing in tests
        ],
        "benchmark": [
            "numpy>=1.24.0",  # For benchmark tests and percentile calculations
        ],
    },
)
