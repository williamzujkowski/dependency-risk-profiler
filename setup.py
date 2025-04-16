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
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/username/dependency-risk-profiler",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "packaging>=20.0",
        "colorama>=0.4.4;platform_system=='Windows'",
    ],
    entry_points={
        "console_scripts": [
            "dependency-risk-profiler=dependency_risk_profiler.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=2.12.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=4.0.0",
            "mypy>=0.9.0",
        ],
    },
)