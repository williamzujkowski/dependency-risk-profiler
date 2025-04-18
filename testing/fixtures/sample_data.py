"""Sample data for testing."""

import os
import tempfile
from typing import Dict

from dependency_risk_profiler.models import DependencyMetadata


def create_sample_nodejs_manifest() -> str:
    """Create a sample package-lock.json file.
    
    Returns:
        Path to the sample manifest file.
    """
    content = """
    {
      "name": "test-project",
      "version": "1.0.0",
      "lockfileVersion": 2,
      "requires": true,
      "packages": {
        "": {
          "name": "test-project",
          "version": "1.0.0",
          "dependencies": {
            "express": "^4.17.1",
            "lodash": "^4.17.20"
          }
        },
        "node_modules/express": {
          "version": "4.17.1",
          "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
          "integrity": "sha512-mHJ9O79RqluphRrcw2X/GTh3k9tVv8YcoyY4Kkh4WDMUYKRZUq0h1o0w2rrrxBqM7VoeUVqgb27xlEMXTnYt4g==",
          "dependencies": {
            "accepts": "~1.3.7",
            "array-flatten": "1.1.1"
          }
        },
        "node_modules/lodash": {
          "version": "4.17.20",
          "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
          "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="
        }
      },
      "dependencies": {
        "express": {
          "version": "4.17.1",
          "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
          "integrity": "sha512-mHJ9O79RqluphRrcw2X/GTh3k9tVv8YcoyY4Kkh4WDMUYKRZUq0h1o0w2rrrxBqM7VoeUVqgb27xlEMXTnYt4g==",
          "requires": {
            "accepts": "~1.3.7",
            "array-flatten": "1.1.1"
          }
        },
        "lodash": {
          "version": "4.17.20",
          "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
          "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="
        }
      }
    }
    """

    fd, path = tempfile.mkstemp(suffix=".json", prefix="package-lock-")
    os.write(fd, content.encode("utf-8"))
    os.close(fd)

    return path


def create_sample_python_manifest() -> str:
    """Create a sample requirements.txt file.
    
    Returns:
        Path to the sample manifest file.
    """
    content = """
    # Test requirements file
    flask==2.0.1
    requests>=2.25.0
    numpy==1.20.0; python_version >= "3.9"
    """

    fd, path = tempfile.mkstemp(suffix=".txt", prefix="requirements-")
    os.write(fd, content.encode("utf-8"))
    os.close(fd)

    return path


def create_sample_golang_manifest() -> str:
    """Create a sample go.mod file.
    
    Returns:
        Path to the sample manifest file.
    """
    content = """
    module github.com/username/test-project

    go 1.17

    require (
        github.com/gin-gonic/gin v1.7.4
        github.com/stretchr/testify v1.7.0
    )

    require github.com/sirupsen/logrus v1.8.1
    """

    fd, path = tempfile.mkstemp(suffix=".mod", prefix="go-")
    os.write(fd, content.encode("utf-8"))
    os.close(fd)

    return path


def get_sample_dependencies() -> Dict[str, DependencyMetadata]:
    """Create sample dependency metadata.
    
    Returns:
        Dictionary of sample dependency metadata.
    """
    return {
        "express": DependencyMetadata(
            name="express",
            installed_version="4.17.1",
            latest_version="4.18.2",
            repository_url="https://github.com/expressjs/express",
        ),
        "lodash": DependencyMetadata(
            name="lodash",
            installed_version="4.17.20",
            latest_version="4.17.21",
            repository_url="https://github.com/lodash/lodash",
        ),
    }