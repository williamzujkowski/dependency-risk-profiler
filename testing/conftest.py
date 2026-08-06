"""Test fixtures for dependency risk profiler."""

import os
import tempfile
from typing import Dict, Iterator

import pytest

from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.utils import reset_failed_clone_cache


@pytest.fixture(autouse=True)
def _forget_clone_failures() -> Iterator[None]:
    """Empty the process-scoped clone-failure cache around every test.

    The cache (#282) lives for the life of the process, which in a test run is
    the whole suite. Left alone, the first test to record a failure for a URL
    would answer for every later test that touches it, and a test asserting a
    clone was attempted would pass or fail on collection order.
    """
    reset_failed_clone_cache()
    yield
    reset_failed_clone_cache()


@pytest.fixture
def sample_nodejs_manifest() -> Iterator[str]:
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
          "integrity": "sha512-express-test",
          "dependencies": {
            "accepts": "~1.3.7",
            "array-flatten": "1.1.1"
          }
        },
        "node_modules/lodash": {
          "version": "4.17.20",
          "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
          "integrity": "sha512-lodash-test"
        }
      },
      "dependencies": {
        "express": {
          "version": "4.17.1",
          "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
          "integrity": "sha512-express-test",
          "requires": {
            "accepts": "~1.3.7",
            "array-flatten": "1.1.1"
          }
        },
        "lodash": {
          "version": "4.17.20",
          "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
          "integrity": "sha512-lodash-test"
        }
      }
    }
    """

    fd, path = tempfile.mkstemp(suffix=".json", prefix="package-lock-")
    os.write(fd, content.encode("utf-8"))
    os.close(fd)

    yield path

    # Cleanup
    os.unlink(path)


@pytest.fixture
def sample_python_manifest() -> Iterator[str]:
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

    yield path

    # Cleanup
    os.unlink(path)


@pytest.fixture
def sample_golang_manifest() -> Iterator[str]:
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

    yield path

    # Cleanup
    os.unlink(path)


@pytest.fixture
def sample_dependencies() -> Dict[str, DependencyMetadata]:
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
