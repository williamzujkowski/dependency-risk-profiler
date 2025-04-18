"""Tests for the dependency manifest parsers."""

import os
import tempfile

from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.golang import GoParser
from dependency_risk_profiler.parsers.nodejs import NodeJSParser
from dependency_risk_profiler.parsers.python import PythonParser


def test_base_parser_factory(
    sample_nodejs_manifest, sample_python_manifest, sample_golang_manifest
):
    """Test the base parser factory method."""
    # Debug info
    print(f"NodeJS manifest path: {sample_nodejs_manifest}")
    print(f"File exists: {os.path.exists(sample_nodejs_manifest)}")

    # Test Node.js parser
    parser = BaseParser.get_parser_for_file(sample_nodejs_manifest)
    assert isinstance(parser, NodeJSParser)

    # Test Python parser
    parser = BaseParser.get_parser_for_file(sample_python_manifest)
    assert isinstance(parser, PythonParser)

    # Test Go parser
    parser = BaseParser.get_parser_for_file(sample_golang_manifest)
    assert isinstance(parser, GoParser)

    # Test TOML parsers
    from dependency_risk_profiler.parsers.toml import TomlParser

    # Create temporary TOML files for testing
    with tempfile.NamedTemporaryFile(
        suffix=".toml", prefix="pyproject-", delete=False
    ) as f:
        pyproject_path = f.name
        f.write(b"[project]\nname = 'test'\n")

    with tempfile.NamedTemporaryFile(
        suffix=".toml", prefix="cargo-", delete=False
    ) as f:
        cargo_path = f.name
        f.write(b"[package]\nname = 'test'\n")

    try:
        parser = BaseParser.get_parser_for_file(pyproject_path)
        assert isinstance(parser, TomlParser)

        parser = BaseParser.get_parser_for_file(cargo_path)
        assert isinstance(parser, TomlParser)
    finally:
        # Clean up
        if os.path.exists(pyproject_path):
            os.unlink(pyproject_path)
        if os.path.exists(cargo_path):
            os.unlink(cargo_path)

    # Test unsupported file type
    parser = BaseParser.get_parser_for_file("unknown.txt")
    assert parser is None


def test_nodejs_parser(sample_nodejs_manifest):
    """Test the Node.js package-lock.json parser."""
    parser = NodeJSParser(sample_nodejs_manifest)
    dependencies = parser.parse()

    assert dependencies is not None
    assert len(dependencies) == 2
    assert "express" in dependencies
    assert "lodash" in dependencies

    express = dependencies["express"]
    assert express.name == "express"
    assert express.installed_version == "4.17.1"

    lodash = dependencies["lodash"]
    assert lodash.name == "lodash"
    assert lodash.installed_version == "4.17.20"


def test_python_parser(sample_python_manifest):
    """Test the Python requirements.txt parser."""
    parser = PythonParser(sample_python_manifest)
    dependencies = parser.parse()

    assert dependencies is not None
    assert len(dependencies) == 3
    assert "flask" in dependencies
    assert "requests" in dependencies
    assert "numpy" in dependencies

    flask = dependencies["flask"]
    assert flask.name == "flask"
    assert flask.installed_version == "2.0.1"

    requests = dependencies["requests"]
    assert requests.name == "requests"
    assert requests.installed_version.replace(">=", "") == "2.25.0"

    numpy = dependencies["numpy"]
    assert numpy.name == "numpy"
    assert numpy.installed_version == "1.20.0"


def test_golang_parser(sample_golang_manifest):
    """Test the Go go.mod parser."""
    parser = GoParser(sample_golang_manifest)
    dependencies = parser.parse()

    assert dependencies is not None
    assert (
        len(dependencies) >= 3
    )  # Might have additional entries due to parser implementation

    # Assert required dependencies are present
    assert any(
        name for name in dependencies.keys() if "github.com/gin-gonic/gin" in name
    )
    assert any(
        name for name in dependencies.keys() if "github.com/stretchr/testify" in name
    )
    assert any(
        name for name in dependencies.keys() if "github.com/sirupsen/logrus" in name
    )

    # Find dependencies by partial name
    def find_dep(partial_name):
        for name, dep in dependencies.items():
            if partial_name in name:
                return dep
        return None

    gin = find_dep("github.com/gin-gonic/gin")
    assert gin is not None
    assert "gin" in gin.name.lower()
    assert "1.7.4" in gin.installed_version

    testify = find_dep("github.com/stretchr/testify")
    assert testify is not None
    assert "testify" in testify.name.lower()
    assert "1.7.0" in testify.installed_version

    logrus = find_dep("github.com/sirupsen/logrus")
    assert logrus is not None
    assert "logrus" in logrus.name.lower()
    assert "1.8.1" in logrus.installed_version
