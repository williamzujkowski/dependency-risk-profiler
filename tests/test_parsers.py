"""Tests for the dependency manifest parsers."""


from dependency_risk_profiler.parsers.base import BaseParser
from dependency_risk_profiler.parsers.nodejs import NodeJSParser
from dependency_risk_profiler.parsers.python import PythonParser
from dependency_risk_profiler.parsers.golang import GoParser


def test_base_parser_factory(
    sample_nodejs_manifest, sample_python_manifest, sample_golang_manifest
):
    """Test the base parser factory method."""
    # Test Node.js parser
    parser = BaseParser.get_parser_for_file(sample_nodejs_manifest)
    assert isinstance(parser, NodeJSParser)
    
    # Test Python parser
    parser = BaseParser.get_parser_for_file(sample_python_manifest)
    assert isinstance(parser, PythonParser)
    
    # Test Go parser
    parser = BaseParser.get_parser_for_file(sample_golang_manifest)
    assert isinstance(parser, GoParser)
    
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
    assert requests.installed_version == ">=2.25.0"
    
    numpy = dependencies["numpy"]
    assert numpy.name == "numpy"
    assert numpy.installed_version == "1.20.0"


def test_golang_parser(sample_golang_manifest):
    """Test the Go go.mod parser."""
    parser = GoParser(sample_golang_manifest)
    dependencies = parser.parse()
    
    assert dependencies is not None
    assert len(dependencies) == 3
    assert "github.com/gin-gonic/gin" in dependencies
    assert "github.com/stretchr/testify" in dependencies
    assert "github.com/sirupsen/logrus" in dependencies
    
    gin = dependencies["github.com/gin-gonic/gin"]
    assert gin.name == "github.com/gin-gonic/gin"
    assert gin.installed_version == "v1.7.4"
    
    testify = dependencies["github.com/stretchr/testify"]
    assert testify.name == "github.com/stretchr/testify"
    assert testify.installed_version == "v1.7.0"
    
    logrus = dependencies["github.com/sirupsen/logrus"]
    assert logrus.name == "github.com/sirupsen/logrus"
    assert logrus.installed_version == "v1.8.1"