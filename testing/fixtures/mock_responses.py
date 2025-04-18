"""Mock HTTP responses for testing."""

import json
from typing import Dict, List, Optional, Union

# GitHub API mock responses
GITHUB_SECURITY_POLICY_RESPONSE = {
    "url": "https://api.github.com/repos/owner/repo/community/profile",
    "health_percentage": 85,
    "description": "Sample repository",
    "documentation": None,
    "files": {
        "code_of_conduct": None,
        "contributing": None,
        "license": {
            "key": "mit",
            "name": "MIT License",
            "url": "https://api.github.com/licenses/mit",
        },
        "readme": {
            "url": "https://api.github.com/repos/owner/repo/readme",
        },
        "security": {
            "url": "https://api.github.com/repos/owner/repo/security/policy",
        },
    },
    "updated_at": "2023-07-01T12:00:00Z",
}

GITHUB_NO_SECURITY_POLICY_RESPONSE = {
    "url": "https://api.github.com/repos/owner/repo/community/profile",
    "health_percentage": 70,
    "description": "Sample repository without security policy",
    "documentation": None,
    "files": {
        "code_of_conduct": None,
        "contributing": None,
        "license": {
            "key": "mit",
            "name": "MIT License",
            "url": "https://api.github.com/licenses/mit",
        },
        "readme": {
            "url": "https://api.github.com/repos/owner/repo/readme",
        },
        "security": None,
    },
    "updated_at": "2023-07-01T12:00:00Z",
}

# NPM vulnerability data mock
NPM_VULN_RESPONSE = {
    "name": "lodash",
    "vulnerabilities": [
        {
            "id": "CVE-2021-23337",
            "title": "Prototype Pollution",
            "severity": "high",
            "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9",
            "affected_versions": "<=4.17.20",
            "patched_versions": ">=4.17.21",
        }
    ]
}

# PyPI vulnerability data mock
PYPI_VULN_RESPONSE = {
    "name": "flask",
    "vulnerabilities": [
        {
            "id": "CVE-2023-12345",
            "title": "XSS in Flask templates",
            "severity": "medium",
            "url": "https://github.com/advisories/sample-12345",
            "affected_versions": "<2.0.0",
            "patched_versions": ">=2.0.0",
        }
    ]
}

# Go vulnerability data mock
GO_VULN_RESPONSE = {
    "name": "github.com/gin-gonic/gin",
    "vulnerabilities": [
        {
            "id": "CVE-2023-67890",
            "title": "Path traversal in Gin",
            "severity": "medium",
            "url": "https://github.com/advisories/sample-67890",
            "affected_versions": "<1.7.0",
            "patched_versions": ">=1.7.0",
        }
    ]
}

def get_mock_response(dependency_name: str) -> Dict:
    """Get mock vulnerability data for a dependency.
    
    Args:
        dependency_name: Name of the dependency
        
    Returns:
        Mock vulnerability data
    """
    if dependency_name == "lodash":
        return NPM_VULN_RESPONSE
    elif dependency_name == "flask":
        return PYPI_VULN_RESPONSE
    elif dependency_name == "github.com/gin-gonic/gin":
        return GO_VULN_RESPONSE
    else:
        return {"name": dependency_name, "vulnerabilities": []}