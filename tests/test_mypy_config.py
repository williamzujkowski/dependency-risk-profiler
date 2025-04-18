"""Tests for the mypy configuration.

These tests ensure that our mypy configuration correctly ignores certain modules
and validates type annotations in others.
"""

import subprocess
import sys
from pathlib import Path
import pytest


def test_mypy_config_validation():
    """Test that the mypy configuration file is valid."""
    # Get the root directory
    root_dir = Path(__file__).parent.parent
    mypy_config_path = root_dir / "mypy.ini"
    
    # Verify the config file exists
    assert mypy_config_path.exists(), "mypy.ini file should exist"
    
    # Run mypy to validate the config
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", str(mypy_config_path), "--no-error-summary"],
        capture_output=True,
        text=True,
    )
    
    # The config should be valid, even if there are type errors
    assert result.returncode != 3, f"mypy config is invalid: {result.stderr}"


def test_mypy_ignores_are_effective():
    """Test that ignored modules are actually ignored by mypy."""
    # Get the root directory
    root_dir = Path(__file__).parent.parent
    mypy_config_path = root_dir / "mypy.ini"
    src_dir = root_dir / "src"
    
    # List of modules (and their files) that should be ignored
    ignored_modules = [
        ("dependency_risk_profiler.config", "config.py"),
        ("dependency_risk_profiler.vulnerabilities", "vulnerabilities/aggregator.py"),
        ("dependency_risk_profiler.transitive", "transitive/analyzer.py"),
        ("dependency_risk_profiler.supply_chain", "supply_chain/graph.py"),
        ("dependency_risk_profiler.scorecard", "scorecard/security_policy.py"),
        ("dependency_risk_profiler.scoring", "scoring/risk_scorer.py"),
        ("dependency_risk_profiler.parsers", "parsers/base.py"),
        ("dependency_risk_profiler.analyzers", "analyzers/golang.py"),
        ("dependency_risk_profiler.community", "community/analyzer.py"),
        ("dependency_risk_profiler.cli", "cli/typer_cli.py"),
        ("dependency_risk_profiler.secure_release", "secure_release/code_signing.py"),
    ]
    
    for module, file_path in ignored_modules:
        # Run mypy on an actual file in the module to verify it's ignored
        full_path = src_dir / "dependency_risk_profiler" / file_path
        if not full_path.exists():
            pytest.skip(f"File {full_path} does not exist, skipping test for {module}")
            
        result = subprocess.run(
            [
                sys.executable, 
                "-m", 
                "mypy", 
                "--config-file", 
                str(mypy_config_path), 
                "--no-error-summary",
                str(full_path),
            ],
            capture_output=True,
            text=True,
        )
        
        # For ignored modules, we should get return code 0 (success) even if they have errors
        assert result.returncode == 0, f"Module {module} should be ignored by mypy, error: {result.stderr}"


@pytest.mark.skip(reason="This test is only run manually when we want to enforce type annotations")
def test_non_ignored_modules_have_valid_types():
    """Test that non-ignored modules have valid type annotations.
    
    This test is skipped by default as it's meant to be run manually when we're ready
    to enforce type annotations in specific modules.
    """
    # Get the root directory
    root_dir = Path(__file__).parent.parent
    mypy_config_path = root_dir / "mypy.ini"
    
    # List of modules that should NOT be ignored
    non_ignored_modules = [
        "dependency_risk_profiler.models",
    ]
    
    for module in non_ignored_modules:
        # Run mypy on just this module to verify it has valid types
        result = subprocess.run(
            [
                sys.executable, 
                "-m", 
                "mypy", 
                "--config-file", 
                str(mypy_config_path), 
                "--no-error-summary",
                f"src/{module.replace('.', '/')}",
            ],
            capture_output=True,
            text=True,
        )
        
        # For non-ignored modules, we should get return code 0 (success)
        assert result.returncode == 0, f"Module {module} should have valid type annotations"