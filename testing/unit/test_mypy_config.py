"""Tests that keep the mypy gate honest.

Two things are enforced here:

1. Every module that is *not* on the ``ignore_errors`` exemption list in
   ``pyproject.toml`` must type-check cleanly. That is the real gate.
2. Every module that *is* still exempt has a recorded error count in
   :data:`MAX_ERRORS_PER_EXEMPT_MODULE`, and that count may never grow. The
   exemptions are debt being paid down, not a permanent licence.

There is deliberately no test asserting that an exempt module stays broken.
A module that starts type-checking cleanly should have its exemption deleted,
not be reported as a failure.
"""

import importlib.util
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import pytest

ROOT_DIR = Path(__file__).parent.parent.parent
PYPROJECT_PATH = ROOT_DIR / "pyproject.toml"

PACKAGE = "dependency_risk_profiler"

# Per-module ceiling for the modules still carrying `ignore_errors = true`.
# These numbers may only ever go DOWN. When a module reaches zero, delete its
# override from pyproject.toml and delete its entry here; the non-exempt test
# below then guards it permanently.
#
# Measured against the repo config with the first-party `ignore_errors`
# overrides stripped out (see `_strip_first_party_ignore_errors`).
MAX_ERRORS_PER_EXEMPT_MODULE: Dict[str, int] = {
    "analyzers": 3,
    "cli": 22,
    "config": 77,
    "parsers": 8,
    "scorecard": 45,
    "vulnerabilities": 16,
}

# `[[tool.mypy.overrides]]` blocks that switch off checking for our own code.
_FIRST_PARTY_IGNORE_BLOCK = re.compile(
    r"\[\[tool\.mypy\.overrides\]\]\n"
    r'module = "' + re.escape(PACKAGE) + r'(?:\.[^"]*)?"\n'
    r"ignore_errors = true\n\n?",
)

# `module = "dependency_risk_profiler.<module>[.*]"` followed by the mask.
_EXEMPT_MODULE = re.compile(
    r'module = "' + re.escape(PACKAGE) + r'\.(?P<module>[^".]+)[^"]*"\n'
    r"ignore_errors = true"
)

# `src/dependency_risk_profiler/<module>...:<line>: error: ...`
_ERROR_LINE = re.compile(
    r"^src/" + re.escape(PACKAGE) + r"/(?P<module>[^/.]+)[^:]*:\d+: error:"
)


def _exempt_modules() -> List[str]:
    """Return the top-level module names still masked in pyproject.toml."""
    text = PYPROJECT_PATH.read_text()
    return sorted({m.group("module") for m in _EXEMPT_MODULE.finditer(text)})


def _strip_first_party_ignore_errors(pyproject_text: str) -> str:
    """Return the config with our own `ignore_errors` masks removed.

    Third-party `ignore_missing_imports` overrides are left alone; the point is
    to see what our own code looks like when it is actually checked.
    """
    return _FIRST_PARTY_IGNORE_BLOCK.sub("", pyproject_text)


def _mypy_command() -> List[str]:
    """Locate a runnable mypy, preferring the one in the current interpreter.

    CI installs `.[dev]` into the same environment as pytest, so `-m mypy`
    works there. A local venv without the dev extra may only have mypy on
    PATH.
    """
    if importlib.util.find_spec("mypy") is not None:
        return [sys.executable, "-m", "mypy"]
    executable = shutil.which("mypy")
    if executable is not None:
        return [executable]
    pytest.skip("mypy is not installed; install the 'dev' extra to run the type gate")


def _run_mypy(config_path: Path, cache_dir: Optional[Path] = None) -> str:
    """Run mypy over `src` with the given config and return its stdout."""
    command = _mypy_command() + [
        "--config-file",
        str(config_path),
        "--no-error-summary",
    ]
    if cache_dir is not None:
        command += ["--cache-dir", str(cache_dir)]
    command.append("src")

    result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT_DIR)
    # 2 is a crash, 3 is a bad config. Type errors are 1.
    assert result.returncode not in (
        2,
        3,
    ), f"mypy failed to run (exit {result.returncode}): {result.stderr}"
    return result.stdout


def _errors_by_module(output: str) -> Counter:
    """Count mypy error lines per top-level module. Notes are not errors."""
    counts: Counter = Counter()
    for line in output.splitlines():
        match = _ERROR_LINE.match(line)
        if match:
            counts[match.group("module")] += 1
    return counts


def test_mypy_config_validation() -> None:
    """The mypy configuration in pyproject.toml parses."""
    assert PYPROJECT_PATH.exists(), "pyproject.toml file should exist"

    result = subprocess.run(
        _mypy_command() + ["--no-error-summary", "src"],
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
    )

    # Exit code 3 means the config itself is broken. Type errors are exit 1.
    assert result.returncode != 3, f"mypy config is invalid: {result.stderr}"


def test_non_exempt_modules_have_valid_types() -> None:
    """Every module not on the exemption list must type-check cleanly.

    This is the gate. It runs mypy with the repo's real configuration, so
    anything it reports comes from a module nobody exempted.
    """
    errors = [
        line for line in _run_mypy(PYPROJECT_PATH).splitlines() if ": error:" in line
    ]

    assert not errors, (
        "Modules outside the ignore_errors exemption list must type-check "
        "cleanly:\n" + "\n".join(errors)
    )


def test_exemption_list_and_ratchet_agree() -> None:
    """The ratchet table tracks exactly the modules still masked."""
    exempt = set(_exempt_modules())
    ratcheted = set(MAX_ERRORS_PER_EXEMPT_MODULE)

    assert exempt == ratcheted, (
        "MAX_ERRORS_PER_EXEMPT_MODULE is out of sync with pyproject.toml.\n"
        f"  masked but not ratcheted: {sorted(exempt - ratcheted)}\n"
        f"  ratcheted but not masked: {sorted(ratcheted - exempt)}"
    )


def test_exempt_module_error_counts_never_increase(tmp_path: Path) -> None:
    """Error counts in the still-masked modules may only go down.

    Strips our own `ignore_errors` overrides, re-runs mypy, and compares the
    per-module counts against the recorded ceilings. Counts coming in *under*
    the ceiling are fine and welcome; only growth fails.
    """
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(_strip_first_party_ignore_errors(PYPROJECT_PATH.read_text()))

    counts = _errors_by_module(_run_mypy(config_path, cache_dir=tmp_path / "cache"))

    regressions = [
        f"  {module}: {counts[module]} errors, ceiling is {ceiling}"
        for module, ceiling in sorted(MAX_ERRORS_PER_EXEMPT_MODULE.items())
        if counts[module] > ceiling
    ]
    assert not regressions, (
        "Type errors increased in modules still exempt from mypy. Fix the new "
        "errors rather than raising the ceiling:\n" + "\n".join(regressions)
    )
