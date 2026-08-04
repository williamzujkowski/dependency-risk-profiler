"""``scan-org`` must produce identical bytes for identical input (#207).

The org repository summary averages a float over the dependencies in a
repository. Those dependencies used to be read out of a ``set``, whose
iteration order for strings varies with ``PYTHONHASHSEED`` — randomised per
process by CPython — and float addition is not associative. So the same scan of
the same input reported a different ``average_risk_score`` from one run to the
next: a last-bit difference, but a real one, in a number the tool publishes.

That defeats byte-comparison of two reports, which is exactly what #205 needed
to prove its v1 compatibility guarantee and could only get by pinning
``PYTHONHASHSEED=0``. It also breaks scan-to-scan diffing, which is a plausible
way to use this tool: "what changed since last week" is worthless if a number
moves when nothing changed.

This module asserts the property the way the issue asks for it — by varying the
seed across child processes and comparing bytes — rather than by reading the
code and concluding it looks fine. Running the module as a script prints the
documents; the test runs that script once per seed.

One caveat, stated rather than left for the next reader to rediscover: CPython
3.12 gave ``sum()`` Neumaier compensation, so on 3.12 the fixture below sums to
the same float in every order and the sweep passes even on the unfixed code.
It fails on 3.9-3.11, which are three of the four jobs in the CI matrix.
:func:`test_the_seed_sweep_is_not_decorative` pins the fixture's
order-sensitivity under plain accumulation so the sweep cannot quietly become
vacuous everywhere.
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.report import report_to_dict
from dependency_risk_profiler.org_scan.report_v1 import report_to_dict_v1
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)

#: Enough dependencies in one repository that their order matters, with scores
#: whose low bits do not cancel. A tidier fixture (0.5, 1.0, 1.5, …) would sum
#: identically in every order and make this whole module decorative.
_NAMES = (
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliett",
    "kilo",
    "lima",
)
_SCORES = {
    name: 0.1 + index * 0.17 + index * index * 0.013
    for index, name in enumerate(_NAMES)
}

#: An order the set actually produced, observed under ``PYTHONHASHSEED=1``
#: against the unfixed code. Recorded so the order-sensitivity guard below does
#: not depend on stumbling onto a differing permutation by chance.
_OBSERVED_SET_ORDER = (
    "alpha",
    "golf",
    "juliett",
    "india",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "kilo",
    "lima",
    "foxtrot",
    "hotel",
)

#: Seeds to run the scan under. ``0`` disables hash randomisation outright and
#: the rest select different orders; 0 and 1 alone disagreed before the fix.
_SEEDS = ("0", "1", "2", "3", "4", "5")

#: Pinned, so the only thing that can differ between two runs is arithmetic.
_GENERATED_AT = datetime(2020, 1, 1, 0, 0, 0)


class _FixtureGitHubClient(GitHubDiscoveryClient):
    """One repository declaring every fixture dependency, offline."""

    def __init__(self) -> None:
        """Build the single-repository fixture."""
        self._repo = RepositoryRef(
            full_name="acme/api",
            name="api",
            default_branch="main",
            html_url="https://github.com/acme/api",
            archived=False,
            fork=False,
        )
        self._manifest = "".join(f"{name}==1.0\n" for name in _NAMES)

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return the fixture repository."""
        return [self._repo]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
        include_collaborations: bool = False,
    ) -> List[RepositoryRef]:
        """Return the fixture repository."""
        return [self._repo]

    def list_manifest_paths(
        self, repo: RepositoryRef, supported_names: Iterable[str]
    ) -> RepositoryManifestListing:
        """Return the single fixture manifest path."""
        return RepositoryManifestListing(supported=["requirements.txt"], unreadable=[])

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return the fixture manifest body."""
        return self._manifest


class _FixtureProfiler(DependencyProfiler):
    """Scores every dependency from :data:`_SCORES`, with no network."""

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Return the pinned fixture score for each dependency."""
        return {
            key: DependencyRiskScore(
                dependency=metadata,
                total_score=_SCORES[key.name],
                risk_level=RiskLevel.MEDIUM,
            )
            for key, metadata in dependencies.items()
        }


def render_documents() -> str:
    """Render the v2 and v1 org-scan documents for the fixture account.

    Returns:
        Both documents concatenated, so one comparison covers both writers. v1
        is included because it is the frozen writer whose byte-stability #205
        could not verify without pinning the seed.
    """
    report = OrgScanRunner(_FixtureGitHubClient(), _FixtureProfiler()).run(
        OrgScanOptions(org="acme")
    )
    report.generated_at = _GENERATED_AT
    return "\n".join(
        [
            json.dumps(report_to_dict(report), indent=2),
            json.dumps(report_to_dict_v1(report), indent=2),
        ]
    )


def _accumulate(values: Iterator[float]) -> float:
    """Add left to right, without compensation.

    ``sum()`` cannot be used here: CPython 3.12 compensates it, which is
    precisely the interpreter detail this guard must not depend on.

    Args:
        values: The values to add, in the order to add them.

    Returns:
        The running total.
    """
    total = 0.0
    for value in values:
        total += value
    return total


def _render_under_seed(seed: str) -> bytes:
    """Run this module as a script in a child process under a given hash seed.

    A child process is the only honest way to vary ``PYTHONHASHSEED``: CPython
    reads it once, at interpreter start, so setting it inside the test would
    change nothing.

    Args:
        seed: The ``PYTHONHASHSEED`` value for the child.

    Returns:
        The child's stdout.
    """
    environment = dict(os.environ)
    environment["PYTHONHASHSEED"] = seed
    completed = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        capture_output=True,
        check=True,
        env=environment,
        shell=False,
    )
    return completed.stdout


def test_scan_org_output_is_byte_identical_across_hash_seeds() -> None:
    """ACCEPTANCE (#207): identical input, different seeds, identical bytes.

    Asserted by varying the seed for real, not by inspection. Before the fix
    this produced two distinct documents across these six seeds on 3.9-3.11.
    """
    documents = {seed: _render_under_seed(seed) for seed in _SEEDS}

    distinct = set(documents.values())
    assert len(distinct) == 1, (
        f"scan-org produced {len(distinct)} different documents from identical "
        f"input across PYTHONHASHSEED values {', '.join(_SEEDS)}. A float "
        "aggregate is being accumulated over an unordered collection "
        "somewhere; sort it."
    )


def test_the_seed_sweep_is_not_decorative() -> None:
    """GUARD: the sweep above only proves something if order changes the sum.

    If the fixture scores added up to the same float in every order, the sweep
    would pass on the broken code too and guard nothing at all. These are the
    two orders that mattered: sorted, which the fix now imposes, and the one
    the set produced under ``PYTHONHASHSEED=1``.
    """
    sorted_order = _accumulate(_SCORES[name] for name in sorted(_NAMES))
    observed_order = _accumulate(_SCORES[name] for name in _OBSERVED_SET_ORDER)

    assert sorted(_OBSERVED_SET_ORDER) == sorted(_NAMES)
    assert sorted_order != observed_order


if __name__ == "__main__":
    print(render_documents())
