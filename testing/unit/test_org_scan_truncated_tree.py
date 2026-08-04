"""A repository the scan saw a prefix of must not report complete coverage.

GitHub caps the recursive git-tree response and sets `"truncated": true` when
it does. `GitHubOrgClient.list_manifest_paths` noticed, wrote a `logger.warning`
and returned the partial listing as though it were the whole thing. Nothing
downstream knew: whatever manifests happened to fall inside the returned prefix
were read, and the repository was reported as `coverage: read` — which #262
defines as "every recognized manifest was fetched and parsed, so a zero here is
a real zero". That is exactly the claim a truncated scan cannot make (#266).

Reproduced before the fix on a real account. `torvalds/linux` returns 71,798
entries with `truncated: true`; one `requirements.txt` fell inside the prefix:

    WARNING  Git tree for torvalds/linux is truncated       github.py:279
    torvalds/linux -> read   3 dependencies
    "warnings": []

A warning that reaches only the log is the same shape as the discovery warnings
#262 found being appended to a local list and dropped: real, correct, and
invisible to every consumer of the report.
"""

from typing import Dict, List, Optional, cast

from org_tree_fixture import tree_client

from dependency_risk_profiler.models import (
    DependencyMetadata,
    DependencyRiskScore,
    RiskLevel,
)
from dependency_risk_profiler.org_scan.models import (
    DependencyKey,
    DependencyProfiler,
    OrgScanReport,
    RepositoryCoverage,
    RepositoryManifestListing,
    RepositoryRef,
)
from dependency_risk_profiler.org_scan.report import (
    render_html_report,
    render_terminal_summary,
    report_to_dict,
)
from dependency_risk_profiler.org_scan.scanner import (
    GitHubDiscoveryClient,
    OrgScanOptions,
    OrgScanRunner,
)

#: Two repositories with identical manifests. Only the tree listing differs, so
#: nothing but truncation can explain a difference in their reported coverage.
_TREES: Dict[str, Dict[str, str]] = {
    "acme/monorepo": {"requirements.txt": "jinja2==3.1.6\n"},
    "acme/small": {"requirements.txt": "jinja2==3.1.6\n"},
    # Truncated, and nothing recognizable inside the prefix. Before the fix
    # this was `no_manifests`: "the tree listed and holds no manifest this tool
    # recognizes", asserted about a tree the scan saw part of.
    "acme/huge-and-empty-looking": {"README.md": "# huge\n"},
    # Truncated, and the prefix holds a manifest the tool cannot read. The
    # per-manifest fact stays in `unreadable_manifests[]`; the repository state
    # names the stronger limitation.
    "acme/huge-and-unreadable": {"package.json": '{"dependencies": {}}'},
}

_TRUNCATED = [
    "acme/monorepo",
    "acme/huge-and-empty-looking",
    "acme/huge-and-unreadable",
]


def _repo(full_name: str) -> RepositoryRef:
    """Build a repository ref for a fixture tree."""
    return RepositoryRef(
        full_name=full_name,
        name=full_name.split("/")[-1],
        default_branch="main",
        html_url=f"https://github.com/{full_name}",
        archived=False,
        fork=False,
    )


class _TruncatingClient(GitHubDiscoveryClient):
    """Offline client whose listings come from the production classifier."""

    def __init__(
        self,
        repositories: Optional[List[str]] = None,
        truncated: Optional[List[str]] = None,
    ) -> None:
        """Serve ``repositories``, truncating the trees named in ``truncated``."""
        self.repositories = list(_TREES) if repositories is None else repositories
        self._client = tree_client(
            {name: list(_TREES[name]) for name in self.repositories},
            _TRUNCATED if truncated is None else truncated,
        )

    def list_org_repositories(
        self,
        org: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return every fixture repository."""
        return [_repo(name) for name in self.repositories]

    def list_user_repositories(
        self,
        user: str,
        include_archived: bool = False,
        max_repos: Optional[int] = None,
    ) -> List[RepositoryRef]:
        """Return every fixture repository."""
        return self.list_org_repositories(user, include_archived, max_repos)

    def list_manifest_paths(
        self,
        repo: RepositoryRef,
    ) -> RepositoryManifestListing:
        """Classify one fixture tree through the production client."""
        return self._client.list_manifest_paths(repo)

    def fetch_manifest_content(self, repo: RepositoryRef, path: str) -> str:
        """Return one fixture manifest body."""
        return _TREES[repo.full_name][path]


class _LowProfiler(DependencyProfiler):
    """Score every dependency LOW, with no network."""

    def profile(
        self, dependencies: Dict[DependencyKey, DependencyMetadata]
    ) -> Dict[DependencyKey, DependencyRiskScore]:
        """Return a deterministic low score per dependency."""
        return {
            key: DependencyRiskScore(
                dependency=dependency,
                total_score=1.0,
                risk_level=RiskLevel.LOW,
            )
            for key, dependency in dependencies.items()
        }


def _run() -> OrgScanReport:
    """Run one offline org scan over the fixture account."""
    return OrgScanRunner(_TruncatingClient(), _LowProfiler()).run(
        OrgScanOptions(org="acme")
    )


def _coverage(report: OrgScanReport) -> Dict[str, RepositoryCoverage]:
    """Index a report's repository coverage states by repository name."""
    return {repo.repo_full_name: repo.coverage for repo in report.riskiest_repositories}


def test_the_client_reports_whether_the_tree_was_truncated() -> None:
    """HYPOTHESIS (#266 acceptance criteria 1 and 4): the fact leaves the client.

    Driven through the real ``GitHubOrgClient`` over a tree document carrying
    ``"truncated": true``, because the client is where the fact was being
    dropped. A scanner test against a fixture that sets the flag itself would
    pass with the client still discarding it.
    """
    truncated = tree_client({"acme/monorepo": ["requirements.txt"]}, ["acme/monorepo"])
    whole = tree_client({"acme/small": ["requirements.txt"]})

    partial_listing = truncated.list_manifest_paths(_repo("acme/monorepo"))
    whole_listing = whole.list_manifest_paths(_repo("acme/small"))

    assert partial_listing.truncated is True
    assert whole_listing.truncated is False
    # The prefix's own contents are still reported: this is not "we saw
    # nothing", it is "we saw this much and cannot say how much there was".
    assert partial_listing.supported == ["requirements.txt"]


def test_a_truncated_tree_cannot_report_complete_coverage() -> None:
    """HYPOTHESIS (#266 acceptance criterion 2): `read` is unavailable here.

    ``acme/monorepo`` and ``acme/small`` hold the same manifest and produce the
    same dependency. The only difference between them is that GitHub truncated
    one tree, and that difference has to be visible in the output or the two
    repositories are indistinguishable — which is the defect.
    """
    report = _run()
    coverage = _coverage(report)

    assert coverage["acme/monorepo"] is RepositoryCoverage.PARTIALLY_LISTED
    assert coverage["acme/small"] is RepositoryCoverage.READ

    counts = {
        summary.repo_full_name: summary.dependency_count
        for summary in report.riskiest_repositories
    }
    assert counts["acme/monorepo"] == counts["acme/small"] == 1
    assert not coverage["acme/monorepo"].is_complete
    assert coverage["acme/small"].is_complete


def test_a_truncated_tree_is_never_reported_as_holding_no_manifests() -> None:
    """INVARIANT: `no_manifests` is a claim about a complete listing.

    "The tree listed and holds no manifest this tool recognizes" is the most
    confident of the five states, and a prefix cannot support it.
    """
    coverage = _coverage(_run())

    assert coverage["acme/huge-and-empty-looking"] is (
        RepositoryCoverage.PARTIALLY_LISTED
    )


def test_truncation_outranks_the_per_manifest_states_without_hiding_them() -> None:
    """DECISION (#266 acceptance criterion 2): one predicate, no lost facts.

    ``partially_read`` means "one ecosystem read and another not", and it names
    every manifest it did not read, each with a remedy. Truncation is a
    different fact: the unread manifests have no names, because they were never
    listed, and no command the user runs will produce them. So it gets its own
    state rather than borrowing that one.

    It outranks the states below it so that "this repository's dependency list
    is a prefix" is a single comparison. Nothing is lost to that ranking: the
    per-manifest entry is still in ``unreadable_manifests[]``.
    """
    report = _run()

    assert (
        _coverage(report)["acme/huge-and-unreadable"]
        is RepositoryCoverage.PARTIALLY_LISTED
    )
    assert ("acme/huge-and-unreadable", "package.json") in {
        (entry.repo_full_name, entry.path) for entry in report.unreadable_manifests
    }


def test_the_reason_reaches_the_json_and_not_only_the_log() -> None:
    """HYPOTHESIS (#266 acceptance criterion 3): a consumer can branch on it.

    Two carriers, on purpose: a count a consumer can test without parsing
    prose, and a per-repository state naming which ones. The warning text is
    there too, but a consumer should never have to read English to find this.
    """
    report = _run()
    document = report_to_dict(report)

    assert document["partially_listed_repository_count"] == 3

    repositories = cast(List[Dict[str, object]], document["riskiest_repositories"])
    states = {repo["repo"]: repo["coverage"] for repo in repositories}
    assert states["acme/monorepo"] == "partially_listed"
    assert states["acme/small"] == "read"

    warnings = cast(List[str], document["warnings"])
    assert any(
        "acme/monorepo" in warning and "truncated" in warning for warning in warnings
    )


def test_the_headline_and_both_renderers_say_the_list_is_a_prefix() -> None:
    """INVARIANT: the terminal and the HTML report state it, not just the JSON.

    The #262 precedent: a coverage gap that only a JSON consumer can see is one
    the person running the scan never sees.
    """
    report = _run()

    assert "3 repos listed only in part" in report.headline

    terminal = render_terminal_summary(report)
    assert "Repositories listed only in part: 3" in terminal
    assert "acme/monorepo" in terminal

    html = render_html_report(report)
    assert "truncated the git tree" in html


def test_an_untruncated_account_says_nothing_about_truncation() -> None:
    """INVARIANT: no crying wolf. A complete listing produces no caveat."""
    client = _TruncatingClient(repositories=["acme/small"], truncated=[])

    report = OrgScanRunner(client, _LowProfiler()).run(OrgScanOptions(org="acme"))

    assert report_to_dict(report)["partially_listed_repository_count"] == 0
    assert "listed only in part" not in report.headline
    assert "listed only in part" not in render_terminal_summary(report)
    assert all("truncated" not in warning for warning in report.warnings)
