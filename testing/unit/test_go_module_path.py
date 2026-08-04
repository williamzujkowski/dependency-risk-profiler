"""Go module path -> source repository resolution (#130).

Table-driven over the four module-path forms a real ``go.mod`` contains, plus
the resolution-failure case. No live network: vanity lookups are served by an
injected fetcher.
"""

from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler.analyzers import golang
from dependency_risk_profiler.analyzers.golang import GoAnalyzer
from dependency_risk_profiler.go_modules import (
    GoModuleResolver,
    ModuleRepository,
    _is_public_host,
    _validated_repo_root,
)
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.release_dates import (
    SOURCE_REPOSITORY_KEY,
    SOURCE_REPOSITORY_UNUSABLE,
)
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer


def _meta(prefix: str, repo_root: str) -> str:
    """Return a minimal vanity page carrying one go-import meta tag."""
    return (
        "<html><head>"
        f'<meta name="go-import" content="{prefix} git {repo_root}">'
        "</head><body>redirecting...</body></html>"
    )


# The vanity pages these module paths actually serve, keyed by request URL.
VANITY_PAGES: Dict[str, str] = {
    "https://go.uber.org/automaxprocs?go-get=1": _meta(
        "go.uber.org/automaxprocs", "https://github.com/uber-go/automaxprocs"
    ),
    "https://cloud.google.com/go/storage?go-get=1": _meta(
        "cloud.google.com/go", "https://github.com/googleapis/google-cloud-go"
    ),
    "https://cloud.google.com/go/iam?go-get=1": _meta(
        "cloud.google.com/go", "https://github.com/googleapis/google-cloud-go"
    ),
    "https://howett.net/plist?go-get=1": _meta(
        "howett.net/plist", "https://github.com/DHowett/go-plist.git"
    ),
    "https://software.sslmate.com/src/go-pkcs12?go-get=1": _meta(
        "software.sslmate.com/src/go-pkcs12",
        "https://software.sslmate.com/src/go-pkcs12.git",
    ),
}


class RecordingFetcher:
    """Serves canned vanity pages and records every URL requested."""

    def __init__(self, pages: Optional[Dict[str, str]] = None) -> None:
        """Store the page table and start with an empty request log."""
        self.pages = VANITY_PAGES if pages is None else pages
        self.requests: List[str] = []

    def __call__(self, url: str) -> Optional[str]:
        """Return the canned page for a URL, or None when there is none."""
        self.requests.append(url)
        return self.pages.get(url)


# (module path, expected repository URL, expected subdirectory)
RESOLUTION_CASES: List[Tuple[str, str, str]] = [
    # Plain github.com/owner/repo — the only form that worked before #130.
    ("github.com/spf13/cobra", "https://github.com/spf13/cobra", ""),
    # Major-version suffix: /vN is part of the module path, not the repo path.
    ("github.com/cespare/xxhash/v2", "https://github.com/cespare/xxhash", ""),
    ("github.com/alecthomas/chroma/v2", "https://github.com/alecthomas/chroma", ""),
    ("gitlab.com/group/project/v10", "https://gitlab.com/group/project", ""),
    # Subdirectory module: one repository, many modules.
    (
        "github.com/aws/aws-sdk-go-v2/service/cloudfront",
        "https://github.com/aws/aws-sdk-go-v2",
        "service/cloudfront",
    ),
    ("bitbucket.org/team/repo/sub", "https://bitbucket.org/team/repo", "sub"),
    # Both at once: subdirectory module that is itself at v2.
    (
        "github.com/aws/aws-sdk-go-v2/config/v2",
        "https://github.com/aws/aws-sdk-go-v2",
        "config",
    ),
    # golang.org/x mirror: static rule, no network.
    ("golang.org/x/net", "https://github.com/golang/net", ""),
    ("golang.org/x/tools", "https://github.com/golang/tools", ""),
    ("golang.org/x/exp/slices", "https://github.com/golang/exp", "slices"),
    # Vanity import path: resolved from the go-import meta tag.
    (
        "go.uber.org/automaxprocs",
        "https://github.com/uber-go/automaxprocs",
        "",
    ),
    (
        "cloud.google.com/go/storage",
        "https://github.com/googleapis/google-cloud-go",
        "storage",
    ),
    # A vanity repository root may carry a .git suffix.
    ("howett.net/plist", "https://github.com/DHowett/go-plist", ""),
]


@pytest.mark.parametrize("module_path, repo_url, subdirectory", RESOLUTION_CASES)
def test_module_path_resolves_to_repository(
    module_path: str, repo_url: str, subdirectory: str
) -> None:
    """Every documented module-path form maps to its repository."""
    resolver = GoModuleResolver(fetch=RecordingFetcher())

    assert resolver.resolve(module_path) == ModuleRepository(repo_url, subdirectory)


# Module paths that must NOT resolve, and must not fabricate a repository.
FAILURE_CASES: List[str] = [
    # Vanity host that serves no go-import meta tag.
    "example.invalid/does/not/exist",
    # Well-formed but too short to name a repository.
    "github.com/orphan",
    # Empty and whitespace-only input.
    "",
    "   ",
]


@pytest.mark.parametrize("module_path", FAILURE_CASES)
def test_unresolvable_module_stays_unresolved(module_path: str) -> None:
    """Resolution failure returns None so signals stay honestly unmeasured."""
    resolver = GoModuleResolver(fetch=RecordingFetcher())

    assert resolver.resolve(module_path) is None


def test_short_code_host_path_is_not_treated_as_a_vanity_path() -> None:
    """A code host is never fetched as a vanity path, however short the rest."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    assert resolver.resolve("github.com/orphan") is None
    assert resolver.resolve("gitlab.com") is None

    assert fetcher.requests == []


def test_static_and_code_host_rules_make_no_network_calls() -> None:
    """Rules 1-3 resolve offline; only true vanity paths trigger a fetch."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    for module_path in (
        "github.com/spf13/cobra",
        "github.com/cespare/xxhash/v2",
        "github.com/aws/aws-sdk-go-v2/service/cloudfront",
        "golang.org/x/net",
    ):
        assert resolver.resolve(module_path) is not None

    assert fetcher.requests == []


def test_vanity_lookup_is_cached_by_import_prefix() -> None:
    """One lookup serves every module under the same import prefix."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    first = resolver.resolve("cloud.google.com/go/storage")
    second = resolver.resolve("cloud.google.com/go/iam")

    assert first == ModuleRepository(
        "https://github.com/googleapis/google-cloud-go", "storage"
    )
    assert second == ModuleRepository(
        "https://github.com/googleapis/google-cloud-go", "iam"
    )
    assert fetcher.requests == ["https://cloud.google.com/go/storage?go-get=1"]


def test_failed_vanity_lookup_is_cached_too() -> None:
    """A host that does not resolve is not re-fetched for every module."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    assert resolver.resolve("example.invalid/pkg") is None
    assert resolver.resolve("example.invalid/pkg") is None

    assert fetcher.requests == ["https://example.invalid/pkg?go-get=1"]


def test_repository_on_unsupported_host_is_recorded_not_invented() -> None:
    """A real repository we cannot clone is still named honestly."""
    resolver = GoModuleResolver(fetch=RecordingFetcher())

    resolved = resolver.resolve("software.sslmate.com/src/go-pkcs12")

    assert resolved == ModuleRepository(
        "https://software.sslmate.com/src/go-pkcs12.git"
    )


# Hostile or malformed go-import content that must be rejected outright.
HOSTILE_CONTENT: List[str] = [
    # Non-https schemes.
    '<meta name="go-import" content="evil.example/x git http://evil.example/x">',
    '<meta name="go-import" content="evil.example/x git file:///etc/passwd">',
    '<meta name="go-import" content="evil.example/x git ssh://git@evil.example/x">',
    # Credentials, explicit ports, and non-public hosts.
    '<meta name="go-import" content="evil.example/x git https://u:p@evil.example/x">',
    '<meta name="go-import" content="evil.example/x git https://evil.example:8080/x">',
    '<meta name="go-import" content="evil.example/x git https://localhost/x">',
    '<meta name="go-import" content="evil.example/x git https://127.0.0.1/x">',
    '<meta name="go-import" content="evil.example/x git https://169.254.169.254/x">',
    # An import prefix that does not cover the module path we asked about.
    '<meta name="go-import" content="other.example/y git https://github.com/o/y">',
    # A non-git VCS, a malformed field count, and no repository root at all.
    '<meta name="go-import" content="evil.example/x mod https://github.com/o/y">',
    '<meta name="go-import" content="evil.example/x https://github.com/o/y">',
    '<meta name="go-import" content="evil.example/x git https://github.com">',
    # A meta tag that is not go-import at all.
    '<meta name="go-source" content="evil.example/x git https://github.com/o/y">',
]


@pytest.mark.parametrize("markup", HOSTILE_CONTENT)
def test_untrusted_go_import_content_is_rejected(markup: str) -> None:
    """Only a well-formed, https, public-host git root is ever accepted."""
    pages = {"https://evil.example/x?go-get=1": f"<html><head>{markup}</head></html>"}
    resolver = GoModuleResolver(fetch=RecordingFetcher(pages))

    assert resolver.resolve("evil.example/x") is None


def test_go_get_lookup_is_not_aimed_at_private_hosts() -> None:
    """A hostile manifest cannot point the fetch at localhost or link-local."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    assert resolver.resolve("localhost/pkg") is None
    assert resolver.resolve("127.0.0.1/pkg") is None
    assert resolver.resolve("169.254.169.254/pkg") is None

    assert fetcher.requests == []


def test_module_path_cannot_smuggle_a_query_or_authority_into_the_url() -> None:
    """The requested URL is built from a percent-encoded module path."""
    fetcher = RecordingFetcher()
    resolver = GoModuleResolver(fetch=fetcher)

    assert resolver.resolve("vanity.example/x?a=b#f@evil.example/y") is None
    assert resolver.resolve("vanity.example/../../etc/passwd") is None

    assert fetcher.requests == [
        "https://vanity.example/x%3Fa%3Db%23f%40evil.example/y?go-get=1"
    ]


def test_repo_root_query_and_fragment_are_discarded() -> None:
    """Nothing an attacker appends to the URL survives validation."""
    assert _validated_repo_root("https://github.com/o/r?x=1#frag") == "github.com/o/r"


def test_public_host_classification() -> None:
    """Public names pass; IP literals outside the global range do not."""
    assert _is_public_host("github.com")
    assert _is_public_host("go.uber.org")
    assert not _is_public_host("localhost")
    assert not _is_public_host("nodots")
    assert not _is_public_host("10.0.0.1")
    assert not _is_public_host("::1")
    assert not _is_public_host(None)


def _analyzer(fetcher: RecordingFetcher) -> GoAnalyzer:
    """Return an analyzer that resolves offline and never clones."""
    analyzer = GoAnalyzer()
    analyzer.resolver = GoModuleResolver(fetch=fetcher)
    analyzer.clone_repos = False
    return analyzer


def test_analyzer_records_resolved_repository_and_subdirectory() -> None:
    """The analyzer stores the repository, not the module path, as the source."""
    dependencies = {
        name: DependencyMetadata(name=name, installed_version="v1.0.0")
        for name in (
            "golang.org/x/net",
            "github.com/cespare/xxhash/v2",
            "github.com/aws/aws-sdk-go-v2/service/cloudfront",
        )
    }
    analyzer = _analyzer(RecordingFetcher())
    with mock.patch.object(golang, "fetch_json", return_value=None):
        analyzed = analyzer.analyze(dependencies)

    assert analyzed["golang.org/x/net"].repository_url == (
        "https://github.com/golang/net"
    )
    assert analyzed["github.com/cespare/xxhash/v2"].repository_url == (
        "https://github.com/cespare/xxhash"
    )
    cloudfront = analyzed["github.com/aws/aws-sdk-go-v2/service/cloudfront"]
    assert cloudfront.repository_url == "https://github.com/aws/aws-sdk-go-v2"
    assert cloudfront.additional_info["module_subdirectory"] == "service/cloudfront"


def test_analyzer_leaves_unresolvable_modules_without_a_repository() -> None:
    """An unresolved module keeps no invented repository URL."""
    dependencies = {
        "example.invalid/pkg": DependencyMetadata(
            name="example.invalid/pkg", installed_version="v1.0.0"
        )
    }
    analyzer = _analyzer(RecordingFetcher())
    with mock.patch.object(golang, "fetch_json", return_value=None):
        analyzed = analyzer.analyze(dependencies)

    assert analyzed["example.invalid/pkg"].repository_url is None
    assert "module_subdirectory" not in analyzed["example.invalid/pkg"].additional_info


def test_a_module_on_a_non_forge_host_is_declared_but_unusable() -> None:
    """#176 for Go: the import path *is* the declaration, so nothing is undeclared.

    ``software.sslmate.com/src/go-pkcs12`` resolves to a real repository on a
    host this tool cannot clone or query — the same class as
    ``go.googlesource.com`` and the two Hugo dependencies #137 leaves honestly
    unmeasured. The module told us where its source lives. We cannot read it.
    That is not "declares no source repository", which is what it used to score.
    """
    name = "software.sslmate.com/src/go-pkcs12"
    analyzer = _analyzer(RecordingFetcher())
    with mock.patch.object(golang, "fetch_json", return_value=None):
        analyzed = analyzer.analyze(
            {name: DependencyMetadata(name=name, installed_version="v0.2.0")}
        )[name]

    assert analyzed.repository_url == "https://software.sslmate.com/src/go-pkcs12.git"
    assert analyzed.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNUSABLE
    assert RiskScorer().score_dependency(analyzed).source_repository_score == 0.75


def test_a_module_path_with_no_repository_in_it_is_declared_but_unusable() -> None:
    """A code-host path too short to name a repository still named something."""
    name = "github.com/orphan"
    analyzer = _analyzer(RecordingFetcher())
    with mock.patch.object(golang, "fetch_json", return_value=None):
        analyzed = analyzer.analyze(
            {name: DependencyMetadata(name=name, installed_version="v1.0.0")}
        )[name]

    assert analyzed.repository_url is None
    assert analyzed.additional_info[SOURCE_REPOSITORY_KEY] == SOURCE_REPOSITORY_UNUSABLE


def test_a_vanity_host_that_does_not_answer_leaves_the_signal_unmeasured() -> None:
    """#182's rule for Go: a host that never replied said nothing about the module.

    ``RecordingFetcher`` returns None for an unrecorded page, which is what the
    bounded ``?go-get=1`` fetch returns on a timeout, a non-200, or a body it
    refused. Recording UNDECLARED off that would be a finding about a lookup
    that did not happen.
    """
    name = "example.invalid/pkg"
    analyzer = _analyzer(RecordingFetcher())
    with mock.patch.object(golang, "fetch_json", return_value=None):
        analyzed = analyzer.analyze(
            {name: DependencyMetadata(name=name, installed_version="v1.0.0")}
        )[name]

    assert SOURCE_REPOSITORY_KEY not in analyzed.additional_info
    assert RiskScorer().score_dependency(analyzed).source_repository_score is None


def test_a_vanity_page_with_no_go_import_tag_is_an_answer_not_a_failure() -> None:
    """A host that replied and named nothing is measured; a silent host is not."""
    name = "vanity.example/pkg"
    fetcher = RecordingFetcher(
        {"https://vanity.example/pkg?go-get=1": "<html><head></head></html>"}
    )
    resolution = GoModuleResolver(fetch=fetcher).resolve_module(name)

    assert resolution.repository is None
    assert resolution.lookup_failed is False


def test_analyzer_clones_each_repository_once_for_all_its_modules() -> None:
    """Subdirectory modules share one clone instead of one clone apiece."""
    names = [
        "github.com/aws/aws-sdk-go-v2/service/cloudfront",
        "github.com/aws/aws-sdk-go-v2/service/s3",
        "github.com/spf13/cobra",
    ]
    dependencies = {
        name: DependencyMetadata(name=name, installed_version="v1.0.0")
        for name in names
    }
    analyzer = _analyzer(RecordingFetcher())
    analyzer.clone_repos = True

    cloned: List[str] = []

    @contextmanager
    def fake_clone(repo_url: str) -> Iterator[Optional[Tuple[str, str]]]:
        cloned.append(repo_url)
        yield ("/nonexistent/repo", "repo")

    with (
        mock.patch.object(golang, "fetch_json", return_value=None),
        mock.patch.object(golang, "cloned_repo", fake_clone),
        mock.patch.object(golang, "analyze_repository", side_effect=lambda dep, _: dep),
    ):
        analyzer.analyze(dependencies)

    assert sorted(cloned) == [
        "https://github.com/aws/aws-sdk-go-v2",
        "https://github.com/spf13/cobra",
    ]
