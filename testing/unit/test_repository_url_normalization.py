"""Forge-agnostic URL normalisation and the one key-set per ecosystem (#290).

Two defects, one change, because they are the same defect seen from two sides:
the tool decided a repository was unreachable, and then reported that decision
as a fact about the *package's metadata* rather than about its own resolver.

* ``normalize_clone_url`` upgraded ``git://`` to https and refused plain
  ``http://``. A survey of 8,870 packages across eight ecosystems found 2.63%
  declaring their repository over ``http://`` — more than every non-GitHub
  forge combined, and 15.35% of RubyGems — and **114 of the 233 are on
  github.com**, a host the tool already supported. It also accepted exactly
  three hosts, silently dropped embedded credentials with
  ``netloc.split("@")[-1]``, and treated ``www.github.com`` as a second
  repository identity.
* ``_declared_source`` and ``_repository_url`` swept different key-sets, so a
  URL only the wider sweep could see resolved to nothing *and* recorded
  UNDECLARED — "declares no source repository", asserted about a package that
  declares one (#281).

Every case below is authored rather than captured, and deliberately so: these
are adversarial inputs (credentials, lookalike hosts, a Mercurial host on a
git forge's domain) that no cooperating registry will ever serve. The captured
side of this change is ``python/python3-openid`` and ``python/django-allauth``
in ``testing/fixtures/registry/``, replayed by the adapter-conformance harness.
"""

from typing import Callable, Dict, List, Optional, Tuple
from unittest import mock

import pytest

from dependency_risk_profiler.analyzers.composer import ComposerAnalyzer
from dependency_risk_profiler.analyzers.crates import CratesIOAnalyzer
from dependency_risk_profiler.analyzers.nodejs import NodeJSAnalyzer
from dependency_risk_profiler.analyzers.nuget import NuGetAnalyzer
from dependency_risk_profiler.analyzers.python import PythonAnalyzer
from dependency_risk_profiler.analyzers.ruby import RubyGemsAnalyzer
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.nuget_registry import NuspecDocument
from dependency_risk_profiler.release_dates import (
    RepositoryResolution,
    record_source_repository,
    resolve_repository,
)
from dependency_risk_profiler.signals import SourceRepositoryState
from dependency_risk_profiler.utils import (
    canonical_repository_url,
    is_cloneable_repo_url,
    normalize_clone_url,
    redact_credentials,
)

#: A URL on a host we clone from that carries no ``owner/repo`` pair. It is the
#: discriminator the middle state needs: we recognised a repository reference
#: and could not use it, which is a resolution failure and not silence.
UNUSABLE_FORGE_URL = "https://github.com/rails"

#: A URL that is not a repository reference at all. #176's case, and the one
#: that must stay UNDECLARED when it turns up under a fallback label.
NOT_A_FORGE_URL = "http://code.whytheluckystiff.net/hpricot/"

#: A URL that resolves.
GOOD_URL = "https://github.com/psf/requests"


# --- The normalisation table ------------------------------------------------
#
# One row per rule in #290's table, both directions where the direction is
# meaningful. ``None`` means the URL is refused and no clone is attempted.


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Unchanged from before #290 — pinned so the rewrite cannot lose them.
        ("git://github.com/debug-js/debug", "https://github.com/debug-js/debug"),
        ("git+https://github.com/foo/bar.git", "https://github.com/foo/bar.git"),
        ("git@github.com:owner/repo.git", "https://github.com/owner/repo.git"),
        ("ssh://git@github.com/owner/repo", "https://github.com/owner/repo"),
        ("https://github.com/a/b", "https://github.com/a/b"),
        ("https://gitlab.com/a/b", "https://gitlab.com/a/b"),
        ("https://bitbucket.org/a/b", "https://bitbucket.org/a/b"),
        ("https://evil.example.com/a/b", None),
        ("file:///etc/passwd", None),
        ("git://internal.host/secret", None),
        # THE #290 assertion: plain http:// is upgraded, not refused. Both of
        # these were None before, and 114 of the 233 http:// declarations in
        # the survey are exactly this shape — github.com, over http.
        (
            "http://github.com/necaris/python3-openid",
            "https://github.com/necaris/python3-openid",
        ),
        ("http://github.com/mikel/mail/", "https://github.com/mikel/mail/"),
        ("http://gitlab.com/a/b", "https://gitlab.com/a/b"),
        # ...and the upgrade is to https. Nothing anywhere returns an http URL,
        # because cloning an artifact over a channel an attacker can rewrite,
        # in order to score that artifact's supply-chain risk, measures the
        # attacker.
        ("http://github.com/a/b", "https://github.com/a/b"),
        # www. is stripped, in every casing. Before #290 the host came back
        # spelled two ways, which is two clone identities for one repository.
        ("https://www.github.com/x/y", "https://github.com/x/y"),
        ("https://WWW.github.com/x/y", "https://github.com/x/y"),
        ("http://www.github.com/x/y", "https://github.com/x/y"),
        # The host is lowercased, as it always was.
        ("https://GitHub.com/x/y", "https://github.com/x/y"),
        # Hosts widened to the six forges verified cloneable with
        # `git clone --depth 1 --no-tags`. All of these were None before.
        (
            "https://codeberg.org/allauth/django-allauth",
            "https://codeberg.org/allauth/django-allauth",
        ),
        ("https://gitea.com/gitea/tea", "https://gitea.com/gitea/tea"),
        ("https://git.sr.ht/~sircmpwn/hare", "https://git.sr.ht/~sircmpwn/hare"),
        ("https://gitee.com/oschina/git-osc", "https://gitee.com/oschina/git-osc"),
        (
            "git@codeberg.org:allauth/django-allauth.git",
            "https://codeberg.org/allauth/django-allauth.git",
        ),
        # Still refused, and each for its own reason. hg.sr.ht is SourceHut's
        # *Mercurial* service on the same domain: `git clone` cannot use it, so
        # widening to git.sr.ht must not widen to its sibling.
        ("https://hg.sr.ht/~icefox/oorandom", None),
        ("https://gitlab.gnome.org/GNOME/glib", None),
        ("https://salsa.debian.org/python-team/packages/foo", None),
        # Lookalikes, unchanged. A full parse, never a substring check.
        ("https://github.com.evil.example/a/b", None),
        ("https://evil.example/github.com/a/b", None),
        ("https://www.github.com.evil.example/a/b", None),
        # An explicit port is not port 443 and is not cloned.
        ("https://github.com:8443/a/b", None),
        # THE credential assertion. Every one of these was *accepted* before
        # #290 — ``netloc.split("@")[-1]`` threw the secret away and cloned the
        # repository, so the URL worked, the credential vanished, and nothing
        # recorded that either had happened.
        ("https://user:token@github.com/x/y", None),
        ("http://user:token@github.com/x/y", None),
        ("https://ghp_deadbeefdeadbeef@github.com/x/y", None),
        ("git+https://user:token@github.com/x/y.git", None),
        ("ssh://user:pass@github.com/x/y", None),
        # ...but the ssh login name is not a credential. It is dropped as part
        # of rewriting the scheme, which is what it has always been.
        ("ssh://git@codeberg.org/a/b", "https://codeberg.org/a/b"),
    ],
)
def test_normalize_clone_url(raw: str, expected: Optional[str]) -> None:
    """Every row of #290's normalisation table, asserted by value."""
    assert normalize_clone_url(raw) == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        # The #281 packages, by value. Both were None.
        (
            "http://github.com/necaris/python3-openid",
            "https://github.com/necaris/python3-openid",
        ),
        (
            "https://codeberg.org/allauth/django-allauth",
            "https://codeberg.org/allauth/django-allauth",
        ),
        # RubyGems' designated field, as four popular gems actually publish it.
        ("http://github.com/mikel/mail/", "https://github.com/mikel/mail"),
        ("http://github.com/sickill/rainbow", "https://github.com/sickill/rainbow"),
        ("http://github.com/rails/arel", "https://github.com/rails/arel"),
        ("http://github.com/rubychan/coderay", "https://github.com/rubychan/coderay"),
        # Deep paths on every forge trim to the same two segments. No per-forge
        # table: /tree, /-/tree, /src/branch and /tree/.../item are all views of
        # a repository, and the repository is its first two path segments.
        (
            "https://github.com/tzinfo/tzinfo/tree/v2.0.6",
            "https://github.com/tzinfo/tzinfo",
        ),
        ("https://gitlab.com/a/b/-/tree/v1", "https://gitlab.com/a/b"),
        (
            "https://codeberg.org/allauth/django-allauth/src/branch/main/setup.py",
            "https://codeberg.org/allauth/django-allauth",
        ),
        (
            "https://gitea.com/gitea/tea/src/branch/main/README.md",
            "https://gitea.com/gitea/tea",
        ),
        # SourceHut's owner carries a leading "~". It is part of the path and
        # survives verbatim; stripping it would name a different account.
        (
            "https://git.sr.ht/~sircmpwn/hare/tree/master/item/Makefile",
            "https://git.sr.ht/~sircmpwn/hare",
        ),
        ("https://git.sr.ht/~sircmpwn/hare", "https://git.sr.ht/~sircmpwn/hare"),
        # www. and .git and the trailing slash all come off, in combination.
        ("https://www.github.com/foo/bar.git/", "https://github.com/foo/bar"),
        # No owner/repo pair: a recognisable host is not a repository.
        ("https://github.com/rails", None),
        ("https://codeberg.org/allauth", None),
        # Credentials do not reach a canonical URL either.
        ("https://user:token@github.com/x/y", None),
    ],
)
def test_canonical_repository_url(raw: str, expected: Optional[str]) -> None:
    """Repository URLs trim to ``https://host/owner/repo``, on every forge."""
    assert canonical_repository_url(raw) == expected


# --- Credentials ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("https://user:token@github.com/x/y", "https://[redacted]@github.com/x/y"),
        ("http://user:token@github.com/x/y", "http://[redacted]@github.com/x/y"),
        ("https://ghp_secret@github.com/x/y", "https://[redacted]@github.com/x/y"),
        ("ssh://user:pass@github.com/x/y", "ssh://[redacted]@github.com/x/y"),
        ("git@github.com:owner/repo.git", "[redacted]@github.com:owner/repo.git"),
        # Nothing to redact is returned unchanged, byte for byte.
        ("https://github.com/x/y", "https://github.com/x/y"),
        ("not a url at all", "not a url at all"),
        (None, "<none>"),
        ("", "<none>"),
    ],
)
def test_redact_credentials(raw: Optional[str], expected: str) -> None:
    """A URL bound for a log line carries no userinfo."""
    assert redact_credentials(raw) == expected


def test_a_rejected_credential_url_is_never_written_to_a_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refusal must not be what writes the token to disk.

    This is the production path, not a helper: ``collect_repository_signals``
    logs the URL it is skipping, and the URLs it skips are exactly the ones
    normalisation just refused. Before the redaction the rejection itself
    leaked the secret at DEBUG.
    """
    from dependency_risk_profiler.analyzers.common import collect_repository_signals

    secret = "ghp_averyrealisticlookingtoken"
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")

    with caplog.at_level("DEBUG"):
        collect_repository_signals(
            dep, f"https://user:{secret}@github.com/acme/widget", clone_repos=True
        )

    assert caplog.records, "the skip must still be logged, just without the secret"
    combined = "\n".join(record.getMessage() for record in caplog.records)
    assert secret not in combined
    assert "user" not in combined
    assert "[redacted]" in combined


def test_a_credential_url_is_refused_before_git_is_invoked() -> None:
    """A URL carrying a credential never reaches ``git clone``."""
    from dependency_risk_profiler import utils

    with mock.patch.object(utils.subprocess, "run") as run:
        assert utils.clone_repo("https://user:token@github.com/acme/widget") is None
        run.assert_not_called()


# --- One sweep: UNDECLARED cannot be reached by a resolution failure ---------


def _state(resolution: RepositoryResolution) -> SourceRepositoryState:
    """Record a resolution on a fresh dependency and return the state."""
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    record_source_repository(dep, resolution)
    assert dep.source_repository_state is not None
    return dep.source_repository_state


def test_a_resolvable_candidate_is_declared_wherever_it_was_found() -> None:
    """Resolution wins over labelling: a repo under Homepage is still a repo."""
    assert _state(resolve_repository([GOOD_URL])) is SourceRepositoryState.DECLARED
    assert (
        _state(resolve_repository([], [GOOD_URL])) is SourceRepositoryState.DECLARED
    )
    # The #281 shape exactly: the repository is named only under fallback
    # labels, and over http. Both sweeps now see it, so it resolves.
    assert (
        _state(
            resolve_repository([], ["http://github.com/necaris/python3-openid"])
        )
        is SourceRepositoryState.DECLARED
    )


def test_a_resolution_failure_is_never_recorded_as_an_absent_declaration() -> None:
    """THE #290 assertion. A forge URL we could not use is UNUSABLE, not silence.

    Under two sweeps this was UNDECLARED: the resolver saw the URL, failed to
    canonicalize it, and the narrower declaration sweep never looked at the key
    at all — so the tool reported "declares no source repository" about a
    package that declared one. Both halves now come out of one traversal, so
    the state cannot disagree with what the resolver looked at.
    """
    assert (
        _state(resolve_repository([], [UNUSABLE_FORGE_URL]))
        is SourceRepositoryState.UNUSABLE
    )
    assert (
        _state(resolve_repository([UNUSABLE_FORGE_URL]))
        is SourceRepositoryState.UNUSABLE
    )


def test_a_fallback_that_is_not_a_repository_reference_stays_undeclared() -> None:
    """#176 is preserved: a docs homepage is not a declaration of source.

    The middle state is earned by naming a host this tool clones from, not by
    being a URL. "This might be a forge nobody has heard of" is a guess, and a
    guess recorded as a measurement is the class of defect this repository
    exists to avoid.
    """
    assert (
        _state(resolve_repository([], [NOT_A_FORGE_URL]))
        is SourceRepositoryState.UNDECLARED
    )
    assert (
        _state(resolve_repository([], ["https://gitlab.gnome.org/GNOME/glib"]))
        is SourceRepositoryState.UNDECLARED
    )
    assert _state(resolve_repository([], [])) is SourceRepositoryState.UNDECLARED
    assert _state(resolve_repository([None, ""], [None])) is (
        SourceRepositoryState.UNDECLARED
    )


def test_declarations_are_swept_before_fallbacks() -> None:
    """One traversal order, and the designated field goes first."""
    resolution = resolve_repository(
        [GOOD_URL], ["https://github.com/pallets/flask"]
    )
    assert resolution.url == GOOD_URL
    assert resolution.declared == GOOD_URL


def test_a_declaration_that_does_not_resolve_still_names_a_source() -> None:
    """A Subversion connection string is a statement about source (#176)."""
    resolution = resolve_repository(
        ["scm:svn:http://svn.apache.org/repos/asf/logging/log4j/tags/v1_2_17"]
    )
    assert resolution.url is None
    assert resolution.declared is not None
    assert _state(resolution) is SourceRepositoryState.UNUSABLE


def test_prepare_runs_before_canonicalization_and_never_over_the_declaration() -> None:
    """Maven's ``<scm>`` is not a URL; the raw text is still the declaration."""
    from dependency_risk_profiler.analyzers.maven import normalize_scm_url

    resolution = resolve_repository(
        ["scm:git:https://github.com/psf/requests.git"], prepare=normalize_scm_url
    )
    assert resolution.url == GOOD_URL
    assert resolution.declared == "scm:git:https://github.com/psf/requests.git"


# --- The same property, per ecosystem, through production code --------------
#
# The property above is about the shared sweep. This table is about each
# adapter actually using it: the point of the defect was that one ecosystem's
# declaration key-set was narrower than its own resolution key-set, and that is
# only observable by putting a URL in a real payload and running the adapter.
#
# Every case below drives the adapter's own ``analyze``/``_apply_registry_
# metadata`` with the network seam mocked. Nothing here reimplements a
# resolution: a fixture double that classified its own input is how five tests
# in this repository were green for the wrong reason.

#: Builds a registry payload for one ecosystem with a URL in the named slot.
PayloadBuilder = Callable[[Optional[str], Optional[str]], object]
#: Runs the adapter over that payload and returns the recorded state.
StateReader = Callable[[object], Optional[SourceRepositoryState]]


def _pypi(declared: Optional[str], fallback: Optional[str]) -> object:
    urls: Dict[str, str] = {}
    if declared:
        urls["Source"] = declared
    if fallback:
        urls["Homepage"] = fallback
    return {"info": {"name": "widget", "version": "1.0.0", "project_urls": urls}}


def _read_pypi(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    analyzer = PythonAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        PythonAnalyzer, "_get_pypi_package_info", return_value=payload
    ):
        analyzer.analyze({"widget": dep})
    return dep.source_repository_state


def _npm(declared: Optional[str], fallback: Optional[str]) -> object:
    payload: Dict[str, object] = {"dist-tags": {"latest": "1.0.0"}, "versions": {}}
    if declared:
        payload["repository"] = {"type": "git", "url": declared}
    if fallback:
        payload["homepage"] = fallback
    return payload


def _read_npm(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    analyzer = NodeJSAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        NodeJSAnalyzer, "_get_npm_package_info", return_value=payload
    ):
        analyzer.analyze({"widget": dep})
    return dep.source_repository_state


def _rubygems(declared: Optional[str], fallback: Optional[str]) -> object:
    payload: Dict[str, object] = {"name": "widget", "version": "1.0.0"}
    if declared:
        payload["source_code_uri"] = declared
    if fallback:
        payload["homepage_uri"] = fallback
    return payload


def _read_rubygems(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    analyzer = RubyGemsAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        RubyGemsAnalyzer, "_get_gem_info", return_value=payload
    ), mock.patch.object(RubyGemsAnalyzer, "_get_owner_count", return_value=None):
        analyzer.analyze({"widget": dep})
    return dep.source_repository_state


def _crates(declared: Optional[str], fallback: Optional[str]) -> object:
    crate: Dict[str, object] = {"name": "widget", "max_version": "1.0.0"}
    if declared:
        crate["repository"] = declared
    if fallback:
        crate["homepage"] = fallback
    return {"crate": crate, "versions": [{"num": "1.0.0"}]}


def _read_crates(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    analyzer = CratesIOAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        CratesIOAnalyzer, "_get_crate_info", return_value=payload
    ), mock.patch.object(CratesIOAnalyzer, "_get_owner_count", return_value=None):
        analyzer.analyze({"widget": dep})
    return dep.source_repository_state


def _packagist(declared: Optional[str], fallback: Optional[str]) -> object:
    release: Dict[str, object] = {"name": "acme/widget", "version": "1.0.0"}
    if declared:
        release["source"] = {"type": "git", "url": declared}
    if fallback:
        release["homepage"] = fallback
    return release


def _read_packagist(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="acme/widget", installed_version="1.0.0")
    analyzer = ComposerAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        ComposerAnalyzer, "_get_latest_release", return_value=payload
    ):
        analyzer.analyze({"acme/widget": dep})
    return dep.source_repository_state


def _nuspec(declared: Optional[str], fallback: Optional[str]) -> object:
    return NuspecDocument(
        package_id="Widget",
        version="1.0.0",
        repository_url=declared,
        project_url=fallback,
    )


def _read_nuget(payload: object) -> Optional[SourceRepositoryState]:
    dep = DependencyMetadata(name="Widget", installed_version="1.0.0")
    analyzer = NuGetAnalyzer()
    analyzer.clone_repos = False
    with mock.patch.object(
        NuGetAnalyzer, "_get_latest_version", return_value="1.0.0"
    ), mock.patch.object(
        NuGetAnalyzer, "_fetch_nuspec", return_value=payload
    ), mock.patch.object(
        analyzer.client, "fetch_catalog_entry", return_value=None
    ):
        analyzer.analyze({"Widget": dep})
    return dep.source_repository_state


#: (ecosystem, payload builder, adapter runner). Every ecosystem whose resolver
#: consults a field its declaration sweep did not, which is all of them except
#: golang (one candidate, the module path) and maven (covered by
#: ``test_prepare_runs_before_canonicalization_and_never_over_the_declaration``
#: and the captured POM cases).
ECOSYSTEM_SWEEPS: Tuple[Tuple[str, PayloadBuilder, StateReader], ...] = (
    ("python", _pypi, _read_pypi),
    ("nodejs", _npm, _read_npm),
    ("rubygems", _rubygems, _read_rubygems),
    ("cargo", _crates, _read_crates),
    ("composer", _packagist, _read_packagist),
    ("nuget", _nuspec, _read_nuget),
)


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_each_ecosystem_declares_everything_its_resolver_reads(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """A forge URL under a fallback label is UNUSABLE in every ecosystem.

    This is the per-ecosystem half of #290, and the one a shared-helper test
    cannot make: the defect was an adapter sweeping two different key-sets, so
    it only shows up when a real payload goes through a real adapter. Every
    one of these read UNDECLARED before the change.
    """
    assert read(build(None, UNUSABLE_FORGE_URL)) is SourceRepositoryState.UNUSABLE


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_each_ecosystem_resolves_a_repository_declared_over_http(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """The designated field, over http, on a supported host, resolves."""
    assert (
        read(build("http://github.com/necaris/python3-openid", None))
        is SourceRepositoryState.DECLARED
    )


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_each_ecosystem_keeps_a_non_forge_fallback_undeclared(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """#176's property survives per ecosystem: a docs homepage declares nothing."""
    assert read(build(None, NOT_A_FORGE_URL)) is SourceRepositoryState.UNDECLARED


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_each_ecosystem_records_silence_as_silence(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """A payload naming no source at all is the one route to UNDECLARED."""
    assert read(build(None, None)) is SourceRepositoryState.UNDECLARED


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_each_ecosystem_resolves_a_repository_on_a_widened_host(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """Codeberg is cloneable, so a package declaring it has declared a source."""
    assert (
        read(build("https://codeberg.org/allauth/django-allauth", None))
        is SourceRepositoryState.DECLARED
    )


@pytest.mark.parametrize(
    "ecosystem, build, read", ECOSYSTEM_SWEEPS, ids=[s[0] for s in ECOSYSTEM_SWEEPS]
)
def test_no_ecosystem_promotes_a_credential_url_to_a_repository(
    ecosystem: str, build: PayloadBuilder, read: StateReader
) -> None:
    """A declared URL carrying a credential is refused, and stays a declaration.

    It is not DECLARED, because nothing usable came out of it, and it is not
    UNDECLARED, because the package did name a source. It is the middle state,
    which is what the middle state is for.
    """
    state = read(build("https://user:token@github.com/acme/widget", None))
    assert state is SourceRepositoryState.UNUSABLE


def test_a_credentialed_declaration_never_reaches_the_reported_repository_url() -> None:
    """The secret must not be laundered into the output document either."""
    dep = DependencyMetadata(name="widget", installed_version="1.0.0")
    analyzer = PythonAnalyzer()
    analyzer.clone_repos = False
    payload = _pypi("https://user:ghp_secret@github.com/acme/widget", None)
    with mock.patch.object(
        PythonAnalyzer, "_get_pypi_package_info", return_value=payload
    ):
        analyzer.analyze({"widget": dep})
    assert dep.repository_url is None or "ghp_secret" not in dep.repository_url


def test_is_cloneable_accepts_the_widened_hosts_and_still_rejects_lookalikes() -> None:
    """The predicate ``collect_repository_signals`` gates the clone on."""
    cloneable: List[str] = [
        "https://codeberg.org/allauth/django-allauth",
        "http://github.com/mikel/mail",
        "https://www.github.com/x/y",
        "https://git.sr.ht/~sircmpwn/hare",
    ]
    refused: List[Optional[str]] = [
        "https://github.com.evil.example/a/b",
        "https://hg.sr.ht/~icefox/oorandom",
        "https://user:token@github.com/x/y",
        None,
        "",
    ]
    assert all(is_cloneable_repo_url(url) for url in cloneable)
    assert not any(is_cloneable_repo_url(url) for url in refused)
