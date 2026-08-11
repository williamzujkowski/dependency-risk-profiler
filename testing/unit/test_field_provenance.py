"""Which acquisition path wrote a field that has more than one (#164 step 7).

The design amendment restricted provenance to *fields with more than one real
write path*, against an original proposal that wrapped about seventeen. Four of
seven voters called that over-broad, so the scope is not a judgement call to be
re-made every time someone adds a field: :func:`test_the_scope_is_exactly_the_
fields_with_more_than_one_writer` re-derives it from an AST walk of ``src/`` and
fails when the source tree and :class:`ProvenancedField` disagree.

The AST walk finds *call sites*, and the criterion is *acquisition paths*, which
no walk can tell apart — five ecosystem adapters writing ``maintainer_count``
from five registries are one path, because only one of them runs for any given
dependency. :data:`SINGLE_SOURCE_FIELDS` carries that judgement explicitly, one
line of reasoning per field, and is itself checked: an entry that stops having
multiple write sites fails as a stale exemption.

The other half of this file is the design's binding security condition. A
source is a *sanitized logical locator* — ``"github:api/repository"`` — and
never an absolute clone path, an authenticated URL, a query string or a header.
That is enforced structurally rather than by review: both sides of the mapping
are closed enum vocabularies, so there is no code path that puts a credential
there, and the tests below try to anyway.
"""

import ast
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Set

import pytest

from dependency_risk_profiler.community.analyzer import analyze_forge_community_metrics
from dependency_risk_profiler.contract import field_sources_to_dict, scored_dependency
from dependency_risk_profiler.models import (
    CommunityMetrics,
    DependencyMetadata,
    DependencyRiskScore,
)
from dependency_risk_profiler.signals import FieldSource, ProvenancedField

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "dependency_risk_profiler"
MODELS_PATH = SRC_ROOT / "models.py"

#: Model fields written from more than one *site* but only one *source*, with
#: the reason. Every entry must still have multiple write sites, or it is a
#: stale exemption and fails below.
SINGLE_SOURCE_FIELDS: Dict[str, str] = {
    # Constructed by the parsers from the manifest and never from anywhere else.
    "name": "one source: the manifest the parser read.",
    "installed_version": "one source: the manifest the parser read.",
    # One adapter runs per dependency, so the eight sites are eight ecosystems,
    # not eight sources for one package.
    "latest_version": "one source per package: its own registry.",
    "category": "two branches of one function over one registry payload.",
    "license_id": "two branches of one function over one registry payload.",
    "is_approved": "two branches of one function over one registry payload.",
    "risk_level": "derived from the licence category by one function.",
    # Container assignments, not value writes: the sites initialize the nested
    # dataclass before the fields inside it are written.
    "community_metrics": "container init; the fields inside carry provenance.",
    "security_metrics": "container init; each metric has a single writer.",
    "dependency": "the scorer builds one DependencyRiskScore per dependency.",
    "manifest_path": "the parser's own path, written once per profile.",
    # Registry publication dates, one registry per package.
    "last_release_date": "one source per package: its own registry's time table.",
    "installed_release_date": "one source per package: its own registry.",
    # A string-keyed bag, not a field. Each key has its own single writer, and
    # v2 does not serialize it; provenance for a dict of strings would be
    # provenance for forty-eight unrelated things.
    "additional_info": "a keyed bag; each key has one writer.",
    # A capability-keyed bag. The three sites write three different keys, and
    # each ForgeAnswer already carries its own field_source, so provenance for
    # the container would duplicate what the values state.
    "forge_answers": "a keyed bag; each answer carries its own field_source.",
    # Qualifies on write-path count and is deliberately out of scope. See the
    # ProvenancedField docstring.
    "repository_url": (
        "an identity locator, not a measured value; what a consumer needs "
        "from it is already typed as source_repository_state (#189)."
    ),
    "transitive_dependencies": (
        "already carries transitive_source (#199), which is provenance "
        "under an older name."
    ),
    # The walk matches attribute names without resolving types, so a model
    # field name that some unrelated object also uses collects that object's
    # writes too. Each of these is one real writer plus one or more homonyms.
    "dependencies": "the scorer builds the profile; the rest are homonyms.",
    "ecosystem": "the scorer builds the profile; the rest are homonyms.",
    "url": "no writer in src/ at all; both sites are homonyms.",
    "high_risk_dependencies": "one writer, the scorer, plus a homonym.",
    "medium_risk_dependencies": "one writer, the scorer, plus a homonym.",
    "unknown_risk_dependencies": "one writer, the scorer, plus a homonym.",
}

#: A source is a short lowercase kind, optionally a colon and a slash-separated
#: locator. No scheme, no host, no userinfo, no query, no percent-encoding, no
#: absolute or relative filesystem path.
LOCATOR = re.compile(r"^[a-z][a-z0-9]*(:[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)*)?$")

#: Things that must never appear in a serialized source, whatever the grammar
#: above happens to allow. Spelled out separately because the failure this
#: guards against is a leak, and a leak deserves a second, blunter check.
FORBIDDEN_SUBSTRINGS = ("@", "?", "#", "&", "=", "%", "//", "\\", "..", " ", "'", '"')

#: Credential-shaped values a caller might reach for if the type let them.
CREDENTIAL_SHAPED = [
    "https://x-access-token:ghp_0123456789abcdefghij@api.github.com/repos/o/r",
    "/home/runner/work/_temp/clone-4f2a/.git",
    "Authorization: Bearer ghp_0123456789abcdefghij",
    "https://api.github.com/repos/o/r?access_token=ghp_0123456789abcdefghij",
    "ghp_0123456789abcdefghij",
]


def _record_as_an_untyped_caller_would(
    dependency: DependencyMetadata, field_name: object, source: object
) -> None:
    """Call the recorder the way something mypy never saw would call it.

    The runtime guard exists precisely for callers the type checker does not
    cover — a plugin, a REPL, a fixture loaded from disk — so the tests have to
    reach it the same way. Going through a loosely typed callable models that
    honestly and keeps the suite's own type gate clean, which matters: the
    repo bans ``# type: ignore``, and a test that needed one to prove a runtime
    check works would be proving the wrong thing.

    Args:
        dependency: The dependency to record on.
        field_name: Whatever the caller believes is a field name.
        source: Whatever the caller believes is a source.
    """
    recorder: Callable[..., None] = dependency.record_field_source
    recorder(field_name, source)


def _model_field_names() -> Set[str]:
    """Return every annotated field name declared in ``models.py``.

    Returns:
        The field names, across every model class.
    """
    tree = ast.parse(MODELS_PATH.read_text(encoding="utf-8"), str(MODELS_PATH))
    names: Set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                names.add(statement.target.id)
    return names


def _write_sites() -> Dict[str, List[str]]:
    """Scan ``src/`` for every site that writes a model field.

    Deliberately generous, like ``test_model_field_reachability``'s detector:
    any ``obj.field = ...`` and any ``field=`` keyword argument in any call
    counts. Over-counting is safe here — it can only pull a field *into* the
    review set — while under-counting would let a genuinely multiply-written
    field slip past unlabelled.

    Returns:
        Mapping of field name to ``path:line`` sites, excluding ``models.py``
        itself (whose only assignments are the dataclass declarations and the
        provenance recorder).
    """
    fields = _model_field_names()
    sites: Dict[str, List[str]] = {}

    for path in sorted(SRC_ROOT.rglob("*.py")):
        if path.name == "models.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            targets: List[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
                targets = [node.target]
            for target in targets:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Attribute) and sub.attr in fields:
                        sites.setdefault(sub.attr, []).append(
                            f"{path.name}:{sub.lineno}"
                        )
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg in fields:
                        sites.setdefault(keyword.arg, []).append(
                            f"{path.name}:{node.lineno}"
                        )
    return sites


def _multiply_written() -> Set[str]:
    """Return every model field written at more than one site in ``src/``.

    Returns:
        The field names.
    """
    return {name for name, sites in _write_sites().items() if len(sites) > 1}


def test_the_scope_is_exactly_the_fields_with_more_than_one_writer() -> None:
    """INVARIANT (#164 step 7): the scope is derived, not asserted.

    The amendment restricted provenance to fields with more than one real write
    path. Adding a second writer to a field therefore fails this test until
    somebody either records provenance for it or writes down, in
    :data:`SINGLE_SOURCE_FIELDS`, why the two writers are one source.
    """
    sites = _write_sites()
    multiply_written = {name for name, where in sites.items() if len(where) > 1}
    unexplained = multiply_written - set(SINGLE_SOURCE_FIELDS)
    provenanced = {field.value for field in ProvenancedField}

    assert unexplained == provenanced, "\n".join(
        [
            "fields written from more than one site, neither provenanced nor "
            "explained in SINGLE_SOURCE_FIELDS:",
            *(f"  {name}: {sites[name]}" for name in sorted(unexplained - provenanced)),
        ]
    )


def test_no_exemption_outlives_the_second_writer_it_explains() -> None:
    """A stale exemption is a scope that quietly shrank without anyone noticing."""
    multiply_written = _multiply_written()
    stale = set(SINGLE_SOURCE_FIELDS) - multiply_written

    assert not stale, f"exemptions with no second writer left: {sorted(stale)}"


def test_every_provenanced_field_is_a_real_model_field() -> None:
    """The enum names attributes, so a rename must break here rather than drift."""
    names = _model_field_names()
    for field in ProvenancedField:
        assert field.value in names, field.value


# ---------------------------------------------------------------------------
# The binding security condition
# ---------------------------------------------------------------------------


def test_every_source_is_a_sanitized_logical_locator() -> None:
    """BINDING CONDITION: no clone paths, URLs, query strings or headers.

    Checked against the grammar and then, separately, against a list of
    characters that must simply never appear. Two checks because one regex is
    one typo away from admitting everything.
    """
    for source in FieldSource:
        assert LOCATOR.match(source.value), source.value
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in source.value, (source.value, forbidden)
        assert not source.value.startswith("/"), source.value
        assert len(source.value) <= 40, source.value


@pytest.mark.parametrize("credential", CREDENTIAL_SHAPED)
def test_a_credential_shaped_value_cannot_reach_a_field_source(
    credential: str,
) -> None:
    """BINDING CONDITION: the recorder refuses anything outside the vocabulary.

    Types already forbid this, but mypy does not run in production. An untyped
    caller — a plugin, a REPL, a fixture — must hit a wall rather than a
    coercion, because there is no sanitized rendering of a token: the only safe
    thing to do with one is refuse it.
    """
    dependency = DependencyMetadata(name="example", installed_version="1.0.0")

    with pytest.raises(TypeError):
        _record_as_an_untyped_caller_would(
            dependency, ProvenancedField.STAR_COUNT, credential
        )

    assert dependency.field_sources == {}


def test_a_credential_shaped_field_name_is_refused_too() -> None:
    """The key is a closed vocabulary as well; a leak either side is a leak."""
    dependency = DependencyMetadata(name="example", installed_version="1.0.0")

    with pytest.raises(TypeError):
        _record_as_an_untyped_caller_would(
            dependency,
            "https://user:ghp_secret@github.com/o/r",
            FieldSource.GITHUB_API_REPOSITORY,
        )

    assert dependency.field_sources == {}


def test_an_impostor_that_merely_looks_like_a_source_is_refused() -> None:
    """``isinstance``, not duck typing: a ``.value`` attribute is not a vocabulary."""

    class LooksLikeASource:
        """An object whose ``value`` is a credential."""

        value = "https://x-access-token:ghp_secret@api.github.com/repos/o/r"

    dependency = DependencyMetadata(name="example", installed_version="1.0.0")

    with pytest.raises(TypeError):
        _record_as_an_untyped_caller_would(
            dependency, ProvenancedField.STAR_COUNT, LooksLikeASource()
        )

    assert dependency.field_sources == {}


def test_the_serialized_block_carries_nothing_credential_shaped() -> None:
    """End to end: whatever is recorded, what ships is locators."""
    dependency = DependencyMetadata(name="example", installed_version="1.0.0")
    for field in ProvenancedField:
        dependency.record_field_source(field, FieldSource.GITHUB_API_REPOSITORY)

    serialized = field_sources_to_dict(dependency)

    assert set(serialized) == {field.value for field in ProvenancedField}
    for name, source in serialized.items():
        assert LOCATOR.match(source), (name, source)
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in source, (name, source, forbidden)


# ---------------------------------------------------------------------------
# The motivating case
# ---------------------------------------------------------------------------


def test_a_scraped_star_count_says_it_was_scraped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The github.com HTML regex is the weakest source here, and says so."""
    module = "dependency_risk_profiler.forges.github"
    monkeypatch.setattr(f"{module}.github_contributor_count", lambda *_: None)
    monkeypatch.setattr(f"{module}.github_commit_frequency", lambda *_: None)
    monkeypatch.setattr(
        f"{module}.fetch_url",
        lambda _: '<span class="Counter js-social-count">4,321</span>',
    )
    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja",
    )

    analyze_forge_community_metrics(dependency)

    assert dependency.community_metrics is not None
    assert dependency.community_metrics.star_count == 4321
    assert (
        dependency.field_sources[ProvenancedField.STAR_COUNT]
        is FieldSource.GITHUB_HTML_SCRAPE
    )


def test_the_api_overwrites_the_scrape_and_the_record_follows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESSION (#164 step 7): the exact collision the amendment named.

    Both writers are live in one org scan — ``_apply_enhanced_metadata`` scrapes
    the HTML, then ``_apply_github_repository_signals`` overwrites it from the
    REST API — and until this change the payload gave a consumer no way to tell
    which of the two they were holding.
    """
    from dependency_risk_profiler.org_scan.github import RepoSignals
    from dependency_risk_profiler.org_scan.pipeline import (
        ExistingDependencyProfiler,
        VulnerabilityOptions,
    )

    module = "dependency_risk_profiler.forges.github"
    monkeypatch.setattr(f"{module}.github_contributor_count", lambda *_: None)
    monkeypatch.setattr(f"{module}.github_commit_frequency", lambda *_: None)
    monkeypatch.setattr(
        f"{module}.fetch_url",
        lambda _: '<span class="Counter js-social-count">4,321</span>',
    )

    class SignalsClient:
        """Offline stand-in for the authenticated repository signals client."""

        def get_repository_signals(self, owner_repo: str) -> RepoSignals:
            """Return the API's answer for the same repository.

            Args:
                owner_repo: Normalized ``owner/repo`` key.

            Returns:
                The fixture signals.
            """
            return RepoSignals(star_count=12345)

    dependency = DependencyMetadata(
        name="jinja2",
        installed_version="3.1.6",
        repository_url="https://github.com/pallets/jinja",
        community_metrics=CommunityMetrics(),
    )

    analyze_forge_community_metrics(dependency)
    assert (
        dependency.field_sources[ProvenancedField.STAR_COUNT]
        is FieldSource.GITHUB_HTML_SCRAPE
    )

    profiler = ExistingDependencyProfiler(
        scoring_weights={},
        vulnerability_options=VulnerabilityOptions(),
        repository_signals_client=SignalsClient(),
    )
    profiler._apply_github_repository_signals(dependency)

    assert dependency.community_metrics is not None
    assert dependency.community_metrics.star_count == 12345
    assert (
        dependency.field_sources[ProvenancedField.STAR_COUNT]
        is FieldSource.GITHUB_API_REPOSITORY
    )


def test_a_field_nobody_wrote_claims_no_source() -> None:
    """An absent key, not a source of "unknown": the #74 rule, for provenance."""
    dependency = DependencyMetadata(name="example", installed_version="1.0.0")

    assert field_sources_to_dict(dependency) == {}


def test_v2_serializes_the_record_beside_the_signals() -> None:
    """The record is read, not merely written: a dead provenance field is worse."""
    dependency = DependencyMetadata(name="example", installed_version="1.0.0")
    dependency.record_field_source(
        ProvenancedField.STAR_COUNT, FieldSource.GITHUB_HTML_SCRAPE
    )
    dependency.record_field_source(
        ProvenancedField.LAST_UPDATED, FieldSource.REGISTRY_RELEASE
    )
    dependency.last_updated = datetime(2026, 1, 1, tzinfo=timezone.utc)

    entry = scored_dependency(
        DependencyRiskScore(dependency=dependency), ecosystem="python"
    )

    assert entry["field_sources"] == {
        "star_count": "github:html",
        "last_updated": "registry:release",
    }
