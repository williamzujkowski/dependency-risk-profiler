"""The adapter-conformance gate: per-signal value assertions (#73, #145).

Three layers, each failing on a different kind of regression:

1. **Value conformance.** Every captured payload is scored offline and every
   signal it can answer is asserted *by value*. This is the layer that catches
   a signal which is always measured and always wrong — #142's phantom npm
   ``deprecated`` key, the case ``signal_floors`` documents itself as unable to
   reach.
2. **The non-default-branch rule.** Every polarized signal (boolean or
   two-state enum) must have at least one fixture whose ground truth is the
   branch a dead read can never produce. A polarized signal without one is
   reported as a gap, not assumed to work.
3. **Fixture hygiene.** Provenance is present, captures are fresh, payloads
   carry no credentials, sizes are bounded, and no test reaches the network.

Deliberately not here: the ecosystems still pending. ``CONVERSION_STATUS``
carries all nine with a note on what each still needs, and
``test_the_conversion_ledger_is_honest`` keeps that list from quietly claiming
more than it has.
"""

from datetime import date, timedelta
from typing import Mapping, Tuple

import pytest
from adapter_conformance import (
    ADVISORY_LOOKUP_CASE_IDS,
    ADVISORY_LOOKUP_CASES,
    CASES,
    CONVERSION_STATUS,
    DRIVERS,
    POLARIZED_SIGNALS,
    AdvisoryLookupCase,
    FixtureCase,
    assert_advisory_lookup_case_conforms,
    assert_case_conforms,
    assert_non_default_branches_are_proven,
    assert_polarized_signals_are_registered,
    assert_source_repository_states_are_pinned,
    converted_ecosystems,
    score_case,
    unproven_branches,
)
from registry_fixtures import (
    MANIFEST,
    FixtureError,
    RegistryFixture,
    declared_fixtures,
    load_fixture,
    replay_fetcher,
    utc_today,
)
from signal_floors import (
    MIN_MEASURED_SIGNALS,
    REGISTRY_MEASURED_SIGNALS,
    SCORES_FROM_REGISTRY_ALONE,
)

from dependency_risk_profiler.analyzers.golang import (
    TRANSITIVE_UNMEASURED_REASON,
    deprecation_notice,
)
from dependency_risk_profiler.community.analyzer import analyze_community_metrics
from dependency_risk_profiler.models import DependencyMetadata
from dependency_risk_profiler.parsers.python import runtime_requirement_names
from dependency_risk_profiler.signals import TRANSITIVE_SOURCE_UNMEASURED

CASE_IDS = [case.slug for case in CASES]


# --- 1. Value conformance --------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_captured_payload_produces_the_signal_values_it_should(
    case: FixtureCase,
) -> None:
    """Each captured payload scores to the values its ground truth demands."""
    assert_case_conforms(case)


@pytest.mark.parametrize(
    "case", ADVISORY_LOOKUP_CASES, ids=list(ADVISORY_LOOKUP_CASE_IDS)
)
def test_advisory_lookup_outcome_produces_the_exploit_value_it_should(
    case: AdvisoryLookupCase,
) -> None:
    """The exploit signal distinguishes a clean package from an outage (#219)."""
    assert_advisory_lookup_case_conforms(case)


def test_the_deprecated_npm_package_is_flagged_deprecated() -> None:
    """#142, pinned by value against the payload npm actually serves.

    The adapter used to read ``npm_data["deprecated"]``. The live ``request``
    packument has no such key — the notice lives in
    ``versions["2.88.2"].deprecated`` — so the flag defaulted to False for
    every package in the registry. ``False`` is not ``None``, so the signal
    counted as measured and every floor stayed green.

    Both halves are asserted here: the fixture's shape (there is no top-level
    key to read) and the resulting value (the signal is 1.0 anyway). Reinstate
    the top-level read and this is the test that goes red.
    """
    fixture = load_fixture("nodejs", "request")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert "deprecated" not in payload, (
        "the captured packument grew a top-level 'deprecated' key; if npm "
        "really started sending one, #142's premise changed and this test "
        "needs rewriting rather than deleting"
    )
    latest = payload["dist-tags"]["latest"]
    assert isinstance(payload["versions"][latest]["deprecated"], str)

    score = score_case(next(c for c in CASES if c.slug == "nodejs/request"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0


def test_the_gem_license_is_read_from_the_list_shape() -> None:
    """#134, pinned by value: RubyGems publishes 'licenses', never 'license'."""
    fixture = load_fixture("rubygems", "tzinfo")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert "license" not in payload
    assert payload["licenses"] == ["MIT"]

    score = score_case(next(c for c in CASES if c.slug == "rubygems/tzinfo"))

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "MIT"
    assert score.license_score == 0.0


def test_the_npm_maintainer_count_is_read_for_unscoped_packages_too() -> None:
    """The npm twin of #171, which survived the PyPI fix by six months.

    ``SCORES_FROM_REGISTRY_ALONE['nodejs']`` was False for one stated reason:
    npm publishes no cheap maintainer count. It does — a top-level
    ``maintainers`` array — and this capture carries all five of express's.
    The read existed; it was routed behind
    ``dependency.name.startswith("@")``, which tests whether a package is
    **scoped**, under a comment reading "npm package". Every unscoped name
    matched neither branch and came out with ``maintainer_count = None``.

    Asserted on an unscoped fixture on purpose. A scoped one passed
    throughout, which is what let this live: the branch was not dead, it was
    dead for the majority.

    This is the signal the abandonment pilot found carrying the only
    information in the model — ablating ``maintainer`` drops it below chance —
    so the field was missing precisely where it mattered most.
    """
    fixture = load_fixture("nodejs", "express")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    maintainers = payload["maintainers"]
    assert isinstance(maintainers, list)
    assert len(maintainers) == 5

    dependency = DependencyMetadata(name="express", installed_version="4.18.2")
    assert not dependency.name.startswith("@")
    analyze_community_metrics(dependency, metadata=dict(payload), github_token=None)
    assert dependency.maintainer_count == 5, (
        "An unscoped npm package must get its maintainer count from the "
        "packument. Routing on the shape of the name rather than the shape "
        "of the document is what hid this."
    )


def test_the_pypi_maintainer_count_comes_from_the_ownership_object() -> None:
    """#171, settled against the payload PyPI actually serves.

    PyPI was recorded as publishing no cheap maintainer count. It does — in a
    top-level ``ownership`` object beside ``info``, which the adapter read
    straight past. Both halves are asserted: the payload's shape (there is no
    ``maintainers`` key to have read instead) and the resulting count.

    The count is read and weighed; it is still not enough for a verdict from a
    registry document alone, because seven measured signals is one short of the
    eight a verdict costs (#340). That is a fact about the ceiling rather than
    about this read, and ``test_signal_floors`` derives it.
    """
    fixture = load_fixture("python", "requests")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert "maintainers" not in payload
    ownership = payload["ownership"]
    assert isinstance(ownership, Mapping)
    assert {entry["user"] for entry in ownership["roles"]} == {
        "Lukasa",
        "graffatcolmingov",
        "nateprewitt",
    }

    score = score_case(next(c for c in CASES if c.slug == "python/requests"))

    assert score.dependency.maintainer_count == 3
    assert score.maintainer_score == 0.25
    assert "maintainer" not in score.unknown_signals
    # True since #339: retiring two signals that a registry-only run could
    # never measure moved the bar from 8-of-15 to 7-of-13, and PyPI's floor of
    # seven now clears it. The maintainer read this test is really about is
    # unaffected -- it is asserted by name above, not through this count.
    assert SCORES_FROM_REGISTRY_ALONE["python"] is True


def test_an_org_owned_project_reports_no_maintainer_count_rather_than_zero() -> None:
    """An empty roles list is unmeasured, not a single-maintainer verdict.

    A project transferred to a PyPI organization carries its permissions on the
    organization, and this payload does not publish who is in it. ``len([])``
    is zero, zero scores 1.0 — the worst answer the maintainer signal has — and
    it would come from a fact nobody measured. #141 is the precedent: the
    transitive analyzer scored the empty set as a confident 0.0.
    """
    fixture = load_fixture("python", "flask")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    ownership = payload["ownership"]
    assert isinstance(ownership, Mapping)
    assert ownership["organization"] == "pallets"
    assert ownership["roles"] == []

    score = score_case(next(c for c in CASES if c.slug == "python/flask"))

    assert score.dependency.maintainer_count is None
    assert score.maintainer_score is None
    assert "maintainer" in score.unknown_signals


def test_the_pypi_licence_is_read_from_the_pep_639_expression() -> None:
    """The dead read the python capture found: metadata 2.4 moved the licence.

    flask publishes ``license_expression: "BSD-3-Clause"`` with ``license``
    null and no ``License ::`` classifier, so neither the singular spelling nor
    the classifier fallback had anything to reach. 17 of 30 sampled popular
    packages are in the same shape. This one a count-based floor *could* have
    caught, because an unread licence goes to None — but only if the floor's
    fixture were an affected package, and the floor's fixture was requests,
    which still publishes the legacy spelling.
    """
    fixture = load_fixture("python", "flask")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    info = payload["info"]
    assert isinstance(info, Mapping)
    assert info["license"] is None
    assert info["license_expression"] == "BSD-3-Clause"
    assert not [c for c in info["classifiers"] if "License ::" in c]

    score = score_case(next(c for c in CASES if c.slug == "python/flask"))

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "BSD-3-CLAUSE"
    assert score.license_score == 0.0


def test_the_fully_yanked_crate_is_flagged_deprecated() -> None:
    """The branch rubygems has no capture for (#170), proven one registry over.

    crates.io answers 200 for a crate whose every release is yanked and reports
    ``yanked: true`` on the release entry. rubygems.org answers 404 for the
    equivalent gem, so its adapter returns before the read — which is why
    ``POLARIZED_SIGNALS['rubygems']['deprecation']`` is still a waiver and this
    one is not. Same idea, different endpoint.
    """
    fixture = load_fixture("cargo", "acid-store")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert payload["crate"]["yanked"] is True
    assert all(entry["yanked"] is True for entry in payload["versions"])

    score = score_case(next(c for c in CASES if c.slug == "cargo/acid-store"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0


def test_a_withdrawn_crate_is_not_reported_as_current() -> None:
    """#139's shape, second field: max_version is a sentinel on a yanked crate.

    crates.io answers ``max_version: "0.0.0"`` when nothing installable
    remains, and no release is numbered 0.0.0. Read as the latest version it
    makes an installed 0.10.0 look like a trivial patch behind — a value that
    was present and wrong, which is exactly why cargo was chosen for this
    conversion.
    """
    fixture = load_fixture("cargo", "acid-store")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert payload["crate"]["max_version"] == "0.0.0"
    assert "0.0.0" not in {entry["num"] for entry in payload["versions"]}

    score = score_case(next(c for c in CASES if c.slug == "cargo/acid-store"))

    assert score.dependency.latest_version == "0.14.2"
    assert score.version_score == 0.5


def test_the_serde_release_date_is_not_the_crates_first_publication() -> None:
    """#139 itself, pinned by value on a captured payload.

    serde's crate object was created in December 2014 and its newest release
    shipped this year. Reading ``crate.created_at`` as the release date scores
    the most actively maintained crate in the registry at maximum staleness.
    """
    fixture = load_fixture("cargo", "serde")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    assert payload["crate"]["created_at"].startswith("2014-")

    score = score_case(next(c for c in CASES if c.slug == "cargo/serde"))

    assert score.dependency.last_updated is not None
    assert score.dependency.last_updated.year >= 2026
    assert score.staleness_score is not None and score.staleness_score < 1.0


def test_the_dotnet_deprecation_block_exists_in_only_one_registration_hive() -> None:
    """The nuget capture's finding, proven by holding the two hives side by side.

    #129 read the deprecation marker from ``registration5-semver1``. nuget.org
    publishes that block **only** in ``registration5-gz-semver2``: the same
    package, the same version, the same catalog entry, differing by exactly
    that key. No amount of reading one payload would have shown it, which is
    why both are captured — the absence has to be provable as the registry's
    shape rather than as a failed request, and a hand-written fixture would
    have carried the key because the parser looks for it.

    Microsoft.Azure.ServiceBus has been deprecated in favour of
    Azure.Messaging.ServiceBus since 2021 and read as healthy the whole time.
    """
    semver2 = load_fixture("nuget", "servicebus.registration")
    semver1 = load_fixture("nuget", "servicebus.registration-semver1")

    entries = {
        fixture.name: _newest_catalog_entry(fixture) for fixture in (semver1, semver2)
    }
    assert (
        entries["servicebus.registration"]["version"]
        == entries["servicebus.registration-semver1"]["version"]
    ), "the two hives no longer describe the same newest version; re-capture"

    assert "deprecation" not in entries["servicebus.registration-semver1"], (
        "registration5-semver1 grew a 'deprecation' key; if nuget.org really "
        "started publishing one there, this finding's premise changed and this "
        "test needs rewriting rather than deleting"
    )
    deprecation = entries["servicebus.registration"]["deprecation"]
    assert isinstance(deprecation, Mapping)
    assert deprecation["reasons"] == ["Other"]
    assert deprecation["alternatePackage"]["id"] == "Azure.Messaging.ServiceBus"
    assert entries["servicebus.registration"]["listed"] is True, (
        "the unlisted fallback must not be what makes this package deprecated; "
        "the explicit block is the thing under test"
    )

    score = score_case(next(c for c in CASES if c.slug == "nuget/servicebus.nuspec"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0


def _newest_catalog_entry(fixture: RegistryFixture) -> Mapping[str, object]:
    """Return the newest inlined catalog entry in a captured registration index.

    Args:
        fixture: A captured NuGet registration index.

    Returns:
        The last leaf's ``catalogEntry`` on the newest page.
    """
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    pages = payload["items"]
    assert isinstance(pages, list)
    page = pages[-1]
    assert isinstance(page, Mapping)
    leaves = page["items"]
    assert isinstance(leaves, list)
    entry = leaves[-1]["catalogEntry"]
    assert isinstance(entry, Mapping)
    return entry


def test_the_retired_go_module_is_flagged_from_its_own_go_mod() -> None:
    """#142's shape in a fifth adapter, and the most complete instance yet.

    Go states a module's retirement in the module's own ``go.mod``, as a
    ``// Deprecated:`` comment attached to the ``module`` directive. The proxy
    serves that file at ``@v/<version>.mod``. Nothing fetched it, so
    ``is_deprecated`` was False for every Go module ever scanned — measured,
    and measured wrong, with every count green.

    Both halves are asserted: that ``@latest`` carries no deprecation field of
    its own (so there was no key to have read instead) and that the resulting
    signal is 1.0 anyway.
    """
    latest = load_fixture("golang", "protobuf.latest")
    payload = latest.payload
    assert isinstance(payload, Mapping)
    assert payload["Version"] == "v1.5.4"
    assert not [key for key in payload if "eprecat" in key], (
        "proxy.golang.org grew a deprecation field on @latest; the marker used "
        "to exist only in the go.mod, which is why this needed a second "
        "endpoint rather than a second key"
    )

    go_mod = load_fixture("golang", "protobuf.mod").payload
    assert isinstance(go_mod, str)
    assert go_mod.splitlines()[0].startswith("// Deprecated:")
    assert deprecation_notice(go_mod) is not None

    healthy = load_fixture("golang", "logrus.mod").payload
    assert isinstance(healthy, str)
    assert deprecation_notice(healthy) is None

    score = score_case(next(c for c in CASES if c.slug == "golang/protobuf.latest"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0


def test_a_require_line_comment_does_not_retire_the_module_reading_it() -> None:
    """The notice belongs to the ``module`` directive, not to a require entry.

    A ``// Deprecated:`` comment above a ``require`` line is about the
    *dependency*. Reading it as the module's own would flag every consumer of a
    retired package as retired itself, which is a fabricated finding rather
    than a missed one — the worse of the two failure modes for this signal.
    """
    consumer = (
        "module example.com/healthy\n"
        "\n"
        "go 1.21\n"
        "\n"
        "require (\n"
        "\t// Deprecated: use google.golang.org/protobuf\n"
        "\tgithub.com/golang/protobuf v1.5.4\n"
        ")\n"
    )

    assert deprecation_notice(consumer) is None


def test_the_maven_release_date_comes_from_the_metadata_document() -> None:
    """Maven's first measured cadence, pinned against the document that states it.

    ``maven-metadata.xml`` publishes ``<versioning><lastUpdated>`` as a bare
    ``yyyyMMddHHmmss`` in UTC. Nothing read it, so a Maven artifact had no
    release cadence at all without a clone — on the ecosystem where the
    repository is least likely to be reachable, since #141 had left
    ``repository_url`` unset entirely.
    """
    fixture = load_fixture("maven", "jackson-databind.metadata")
    document = fixture.payload
    assert isinstance(document, str)
    assert "<lastUpdated>" in document

    score = score_case(next(c for c in CASES if c.slug == "maven/jackson-databind.pom"))

    assert score.dependency.last_updated is not None
    assert score.dependency.last_updated.tzinfo is not None
    assert score.staleness_score is not None
    assert "staleness" not in score.unknown_signals


def test_a_maven_licence_declared_only_in_the_parent_pom_is_read() -> None:
    """The reading the maven capture found, now closed (#178).

    Maven's convention is to declare ``<licenses>``, ``<scm>`` and
    ``<developers>`` once in a parent POM and inherit them. The adapter used to
    read the artifact POM and stop, so guava's licence was unmeasured while
    Maven Central served it one request away — and the same held for every
    Apache Commons artifact, whose licence sits two hops up in
    ``org.apache:apache``.

    The fixture halves of these assertions are what keep the test honest: guava
    genuinely declares neither element, so a licence appearing on the score can
    only have come from walking to ``guava-parent``.
    """
    fixture = load_fixture("maven", "guava.pom")
    pom = fixture.payload
    assert isinstance(pom, str)
    assert "<licenses>" not in pom
    assert "<scm>" not in pom
    assert "<artifactId>guava-parent</artifactId>" in pom

    parent = load_fixture("maven", "guava-parent.pom")
    parent_pom = parent.payload
    assert isinstance(parent_pom, str)
    assert "<licenses>" in parent_pom and "<scm>" in parent_pom

    score = score_case(next(c for c in CASES if c.slug == "maven/guava.pom"))

    assert score.dependency.license_info is not None
    assert score.dependency.license_info.license_id == "APACHE"
    assert score.license_score == 0.0
    assert "license" not in score.unknown_signals


def test_the_maven_parent_walk_does_not_stop_at_the_first_parent() -> None:
    """slf4j-api's licence and repository are two hops up, not one.

    slf4j-parent declares neither ``<licenses>`` nor ``<scm>``; slf4j-bom, its
    parent, declares both. A walk that read one level and gave up would report
    this artifact exactly as the unwalked adapter did, so the two-hop case is
    the one that tells "walks the chain" from "reads the parent".
    """
    middle = load_fixture("maven", "slf4j-parent.pom")
    middle_pom = middle.payload
    assert isinstance(middle_pom, str)
    assert "<licenses>" not in middle_pom
    assert "<scm>" not in middle_pom

    score = score_case(next(c for c in CASES if c.slug == "maven/slf4j-api.pom"))

    assert score.dependency.repository_url == "https://github.com/qos-ch/slf4j"
    assert score.license_score == 0.0
    assert not {"license", "source_repository"} & set(score.unknown_signals)


def test_two_maven_artifacts_of_the_same_era_report_different_source_states() -> None:
    """#176's acceptance, pinned against the two POMs Maven Central serves.

    ``log4j:log4j:1.2.17`` declares ``<scm>`` and every spelling of it is
    Subversion; ``commons-collections:commons-collections:3.1`` carries no
    ``<scm>`` element at all. Both used to record UNDECLARED and score 1.0, so
    "this project published its provenance and the host was decommissioned" and
    "this project never said where its source lived" were the same fact.

    Both halves are asserted: the fixtures' shape (one declares SVN, the other
    declares nothing) and the resulting values (0.75 against 1.0). Collapse the
    two states back together and this is the test that goes red.
    """
    log4j = load_fixture("maven", "log4j.pom").payload
    assert isinstance(log4j, str)
    assert "<scm>" in log4j
    assert "scm:svn:http://svn.apache.org/repos/asf/logging/log4j" in log4j
    assert "github.com" not in log4j

    collections = load_fixture("maven", "commons-collections.pom").payload
    assert isinstance(collections, str)
    assert "scm" not in collections, (
        "commons-collections:3.1 grew an <scm> element; if Maven Central "
        "really started serving one, this comparison needs a different pair "
        "rather than deleting"
    )

    declared_svn = score_case(next(c for c in CASES if c.slug == "maven/log4j.pom"))
    declared_nothing = score_case(
        next(c for c in CASES if c.slug == "maven/commons-collections.pom")
    )

    assert declared_svn.source_repository_score == 0.75
    assert declared_nothing.source_repository_score == 1.0
    assert (
        declared_svn.source_repository_score != declared_nothing.source_repository_score
    )
    assert (
        "Declares a source repository that is not a reachable git forge"
        in declared_svn.factors
    )
    assert "Declares no source repository" in declared_nothing.factors

    # Both are unreadable, so both still explain the same eight quiet signals
    # rather than counting them as independent gaps (#146).
    for score in (declared_svn, declared_nothing):
        assert score.insufficient_data is False
        assert "health_indicators" in score.unknown_signals


def test_every_source_repository_state_is_pinned_by_value() -> None:
    """Three states, three captured fixtures; none of them decided by omission."""
    assert_source_repository_states_are_pinned()


def test_the_nuget_source_repository_signal_is_measured_at_all() -> None:
    """#183: nuget resolved a repository and reported nothing either way.

    ``_repository_url`` read ``<repository url>`` off the nuspec, set
    ``dep.repository_url``, and never recorded the answer, so
    ``_calculate_source_repository_score`` returned None and the signal left
    ``weighted_scores`` entirely. nuget was the only ecosystem scoring 15 where
    the rest scored 16.
    """
    fixture = load_fixture("nuget", "newtonsoft.json.nuspec")
    nuspec = fixture.payload
    assert isinstance(nuspec, str)
    assert "<repository" in nuspec

    score = score_case(
        next(c for c in CASES if c.slug == "nuget/newtonsoft.json.nuspec")
    )

    assert score.source_repository_score == 0.0
    assert "source_repository" not in score.unknown_signals
    assert "source_repository" in REGISTRY_MEASURED_SIGNALS["nuget"]
    assert MIN_MEASURED_SIGNALS["nuget"] == len(REGISTRY_MEASURED_SIGNALS["nuget"])


def test_the_packagist_abandoned_marker_names_its_successor() -> None:
    """Composer's deprecation non-default branch, captured.

    Packagist's ``abandoned`` is two-valued: ``true``, or the name of the
    package that supersedes it. swiftmailer carries the second form. A dead
    read of the key gives False here forever, and False is measured.
    """
    fixture = load_fixture("composer", "swiftmailer")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    head = payload["packages"]["swiftmailer/swiftmailer"][0]
    assert head["abandoned"] == "symfony/mailer"
    assert head["license"] == ["MIT"], (
        "Packagist publishes the licence as a list, the RubyGems shape; #134's "
        "fix is what makes it read at all"
    )

    score = score_case(next(c for c in CASES if c.slug == "composer/swiftmailer"))

    assert score.dependency.is_deprecated is True
    assert score.deprecation_score == 1.0
    assert score.dependency.additional_info["abandoned_in_favor_of"] == "symfony/mailer"


def test_the_packagist_entry_states_dependencies_and_the_adapter_reads_them() -> None:
    """The gap the composer audit found, now closed (#180).

    The p2 release entry carries a ``require`` block naming the package's own
    dependencies — the same fact nuget reads out of its ``.nuspec`` and scores
    as the transitive signal (#129). Two judgements are asserted by value here
    rather than described in a comment.

    **Platform constraints are not packages.** psr/log's whole ``require`` block
    is ``{"php": ">=8.0.0"}``. Counting it would give one dependency and a 0.1
    score; the measured answer is zero packages and 0.0, and the two are
    distinguishable, which is the only reason this fixture proves anything.

    **``require-dev`` is not counted.** swiftmailer requires four packages at
    runtime and two more for development. Runtime-only scores 0.1; folding the
    dev block in scores 0.25.
    """
    fixture = load_fixture("composer", "monolog")
    payload = fixture.payload
    assert isinstance(payload, Mapping)
    head = payload["packages"]["monolog/monolog"][0]
    assert isinstance(head["require"], Mapping) and head["require"]

    score = score_case(next(c for c in CASES if c.slug == "composer/monolog"))

    assert score.dependency.transitive_dependencies == {"psr/log"}
    assert score.transitive_score == 0.1
    assert "transitive" not in score.unknown_signals

    platform_only = load_fixture("composer", "psr-log").payload
    assert isinstance(platform_only, Mapping)
    assert platform_only["packages"]["psr/log"][0]["require"] == {"php": ">=8.0.0"}

    psr_log = score_case(next(c for c in CASES if c.slug == "composer/psr-log"))

    assert psr_log.dependency.transitive_dependencies == set()
    assert psr_log.transitive_score == 0.0, (
        "a require block holding only platform constraints is a measured zero; "
        "counting 'php' as a package would score 0.1"
    )

    dev_heavy = load_fixture("composer", "swiftmailer").payload
    assert isinstance(dev_heavy, Mapping)
    dev_head = dev_heavy["packages"]["swiftmailer/swiftmailer"][0]
    assert len(dev_head["require-dev"]) == 2

    swiftmailer = score_case(next(c for c in CASES if c.slug == "composer/swiftmailer"))

    assert "php" not in swiftmailer.dependency.transitive_dependencies
    assert len(swiftmailer.dependency.transitive_dependencies) == 4
    assert swiftmailer.transitive_score == 0.1, (
        "runtime requirements only; the six-package total that includes "
        "require-dev scores 0.25"
    )


def test_a_composer_vendor_that_looks_like_a_platform_prefix_still_counts() -> None:
    """``php-http/discovery`` is a package, not a platform requirement (#180).

    The platform filter tests the vendor prefix rather than the name, because
    several real vendors start with exactly the prefixes a platform constraint
    does. mailgun/mailgun-php requires six packages, three of them under
    ``php-http``; a filter that matched ``php-`` before it looked for the slash
    would report three, and score 0.1 instead of 0.25.
    """
    payload = load_fixture("composer", "mailgun-php").payload
    assert isinstance(payload, Mapping)
    require = payload["packages"]["mailgun/mailgun-php"][0]["require"]
    assert sum(name.startswith("php-http/") for name in require) == 3

    score = score_case(next(c for c in CASES if c.slug == "composer/mailgun-php"))

    assert "php-http/discovery" in score.dependency.transitive_dependencies
    assert len(score.dependency.transitive_dependencies) == 6
    assert score.transitive_score == 0.25


# --- 1b. #204: the other five ecosystems, and the trap in each -------------


def test_the_npm_version_manifest_states_dependencies_and_the_adapter_reads_them() -> (
    None
):
    """#204: the list was in the packument the adapter already fetched.

    Two absences that look alike from outside and are not. ``indexof`` ships
    ``"dependencies": {}`` — a manifest that is there, declaring nothing, which
    is a measured zero. A packument missing the latest version's manifest
    entirely is nobody having read a list, and stays unmeasured. Conflating
    them would put #141's fabricated zero back through a new door, which is why
    the two are asserted side by side.
    """
    payload = load_fixture("nodejs", "express").payload
    assert isinstance(payload, Mapping)
    assert "dependencies" not in payload, "the packument has no top-level list (#142)"
    manifest = payload["versions"]["5.2.1"]
    assert len(manifest["dependencies"]) == 28
    assert len(manifest["devDependencies"]) == 16

    express = score_case(next(c for c in CASES if c.slug == "nodejs/express"))

    assert len(express.dependency.transitive_dependencies) == 28
    assert "mocha" not in express.dependency.transitive_dependencies
    assert express.transitive_score == 0.5

    empty = load_fixture("nodejs", "indexof").payload
    assert isinstance(empty, Mapping)
    assert empty["versions"]["0.0.1"]["dependencies"] == {}

    indexof = score_case(next(c for c in CASES if c.slug == "nodejs/indexof"))

    assert indexof.dependency.transitive_dependencies == set()
    assert indexof.transitive_score == 0.0
    assert "transitive" not in indexof.unknown_signals


def test_a_python_requirement_gated_behind_an_extra_is_not_a_runtime_one() -> None:
    """#204's #190-shaped trap, in the ecosystem where it bites.

    requests publishes six ``requires_dist`` entries, two of them extras-gated.
    Four scores 0.1 and six scores 0.25, so the filter is visible in the value.

    The trap is *how* the filter is written. ``extras`` is a real, installable
    PyPI project — testtools depends on it — and so are ``pytest-extra`` and
    ``sphinx-extras``. A substring sweep for ``extra`` over the requirement
    string deletes every one of them, exactly the way a Composer platform check
    matching on ``php-`` would delete ``php-http/discovery`` (#190). So the
    marker section is severed at the semicolon first, and flask proves the
    other half: an ordinary environment marker is *not* an extra and stays.
    """
    payload = load_fixture("python", "requests").payload
    assert isinstance(payload, Mapping)
    requires = payload["info"]["requires_dist"]
    assert len(requires) == 6
    assert sum("extra ==" in entry for entry in requires) == 2

    requests = score_case(next(c for c in CASES if c.slug == "python/requests"))

    assert requests.dependency.transitive_dependencies == {
        "certifi",
        "charset_normalizer",
        "idna",
        "urllib3",
    }
    assert requests.transitive_score == 0.1, (
        "runtime requirements only; the six-entry total that includes the "
        "extras scores 0.25"
    )

    # The name-shaped filter this one has to survive.
    assert runtime_requirement_names(
        ["extras>=1.0.0", 'pytest-extra; extra == "t"']
    ) == {"extras"}

    flask = score_case(next(c for c in CASES if c.slug == "python/flask"))

    assert "importlib-metadata" in flask.dependency.transitive_dependencies, (
        "'; python_version < \"3.10\"' is a runtime marker, not an extra — a "
        "consumer on 3.9 really does install it"
    )
    assert "asgiref" not in flask.dependency.transitive_dependencies


def test_a_null_requires_dist_is_not_a_measured_zero() -> None:
    """#204's fail-closed half for python, and the reason it is not optional.

    PyPI sends ``requires_dist: null`` whenever the newest release publishes no
    ``Requires-Dist`` metadata at all. That is true of ``six`` and ``certifi``,
    which genuinely have no dependencies — and equally true of ``carbon`` and
    ``graphite-web``, sdist-only uploads that declare real ``install_requires``
    in their ``setup.py``. Null is therefore "PyPI cannot tell you", and reading
    it as an empty list would score a confident 0.0 across the whole sdist-only
    population.
    """
    payload = load_fixture("python", "sklearn").payload
    assert isinstance(payload, Mapping)
    assert payload["info"]["requires_dist"] is None

    score = score_case(next(c for c in CASES if c.slug == "python/sklearn"))

    assert score.dependency.transitive_source is None
    assert score.transitive_score is None
    assert "transitive" in score.unknown_signals


def test_the_rubygems_dependency_object_is_keyed_by_scope_not_counted() -> None:
    """#204's shape trap: the value is an object, and counting it says two.

    ``/gems/<name>.json`` publishes ``dependencies`` as
    ``{"development": [...], "runtime": [...]}``. Something that counted the
    value would report exactly two dependencies for every gem on rubygems.org
    forever — and two is a thoroughly plausible number, so nothing but a value
    assertion catches it. tzinfo has one runtime dependency and hpricot has
    none, and both would read as two.
    """
    payload = load_fixture("rubygems", "tzinfo").payload
    assert isinstance(payload, Mapping)
    assert sorted(payload["dependencies"]) == ["development", "runtime"]

    tzinfo = score_case(next(c for c in CASES if c.slug == "rubygems/tzinfo"))

    assert tzinfo.dependency.transitive_dependencies == {"concurrent-ruby"}
    assert tzinfo.transitive_score == 0.1

    hpricot = score_case(next(c for c in CASES if c.slug == "rubygems/hpricot"))

    assert hpricot.dependency.transitive_dependencies == set()
    assert hpricot.transitive_score == 0.0
    assert "transitive" not in hpricot.unknown_signals


def test_cargo_counts_normal_dependencies_once_and_dev_ones_never() -> None:
    """#204's cargo trap, and it is two traps in one document.

    acid-store 0.14.2 publishes 42 dependency entries: 32 ``normal`` and 10
    ``dev``. Counting the array is wrong by the ten, and wrong again because
    ``rand`` and ``tempfile`` each appear TWICE — once under each kind. 42, 40
    and 32 all land in the same 20-49 score bucket, so only the set catches it.

    ``optional`` is deliberately not a third exclusion: it is a feature gate
    inside ``[dependencies]``, not a scope. 18 of acid-store's 32 are optional
    backends and are counted as the declared runtime dependencies they are.
    """
    payload = load_fixture("cargo", "acid-store.dependencies").payload
    assert isinstance(payload, Mapping)
    entries = payload["dependencies"]
    assert len(entries) == 42
    assert sum(entry["kind"] == "dev" for entry in entries) == 10
    assert sum(entry["crate_id"] == "rand" for entry in entries) == 2

    score = score_case(next(c for c in CASES if c.slug == "cargo/acid-store"))

    assert len(score.dependency.transitive_dependencies) == 32
    assert "criterion" not in score.dependency.transitive_dependencies
    assert "rand" in score.dependency.transitive_dependencies
    assert "redis" in score.dependency.transitive_dependencies, (
        "an optional feature-gated backend is still a declared runtime "
        "dependency, the same way maven counts <optional>true</optional>"
    )
    assert score.transitive_score == 0.5


def test_golang_abstains_on_transitive_and_says_so() -> None:
    """#204: the one ecosystem that cannot answer, recorded rather than silent.

    The go.mod is fetched and the require block is right there. What is not
    there is a scope: ``go mod tidy`` writes a module's test-only requirements
    into the same direct block as its runtime ones, and logrus is the ordinary
    case — testify beside golang.org/x/sys, with nothing to tell them apart.
    Counting the block would report two where a consumer is exposed to one,
    for every module that tests with testify.
    """
    go_mod = load_fixture("golang", "logrus.mod").payload
    assert isinstance(go_mod, str)
    assert "github.com/stretchr/testify" in go_mod
    assert "golang.org/x/sys" in go_mod
    assert "// indirect" in go_mod, "depth is marked; scope is not"

    score = score_case(next(c for c in CASES if c.slug == "golang/logrus.latest"))

    assert score.dependency.transitive_source == TRANSITIVE_SOURCE_UNMEASURED, (
        "golang must record UNMEASURED positively rather than inheriting it by "
        "staying quiet — an audited abstention and an unaudited adapter are "
        "different facts (#204)"
    )
    assert score.transitive_score is None
    assert "transitive" in score.unknown_signals
    assert TRANSITIVE_UNMEASURED_REASON, "the abstention carries its reason"


# --- 2. The non-default-branch rule ----------------------------------------


@pytest.mark.parametrize("ecosystem", converted_ecosystems())
def test_every_polarized_signal_has_a_non_default_fixture(ecosystem: str) -> None:
    """A signal that defaults to False needs a fixture where the answer is True."""
    assert_non_default_branches_are_proven(ecosystem)


@pytest.mark.parametrize("ecosystem", converted_ecosystems())
def test_polarity_is_declared_only_for_signals_the_ecosystem_measures(
    ecosystem: str,
) -> None:
    """The polarity table and the measured-signal table describe one thing."""
    assert_polarized_signals_are_registered(ecosystem)


def test_unproven_branches_are_named_rather_than_assumed_closed() -> None:
    """Every waived branch carries a reason, and the reasons stay legible.

    A waiver is a gap that has been looked at, not a gap that has been fixed.
    The rubygems ``yanked`` entry is the one this harness produced on its own:
    no live gem payload was found reporting ``yanked: true``, which makes it a
    candidate for the same dead read as #142 in a second adapter.
    """
    waived = unproven_branches()

    assert waived, "the waiver list is the visible-gap mechanism; do not empty it"
    for line in waived:
        assert len(line) > 80, f"a waiver needs a reason, not a shrug: {line}"
    assert any(line.startswith("rubygems.deprecation") for line in waived)
    # Maven and Gradle carry no deprecation waiver, and the absence is the
    # point rather than an omission. A waiver says "this signal is measured and
    # no fixture can prove the other branch", which was true while Maven
    # Central's silence was scored as a confident False. It publishes no
    # retirement marker at all, so the adapter now records nothing and the
    # signal is honestly unmeasured — which the floors catch, and which is what
    # #179 asked for (#320).
    assert not any(
        line.startswith(("maven.deprecation", "gradle.deprecation"))
        for line in waived
    ), (
        "a signal an ecosystem does not measure has no polarity to waive; "
        "declaring one here would put the #142-shaped hole back by asserting "
        "that Maven Central answers a question it does not answer"
    )


# --- 3. Fixture hygiene ----------------------------------------------------


@pytest.mark.parametrize("fixture_id", declared_fixtures(), ids=str)
def test_every_declared_fixture_loads_with_provenance(
    fixture_id: Tuple[str, str],
) -> None:
    """Each fixture records where it came from and when it was taken.

    ``captured_at`` is written in UTC by ``capture_registry_fixtures.py``, so
    it is compared against UTC. Against a local ``date.today()`` a fixture
    captured from a machine behind UTC reads as taken tomorrow, and the check
    fires on a correct capture — which is a bug in the check, not in the
    fixture.
    """
    ecosystem, name = fixture_id
    fixture = load_fixture(ecosystem, name)

    assert fixture.source_url.startswith("https://")
    assert fixture.captured_at <= utc_today()
    assert fixture.payload not in (None, {}, [])


def test_fixtures_are_within_the_refresh_cadence() -> None:
    """Ageing fixtures warn; stale ones fail, so the refresh has a trigger.

    A fixture that is never re-captured freezes the registry's shape as it was
    the day it was taken and then defends that shape forever, which is #145 in
    slow motion. Thresholds live in the manifest next to the fixtures.
    """
    from registry_fixtures import assert_fixtures_are_fresh

    assert MANIFEST["warn_after_days"] < MANIFEST["fail_after_days"]
    assert_fixtures_are_fresh()


def test_an_ageing_capture_warns_and_a_stale_one_fails() -> None:
    """Both staleness branches are observed, not merely believed to work.

    A gate nobody has watched fail is a gate nobody has tested (#153). Time is
    injected rather than waited for.
    """
    from registry_fixtures import assert_fixtures_are_fresh

    oldest = min(load_fixture(e, n).captured_at for e, n in declared_fixtures())
    newest = max(load_fixture(e, n).captured_at for e, n in declared_fixtures())

    ageing = oldest + timedelta(days=MANIFEST["warn_after_days"] + 1)
    with pytest.warns(UserWarning, match="past the .* refresh cadence"):
        warnings = assert_fixtures_are_fresh(today=ageing)
    assert warnings, "an ageing fixture must name itself"

    stale = newest + timedelta(days=MANIFEST["fail_after_days"] + 1)
    with pytest.raises(FixtureError, match="no longer describe the live registries"):
        assert_fixtures_are_fresh(today=stale)


def test_fixture_ids_cannot_escape_the_fixture_directory() -> None:
    """Captured payloads are untrusted data; their ids never become free paths."""
    for hostile in ("../secrets", "/etc/passwd", "a/b", "Express", ""):
        with pytest.raises(FixtureError):
            load_fixture("nodejs", hostile)
        with pytest.raises(FixtureError):
            load_fixture(hostile, "express")


def test_the_replay_fetcher_refuses_any_url_it_has_no_recording_for() -> None:
    """CI never reaches a registry: an unrecorded URL raises instead of fetching."""
    fixture = load_fixture("nodejs", "express")
    fetch = replay_fetcher({"express": fixture})

    assert fetch(fixture.source_url) is fixture.payload
    with pytest.raises(AssertionError, match="do not let this fall through"):
        fetch("https://registry.npmjs.org/lodash")


def test_fixtures_stay_within_the_size_bound() -> None:
    """A bounded recording is a bounded parse; the loader refuses anything over.

    ``load_fixture`` enforces the bound itself, so a fixture that grew past it
    raises here rather than at whatever test happens to load it first.
    """
    bound = MANIFEST["max_fixture_bytes"]
    assert 0 < bound <= 1024 * 1024

    for ecosystem, name in declared_fixtures():
        assert load_fixture(ecosystem, name).name == name


def test_no_fixture_carries_a_credential_shaped_value() -> None:
    """Recorded registry documents are scanned before they are trusted.

    Public registries have no business serving a token, which is exactly why a
    token appearing in one would matter. The scan runs on load, so it also
    covers a fixture captured from a private or proxying registry.
    """
    for ecosystem, name in declared_fixtures():
        load_fixture(ecosystem, name)  # raises FixtureError on a match


def test_trimming_removed_volume_and_never_a_schema_key() -> None:
    """The capture may drop 285 release manifests; it may not drop a key.

    "Trimmed to the keys the adapter reads" is the sentence that made four of
    #145's five dead reads undetectable. Every note a reducer leaves behind has
    to be about volume.
    """
    for ecosystem, name in declared_fixtures():
        fixture = load_fixture(ecosystem, name)
        for note in fixture.trimming:
            assert any(
                token in note
                for token in ("volume only", "no longer present", "truncated")
            ), f"{fixture.slug}: trimming note does not describe volume: {note}"


# --- The ledger ------------------------------------------------------------


def test_the_conversion_ledger_is_honest() -> None:
    """Every ecosystem is listed, converted ones have a driver, pending say why.

    The ledger claims all nine are converted, so this checks the claim from
    both ends: nothing is marked converted without a driver, a polarity table,
    a coverage-floor case and at least one value assertion behind it, and
    nothing with a floor is missing from the ledger.
    """
    assert set(CONVERSION_STATUS) == set(MIN_MEASURED_SIGNALS), (
        "the ledger and the floor table describe the same nine ecosystems; a "
        "key in one and not the other is a half-registered adapter"
    )
    assert set(CONVERSION_STATUS) >= set(DRIVERS)

    converted = converted_ecosystems()
    assert set(converted) == set(DRIVERS), (
        "an ecosystem marked converted with no driver is a claim with nothing "
        "behind it"
    )
    for ecosystem in converted:
        assert ecosystem in POLARIZED_SIGNALS
        assert any(case.ecosystem == ecosystem for case in CASES)
        assert any(
            case.ecosystem == ecosystem and case.meets_signal_floor for case in CASES
        ), f"{ecosystem} has no coverage-floor case"

    pending = [k for k, v in CONVERSION_STATUS.items() if not v.converted]
    for ecosystem in pending:
        assert "PENDING" in CONVERSION_STATUS[ecosystem].note


def test_every_ecosystem_with_an_adapter_is_under_the_value_harness() -> None:
    """No adapter scores dependencies without a captured value gate behind it.

    The ledger's own honesty check (above) is satisfied by any consistent
    story, including a shrinking one. This is the ratchet: every ecosystem the
    tool can analyze must be converted, so removing a conversion fails here
    rather than passing as a smaller-but-consistent table.
    """
    unconverted = sorted(set(MIN_MEASURED_SIGNALS) - set(converted_ecosystems()))

    assert not unconverted, (
        f"{unconverted} score dependencies with no per-signal value gate. A "
        f"count-based floor cannot see a signal that is always measured and "
        f"always wrong, which is the whole of #145."
    )
