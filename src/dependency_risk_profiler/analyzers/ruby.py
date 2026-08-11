"""Analyzer for Ruby (RubyGems) dependencies."""

import logging
from typing import Dict, List, Optional, Sequence

import requests

from ..models import DependencyMetadata
from ..parsers.ruby import runtime_dependency_names
from ..release_dates import (
    RepositoryResolution,
    apply_registry_release_date,
    parse_registry_timestamp,
    record_source_repository,
    resolve_repository,
)
from ..signals import FieldSource, ProvenancedField
from ..transitive.analyzer_enhanced import record_transitive_source
from .base import BaseAnalyzer
from .common import collect_repository_signals

logger = logging.getLogger(__name__)

RUBYGEMS_API_BASE = "https://rubygems.org/api/v1"
_USER_AGENT = "dependency-risk-profiler (metadata lookup)"

# Recorded so the transitive signal is treated as measured rather than as an
# assumed-empty set (#141, #204). The gem's runtime dependency list is already
# in the ``/gems/<name>.json`` payload this adapter fetches, at no extra
# request; ``development`` is a separate list and is not read.
TRANSITIVE_SOURCE_RUBYGEMS = "rubygems-runtime-dependencies"

# The words a maintainer uses when the gem's own blurb is the retirement
# notice. Same list the PyPI adapter sweeps its one-line summary for, because
# the phrasing is the same across ecosystems and a second list would drift.
_DESCRIPTION_DEPRECATION_TERMS: Sequence[str] = (
    "deprecated",
    "unmaintained",
    "abandoned",
)


class RubyGemsAnalyzer(BaseAnalyzer):
    """Analyzer for Ruby dependencies published on rubygems.org."""

    def __init__(self, timeout: int = 10):
        """Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        super().__init__(timeout)
        self.metadata_cache: Dict[str, Dict[str, object]] = {}

    def analyze(
        self, dependencies: Dict[str, DependencyMetadata]
    ) -> Dict[str, DependencyMetadata]:
        """Analyze Ruby dependencies and collect rubygems.org metadata.

        Args:
            dependencies: Dictionary mapping gem names to their metadata.

        Returns:
            Updated dictionary with collected metadata.
        """
        for name, dep in dependencies.items():
            logger.info("Analyzing Ruby gem: %s", name)
            # Route vulnerability lookups to the RubyGems OSV ecosystem.
            dep.additional_info["ecosystem"] = "rubygems"

            try:
                info = self._get_gem_info(name)
                if not info:
                    continue
                self.metadata_cache[name] = info
                self._apply_registry_metadata(dep, info)

                # Repository-derived signals (last commit, tests/CI, the
                # OpenSSF-style security checks) come from the source repo, the
                # same way the Python/npm/Go analyzers collect them.
                dep = collect_repository_signals(
                    dep, dep.repository_url, self.clone_repos
                )
                dependencies[name] = dep

                # Gem owners are RubyGems' own maintainer set (who may push a
                # release). Read them after the repository pass so the shallow
                # clone's contributor count — always ~1 — can't stand in for it.
                owner_count = self._get_owner_count(name)
                if owner_count is not None:
                    dep.maintainer_count = owner_count
                    dep.record_field_source(
                        ProvenancedField.MAINTAINER_COUNT,
                        FieldSource.REGISTRY_METADATA,
                    )
            except Exception as exc:
                logger.error("Error analyzing Ruby gem %s: %s", name, exc)

        return dependencies

    def _apply_registry_metadata(
        self, dep: DependencyMetadata, info: Dict[str, object]
    ) -> None:
        """Copy the rubygems.org payload onto the fields the scorer reads.

        Args:
            dep: Dependency metadata to update in place.
            info: rubygems.org ``/gems/<name>.json`` payload.
        """
        latest = info.get("version")
        if isinstance(latest, str) and latest:
            dep.latest_version = latest

        # The payload's ``dependencies`` object splits the gemspec's declared
        # dependencies by scope. Only ``runtime`` is what installing the gem
        # pulls in; ``development`` is the build/test set and is not read, for
        # composer's ``require-dev`` reason. See the parser for the shape trap:
        # this value is an object, not a list.
        shipped = runtime_dependency_names(info.get("dependencies"))
        if shipped is not None:
            dep.transitive_dependencies = shipped - {dep.name}
            record_transitive_source(dep, source=TRANSITIVE_SOURCE_RUBYGEMS)

        # ``source_code_uri`` is RubyGems' designated source pointer, read raw
        # so a gem naming a repository nobody can clone stays distinguishable
        # from one naming none (#176). ``homepage_uri`` remains a resolution
        # fallback: hpricot's is code.whytheluckystiff.net, a dead host that was
        # never a declaration of source in the first place.
        resolution = self._resolve_repository(info)
        if resolution.url:
            dep.repository_url = resolution.url
        record_source_repository(dep, resolution)

        # RubyGems dates the latest release, not the repository; it is the
        # release cadence a consumer of the gem actually sees, and it now wins
        # over a clone's last commit rather than being overwritten by it (#146).
        apply_registry_release_date(
            dep, parse_registry_timestamp(info.get("version_created_at"))
        )

        # RubyGems *removes* a yanked release rather than tombstoning it, so
        # this read cannot fire against today's API (#170). Checked live
        # against rubygems.org, all four places a yank could surface:
        #
        #   /api/v1/gems/<name>.json         answers with the newest release
        #                                    that still exists and reports
        #                                    yanked: false for every gem.
        #   /api/v1/versions/<name>.json     carries no `yanked` key at all and
        #                                    omits withdrawn releases outright
        #                                    (rest-client 1.6.10, strong_password
        #                                    0.0.7 and bootstrap-sass 3.2.0.3 are
        #                                    all simply absent).
        #   /api/v2/rubygems/<name>/         reports yanked: false, and 404s the
        #     versions/<version>.json        moment a release is withdrawn.
        #   index.rubygems.org/info/<name>   omits withdrawn releases too.
        #
        # A gem whose every release is yanked 404s on all of them, byte for byte
        # the answer a name that never existed gets, so "fully yanked" is not
        # separable from "not on rubygems.org" and is left honestly unmeasured
        # rather than guessed at. crates.io keeps the withdrawn release visible
        # with yanked: true, which is why the same idea IS capturable one
        # ecosystem over — the difference is the registry's model, not the read.
        # The read stays because it costs nothing and is right the day
        # rubygems.org starts sending it; it is not the deprecation signal here.
        #
        # Recorded either way once there is a gem document to read: "the gem's
        # own blurb does not name it retired" is what rubygems.org answers, and
        # it is a measurement rather than an assumption (#320).
        if info:
            dep.record_deprecation(
                deprecated=(
                    info.get("yanked") is True
                    or self._description_declares_deprecation(info)
                )
            )

    @staticmethod
    def _description_declares_deprecation(info: Dict[str, object]) -> bool:
        """Return whether the gem's own blurb names it deprecated.

        With the ``yanked`` branch unreachable (see above), this is the only
        deprecation evidence the ``/gems/<name>.json`` payload carries. RubyGems
        publishes the gemspec description as ``info``, and a gemspec description
        is a sentence or two the maintainer writes on purpose ("Ruby Sass is
        deprecated! See ... for details"), not the rendered README that made the
        same sweep unusable on PyPI (#171) — across 25 sampled gems the longest
        was 803 characters and the median under 100.

        Low yield is expected and accepted: it caught 2 of those 25, the same
        shape as PyPI's summary read catching only ``sklearn`` out of five
        known-deprecated packages. Most retired gems (paperclip, syck,
        protected_attributes) never say so anywhere a registry can be asked. It
        shares PyPI's one exposure, a gem that *provides* deprecated APIs rather
        than being deprecated itself; that phrasing is rare enough, and near
        enough to true when it happens, to be worth the recall.

        Args:
            info: The ``/gems/<name>.json`` payload.

        Returns:
            True when the description names the gem as deprecated.
        """
        description = info.get("info")
        if not isinstance(description, str) or not description:
            return False
        lowered = description.lower()
        return any(term in lowered for term in _DESCRIPTION_DEPRECATION_TERMS)

    @staticmethod
    def _resolve_repository(info: Dict[str, object]) -> RepositoryResolution:
        """Return RubyGems' one answer about where this gem's source lives.

        ``source_code_uri`` is the declaration and RubyGems publishes it both
        at the top level and inside ``metadata``; either spelling counts.
        ``homepage_uri``, in both spellings, is the resolution fallback — gems
        commonly point at a tagged subpath (``.../tree/v2.0.6``), which the
        canonicalizer trims back to ``owner/repo``.

        RubyGems is the ecosystem this matters most in: 15.35% of sampled gems
        declare their repository over plain ``http://``, and ``mail``,
        ``rainbow``, ``arel`` and ``coderay`` all publish a ``source_code_uri``
        of ``http://github.com/...`` — the designated field, naming a supported
        host, discarded over the scheme until #290.

        Args:
            info: The ``/gems/<name>.json`` payload.

        Returns:
            The resolution the gem's metadata supports.
        """
        metadata = info.get("metadata")
        nested: Dict[str, object] = metadata if isinstance(metadata, dict) else {}
        return resolve_repository(
            declarations=[
                _string_or_none(info.get("source_code_uri")),
                _string_or_none(nested.get("source_code_uri")),
            ],
            fallbacks=[
                _string_or_none(info.get("homepage_uri")),
                _string_or_none(nested.get("homepage_uri")),
            ],
        )

    def _get_gem_info(self, gem_name: str) -> Optional[Dict[str, object]]:
        """Return rubygems.org metadata for a gem, or None on failure."""
        payload = self._get_json(f"{RUBYGEMS_API_BASE}/gems/{gem_name}.json")
        return payload if isinstance(payload, dict) else None

    def _get_owner_count(self, gem_name: str) -> Optional[int]:
        """Return the number of registered owners for a gem, or None on failure."""
        payload = self._get_json(f"{RUBYGEMS_API_BASE}/gems/{gem_name}/owners.json")
        if not isinstance(payload, list):
            return None
        owners: List[object] = payload
        return len(owners) if owners else None

    def _get_json(self, url: str) -> Optional[object]:
        """Fetch and decode a rubygems.org JSON endpoint, or None on failure."""
        headers = {"User-Agent": _USER_AGENT}
        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.debug("rubygems.org lookup failed for %s: %s", url, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            payload: object = response.json()
        except ValueError:
            return None
        return payload


def _string_or_none(value: object) -> Optional[str]:
    """Return a non-empty string value, or None for anything else.

    Args:
        value: Raw value from a rubygems.org payload, of any type.

    Returns:
        The stripped-of-nothing original string when it has content, else None.
    """
    if isinstance(value, str) and value.strip():
        return value
    return None
