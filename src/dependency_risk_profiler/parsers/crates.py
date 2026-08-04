"""Reader for the crates.io per-version dependencies document."""

import logging
from typing import Mapping, Optional, Sequence, Set

logger = logging.getLogger(__name__)

# Cargo's dependency kinds, as crates.io spells them. ``normal`` is
# ``[dependencies]``: what a consumer of the crate compiles against. ``dev`` is
# ``[dev-dependencies]`` — tests, examples, benchmarks — and ``build`` is
# ``[build-dependencies]``, which runs at build time and ships with nothing.
# Only the first is a consumer's runtime surface, which is the same line maven
# draws with scopes and composer with ``require`` versus ``require-dev``.
RUNTIME_DEPENDENCY_KIND = "normal"
NON_RUNTIME_DEPENDENCY_KINDS = ("dev", "build")


def runtime_dependency_names(payload: object) -> Optional[Set[str]]:
    """Return the crates a ``/crates/<name>/<version>/dependencies`` doc names.

    Two things here are easy to get wrong and both are visible in one real
    crate. ``acid-store`` 0.14.2 publishes 42 entries: 32 ``normal`` and 10
    ``dev``.

    * **Counting the array is wrong**, and not only by the ten dev entries. It
      double-counts: ``rand`` and ``tempfile`` each appear *twice* in that
      list, once as a ``dev`` dependency and once as an optional ``normal``
      one. Names are collected into a set after the kind filter, so the same
      crate named under two kinds is one dependency.
    * **``optional`` is not a scope and is not filtered.** An optional
      dependency is a ``[dependencies]`` entry behind a feature gate; it is a
      declared runtime dependency of the crate, and a consumer who turns the
      feature on compiles it. Excluding it would need the crate's default-feature
      closure resolved, which is a resolver rather than a read, and would put
      cargo on a different line from maven (which counts ``<optional>``
      dependencies) and nuget (whose nuspec groups are all counted). The
      runtime/dev/build axis is the scope axis; features are a second one.

    ``target``-conditional entries (``cfg(unix)``) are counted for the same
    reason: they are runtime dependencies on the platforms they name.

    Args:
        payload: The decoded ``/api/v1/crates/<name>/<version>/dependencies``
            document, or None when the request did not answer.

    Returns:
        The runtime crate names, or None when no dependencies document was
        read at all — which must stay distinguishable from a crate that has
        none (#141, #199).
    """
    if not isinstance(payload, Mapping):
        return None
    dependencies = payload.get("dependencies")
    if not isinstance(dependencies, Sequence) or isinstance(dependencies, (str, bytes)):
        logger.debug("crates.io dependencies document carries no 'dependencies' list")
        return None

    names: Set[str] = set()
    for entry in dependencies:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("kind") != RUNTIME_DEPENDENCY_KIND:
            continue
        # ``crate_id`` is the published crate, which is what a consumer is
        # exposed to. A Cargo.toml may bind it to a different local name with
        # ``package = "..."``; crates.io records the real one here.
        name = entry.get("crate_id")
        if isinstance(name, str) and name.strip():
            names.add(name.strip())
    return names
