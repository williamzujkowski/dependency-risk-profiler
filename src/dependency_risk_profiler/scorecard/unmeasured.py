"""Why a scorecard check could not answer, recorded rather than implied.

The five OpenSSF-style checks in this package answer presence questions by
reading a cloned repository: files, YAML, JSON, and ``git`` subprocesses. Until
#218 each of them opened with ``has_X = False`` and returned that initial value
on two paths that are not measurements — the broad ``except`` around the read,
and the branch taken when no repository was available at all. ``False`` is also
the right answer for a repository that genuinely ships no security policy, so an
unreadable ``.github/settings.yml`` came back indistinguishable from a measured
absence, and the scorer counted it as evidence.

The state is now carried by ``Optional[bool]``: ``None`` is unmeasured, and
``False`` is reserved for "we read the repository and the evidence was not
there". This module supplies the *reason*, so the two unmeasured paths do not
collapse into one undifferentiated silence.

The vocabulary is :class:`~dependency_risk_profiler.signals.UnmeasuredReason`,
reused rather than paralleled — the same enum the scorer records for every other
signal (#164, #225). No member is invented here, and the fact-to-reason mapping
lives in one place:

* no repository to read at all -> ``SOURCE_REPOSITORY_UNREADABLE``
* a read was attempted against a repository and raised ->
  ``SOURCE_LOOKUP_FAILED``

Both recorders take every argument they need with no defaults, so neither state
can be reached by forgetting something (AGENTS.md rule 4).
"""

from ..signals import UnmeasuredReason


def no_repository_issue(check: str) -> str:
    """Record that a check had no repository to read.

    The caller passed no ``repo_dir``, so nothing was opened and nothing was
    found absent. This is the ``SOURCE_REPOSITORY_UNREADABLE`` case: the
    repository-derived signal had nothing to read.

    Args:
        check: Human-readable name of the check, e.g. ``"Security policy"``.
            Required, so an issue line cannot omit which signal it explains.

    Returns:
        The issue line to report, naming the reason.
    """
    return (
        f"{check} unmeasured "
        f"({UnmeasuredReason.SOURCE_REPOSITORY_UNREADABLE.value}): "
        "no repository was available to read"
    )


def read_failed_issue(check: str, error: BaseException) -> str:
    """Record that a check read a repository and the read failed.

    Distinct from :func:`no_repository_issue` on purpose. A repository was
    there, the read ran, and it did not produce a readable answer — an
    unreadable file, a git subprocess that exited non-zero, a payload this code
    cannot interpret. That is ``SOURCE_LOOKUP_FAILED``, and it is the reason the
    output must show instead of a confident negative finding.

    Args:
        check: Human-readable name of the check, e.g. ``"Branch protection"``.
        error: The exception the read raised. Required, so the line cannot be
            emitted without saying what actually went wrong.

    Returns:
        The issue line to report, naming the reason and the failure.
    """
    return (
        f"{check} unmeasured ({UnmeasuredReason.SOURCE_LOOKUP_FAILED.value}): "
        f"{type(error).__name__}: {error}"
    )
