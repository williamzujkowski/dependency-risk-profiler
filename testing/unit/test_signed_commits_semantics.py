"""`signed_commits` must not report a finding it has not got (#389, #218).

Measured on eight real repositories: the collector returned a definite
``False`` -- a read finding -- for every repository on earth, because
"verified" meant "verifiable against a local keyring" and a fresh clone has no
keys. axios (every commit carries a signature) and golang/go (none do) were
indistinguishable: both False.

Everything here is offline. The git outputs are the real strings, recorded.
"""

from __future__ import annotations

import pytest

from dependency_risk_profiler.scorecard.signed_commits import (
    _COMMIT_STATUS_BUCKETS,
    _classify_tag_verification,
)


@pytest.mark.parametrize(
    "code,bucket",
    [
        ("G", "verified_commits"),
        ("B", "unverified_commits"),
        ("R", "unverified_commits"),
        ("U", "unverified_commits"),
        ("X", "unverified_commits"),
        ("Y", "unverified_commits"),
        ("E", "unverified_commits"),
        ("N", "no_signature_commits"),
    ],
)
def test_only_a_good_signature_counts_as_verified(code: str, bucket: str) -> None:
    """git's own semantics, which the previous table misdescribed.

    It recorded B as "valid signature but with expired key" -- git says B is a
    **BAD** signature -- and R as "valid signature, key expired" when git says
    it is a good signature made by a **REVOKED** key. Both were bucketed as
    verified, so a bad signature and a revoked key each counted as evidence
    that a project signs its commits.
    """
    assert _COMMIT_STATUS_BUCKETS[code] == bucket


def test_every_git_status_code_is_mapped() -> None:
    """A fall-through here would quietly answer the question (#236)."""
    assert set(_COMMIT_STATUS_BUCKETS) == set("GBRUXYEN")


@pytest.mark.parametrize(
    "output,expected",
    [
        ("gpg: Good signature from \"A\"", "verified_tags"),
        ("gpg: BAD signature from \"A\"", "unverified_tags"),
        ("error: no signature found", "no_signature_tags"),
        (
            "error: 0.1: cannot verify a non-tag object of type commit.",
            "no_signature_tags",
        ),
        (
            "gpg: Signature made Wed 18 Feb 2026\n"
            "gpg: Can't check signature: No public key",
            "unverified_tags",
        ),
        (
            "error: gpg.ssh.allowedSignersFile needs to be configured and "
            "exist for ssh signature verification",
            "unverified_tags",
        ),
    ],
)
def test_the_ordinary_states_of_a_fresh_clone_are_classified(
    output: str, expected: str
) -> None:
    """The two cases whose absence made the collector raise on real projects.

    "Can't check signature: No public key" is what gpg says about a signed tag
    when the signer's key was never imported -- the normal state of any clone,
    and observed on pallets/flask. The SSH variant is what git says when no
    allowed-signers file is configured, observed on sigstore/cosign, which
    signs every release tag.

    Both were absent from the table, so every sampled tag on those projects
    came back uninterpretable, the "no verdict for any tag" guard fired, and
    the whole signal raised rather than answering. The guard was right; the
    table was incomplete.
    """
    assert _classify_tag_verification(output) == expected


def test_an_unrecognised_output_still_establishes_nothing() -> None:
    """The guard this fix must not weaken.

    Adding the two missing cases is the fix. Turning the fall-through into a
    default would have been the other kind of fix, and would have hidden the
    next gap instead of surfacing it.
    """
    assert _classify_tag_verification("something git has never printed") is None
