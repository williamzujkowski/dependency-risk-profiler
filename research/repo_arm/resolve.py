"""Stage 2, first half: what repository each cohort package declared at T.

**The declaration is read at T, never today.** ``repository_at`` returns the
URL frozen into the version document in force at T, so a package that moved
its repository afterwards is still asked about the repository it had. Reading
``package.json`` from the registry today would observe the post-outcome world,
which is the leak §4b exists to prevent.

**Parsing is deliberately strict, and a rejection is recorded rather than
repaired.** ``extract_github_repo_info`` anchors on the end of the URL, so it
returns a pair for ``.../owner/repo.git#main`` in which the repository name is
``repo.git#main`` — a string GitHub cannot name. Handing that to ``git clone``
would produce a 404 that this study would then have to interpret as a deleted
repository. The two patterns below reject it up front as *unparseable*, which
is a different fact from *deleted* and is reported as one.

The charset rules are GitHub's own: an owner is alphanumeric with internal
hyphens and at most 39 characters, a repository name adds ``.`` and ``_``.
Applied to the 2024-08-01 cohort they yield 2,066 packages over 1,749 distinct
repositories, which is the population §6 and §4c size the study against.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from abandonment_pilot.cohort import CohortMember
from abandonment_pilot.snapshot import PackageRecord, repository_at
from dependency_risk_profiler.utils import extract_github_repo_info

#: A GitHub account name: alphanumeric, internal hyphens, 39 characters max.
_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")

#: A GitHub repository name. Wider than an owner: dots and underscores are
#: legal, which is why ``repo.git#main`` fails on the ``#`` and not the dot.
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

#: A declaration naming github.com that this module could not turn into an
#: ``owner/repo`` pair. Counted, never cloned.
UNPARSEABLE = "github_unparseable"

#: No repository field at all in the version document in force at T.
UNDECLARED = "no_declaration"

#: A repository on some host other than github.com, including GitHub
#: Enterprise installations, whose contents this arm has no access to.
OTHER_HOST = "other_host"

#: A declaration this arm can attempt to clone.
GITHUB = "github"


@dataclass(frozen=True)
class Declaration:
    """One cohort package's repository declaration, as read at T."""

    package: str
    #: The URL exactly as the registry froze it, or None when absent.
    url: Optional[str]
    #: One of :data:`GITHUB`, :data:`UNDECLARED`, :data:`OTHER_HOST`,
    #: :data:`UNPARSEABLE`.
    category: str
    #: ``owner/repo`` when :data:`GITHUB`, else None.
    slug: Optional[str]
    #: True when the package published no release in ``(T, T + 2y]``.
    abandoned: bool


def _mentions_github(url: str) -> bool:
    """Return whether a URL refers to github.com rather than another forge.

    ``github.example.com`` and ``github.deutsche-boerse.de`` are GitHub
    Enterprise installations on someone else's domain; they are other hosts,
    not github.com, and matching on the bare word ``github`` would swallow
    them.

    Args:
        url: The declared URL.

    Returns:
        True when the declaration names github.com or npm's ``github:`` short
        form.
    """
    lowered = url.lower()
    return "github.com" in lowered or lowered.startswith("github:")


def classify(
    members: Sequence[CohortMember], records: Dict[str, PackageRecord]
) -> Tuple[Declaration, ...]:
    """Read and classify every cohort member's repository declaration at T.

    Args:
        members: The cohort at T.
        records: Snapshot records by package name.

    Returns:
        One declaration per member, in the members' order.
    """
    out: List[Declaration] = []
    for member in members:
        raw = repository_at(records[member.name], member.index_at_t)
        url = str(raw).strip() if raw is not None else ""
        if not url:
            out.append(
                Declaration(member.name, None, UNDECLARED, None, member.abandoned)
            )
            continue
        info = extract_github_repo_info(url)
        if info is not None and _OWNER.match(info[0]) and _REPO.match(info[1]):
            slug = f"{info[0]}/{info[1]}"
            out.append(Declaration(member.name, url, GITHUB, slug, member.abandoned))
        elif _mentions_github(url):
            out.append(
                Declaration(member.name, url, UNPARSEABLE, None, member.abandoned)
            )
        else:
            out.append(
                Declaration(member.name, url, OTHER_HOST, None, member.abandoned)
            )
    return tuple(out)


def distinct_slugs(declarations: Sequence[Declaration]) -> Tuple[str, ...]:
    """Return the distinct ``owner/repo`` slugs, sorted.

    Monorepos publish many packages from one repository, so the clone unit is
    the repository and the analysis unit stays the package.

    Args:
        declarations: Classified declarations.

    Returns:
        Each slug once, in sorted order.
    """
    return tuple(
        sorted({d.slug for d in declarations if d.slug is not None})
    )
