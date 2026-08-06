"""The GitHub adapter, and the three facts a clone of a GitHub repo cannot give.

GitHub hosts 97.49% of the packages that declare a forge at all, measured over
8,870 packages across eight ecosystems (#289). That share is why it is the
adapter the contract is proved against: it is the one forge whose answers can
be checked against what this tool already produced.

Each capability is served by a different acquisition path, and they are not
worth the same:

* ``CONTRIBUTOR_COUNT`` and ``COMMIT_FREQUENCY`` come from the REST API with
  the single-request pagination trick — ask for one item per page and read the
  last page number out of the ``Link`` header. Both need a token. Without one
  the answer is ``UNMEASURED``, never a guess from the shallow clone, whose
  answer is one contributor and one commit for every repository in existence.
* ``STAR_COUNT`` is regexed out of the unauthenticated repository page. It is
  the weakest source in the tool and is marked as such: an org scan's
  authenticated API overwrites it, and
  :attr:`~dependency_risk_profiler.signals.FieldSource.GITHUB_HTML_SCRAPE` is
  what tells a consumer which of the two they are holding. GitHub publishes no
  anonymous star count anywhere else, so the alternative is not a better
  source but no signal at all.

Declaring a capability describes the endpoint, not the outcome. All three are
declared unconditionally; a call without a token, against a repository that
404s, or against an API that does not answer comes back ``UNMEASURED`` with
the reason. That split is the contract's, not this module's.
"""

import logging
import re
from typing import Optional

from ..signals import FieldSource, UnmeasuredReason
from ..utils import fetch_url, github_commit_frequency, github_contributor_count
from . import (
    CanonicalRepo,
    ForgeAdapter,
    ForgeAnswer,
    ForgeCapability,
    ForgeRegistry,
    ForgeSoftware,
)

logger = logging.getLogger(__name__)

#: Patterns that carry a star count on a rendered GitHub repository page, in
#: preference order. Three spellings because GitHub restyles the page and the
#: older markup persists on cached and proxied responses; the ``aria-label``
#: form is the most stable because it exists for screen readers rather than
#: for layout.
_STAR_PATTERNS = (
    r'aria-label="([0-9,]+) users starred this repository"',
    r'<span class="Counter js-social-count">([0-9,k]+)</span>',
    r'<a class="social-count js-social-count" [^>]*>([0-9,k]+)</a>',
)


def extract_star_count(html_content: str) -> Optional[int]:
    """Extract a star count from a GitHub repository page.

    Args:
        html_content: The rendered repository page.

    Returns:
        The star count, or ``None`` when no pattern matched or the matched text
        did not parse. ``None`` is the honest answer for markup this code
        cannot read: the page is GitHub's to restyle, and a number guessed out
        of an unrecognised layout would be worse than an absent signal.
    """
    if not html_content:
        return None

    for pattern in _STAR_PATTERNS:
        match = re.search(pattern, html_content)
        if not match:
            continue
        count_str = match.group(1).replace(",", "")
        if "k" in count_str.lower():
            # The compact form GitHub renders above a thousand: "1.2k".
            count_str = count_str.lower().replace("k", "")
            try:
                return int(float(count_str) * 1000)
            except ValueError:
                continue
        try:
            return int(count_str)
        except ValueError:
            continue

    return None


class GitHubAdapter(ForgeAdapter):
    """Answers the three forge-only facts for repositories on github.com."""

    software = ForgeSoftware.GITHUB
    capabilities = frozenset(
        {
            ForgeCapability.STAR_COUNT,
            ForgeCapability.CONTRIBUTOR_COUNT,
            ForgeCapability.COMMIT_FREQUENCY,
        }
    )

    def fetch(
        self,
        repo: CanonicalRepo,
        capability: ForgeCapability,
        token: Optional[str],
    ) -> ForgeAnswer:
        """Ask GitHub for one fact about one repository.

        Args:
            repo: The repository to ask about.
            capability: Which fact to fetch. Only a declared capability
                reaches here; the router answers the rest.
            token: A GitHub token, when the caller resolved one. The two REST
                capabilities need it and answer ``UNMEASURED`` without one.

        Returns:
            The fact and the path that produced it, or the reason GitHub did
            not supply it.

        Raises:
            ValueError: If asked for a capability this adapter declares and
                does not handle. Unreachable through the router, and a loud
                failure is the right answer to a declaration that outran its
                implementation.
        """
        if capability is ForgeCapability.CONTRIBUTOR_COUNT:
            count = github_contributor_count(repo.clone_url, token)
            if count is None:
                return ForgeAnswer.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)
            return ForgeAnswer.measured(
                float(count), FieldSource.GITHUB_API_CONTRIBUTORS
            )

        if capability is ForgeCapability.COMMIT_FREQUENCY:
            frequency = github_commit_frequency(repo.clone_url, token)
            if frequency is None:
                return ForgeAnswer.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)
            return ForgeAnswer.measured(frequency, FieldSource.GITHUB_API_COMMITS)

        if capability is ForgeCapability.STAR_COUNT:
            html = fetch_url(f"https://{repo.host}/{repo.owner}/{repo.name}")
            if not html:
                return ForgeAnswer.unmeasured(UnmeasuredReason.SOURCE_LOOKUP_FAILED)
            stars = extract_star_count(html)
            if stars is None:
                return ForgeAnswer.unmeasured(UnmeasuredReason.NO_DATA_FROM_SOURCE)
            return ForgeAnswer.measured(float(stars), FieldSource.GITHUB_HTML_SCRAPE)

        raise ValueError(f"GitHubAdapter declares {capability} and does not serve it")


def register() -> None:
    """Register the GitHub adapter and the hosts that route to it.

    The suffix matcher covers GitHub Enterprise Cloud's per-tenant subdomains,
    which serve the same API under the same paths. It is dot-anchored, so a
    lookalike host such as ``github.com.evil.example`` does not match — the
    check is on a parent domain, not a substring.
    """
    ForgeRegistry.register_adapter(
        GitHubAdapter,
        [
            {"type": "host", "pattern": "github.com"},
            {"type": "suffix", "pattern": "github.com"},
        ],
    )
