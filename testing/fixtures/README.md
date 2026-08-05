# Test Fixtures

This directory contains reusable test data and mock objects for the Dependency Risk Profiler tests.

Fixtures help create consistent test environments and reduce duplication across tests.
EOF < /dev/null

## `repo_layouts/` — captured repository file layouts

Conformance fixtures for the `scorecard/` presence checks, which answer their
questions with `pathlib` existence checks off a shallow clone. What a faithful
fixture has to reproduce is therefore the **set of paths** a real repository
has, and nothing else.

Recorded by `scripts/capture_repo_layouts.py` from real clones at a pinned
commit, with the whole `git ls-files` output kept — no reducer, because any
reducer here would be a judgment about which paths matter, which is exactly the
judgment #291 found the checks getting wrong. `testing/unit/repo_layouts.py`
replays a recording onto disk, optionally minus a named directory so a test can
reduce a captured tree to a forge-native one at the call site.

Captured, never authored (AGENTS.md rule 5): a hand-built tree puts the pull
request template wherever the author believes the check looks, and every test
tree in this repository had a `.github/` directory for that reason while
Forgejo-native repositories reported having no templates at all.
