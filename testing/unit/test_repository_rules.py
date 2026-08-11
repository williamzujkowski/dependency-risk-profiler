"""Enforce the AGENTS.md rules that can be checked mechanically.

AGENTS.md rule 6 says a gate never observed to fail is unverified. A file of
prose is exactly that, so the rules that *can* be enforced are enforced here.

Each check in this module was verified to fail before it was committed, by
reintroducing a specimen of the defect it catches:

* rule 1 -- restoring ``scan_for_malware``'s "always clean in this example"
* rule 3 -- adding a module-level function with no caller
* rule 8 -- adding a ``# type: ignore`` to a source file

Rules 2 (rescope, don't stub), 4 (silence is not an answer) and 5 (fixtures
are captured) are review-time judgment and are deliberately absent. Not every
rule can be mechanised; a rule that can be and isn't is just a wish.

**A check here that fires on legitimate work is a bug in the check.** Fix the
check or argue the rule in review -- do not silence it.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple

SRC = Path(__file__).resolve().parents[2] / "src" / "dependency_risk_profiler"
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _source_files() -> List[Path]:
    """Return every first-party source file.

    Returns:
        Sorted list of ``.py`` files under the package.
    """
    return sorted(SRC.rglob("*.py"))


# --------------------------------------------------------------------------
# Rule 1 -- no simulated implementations
# --------------------------------------------------------------------------

# Phrases that mark a body as standing in for work not done. Deliberately
# specific: "simulate" alone appears in legitimate prose about simulating a
# scan in a *test*, so each pattern here names the shape of an admission.
STUB_MARKERS: Tuple[Tuple[str, str], ...] = (
    (r"in a real implementation", "admits the body is not the real thing"),
    (r"for simulation purposes", "admits the body is a stand-in"),
    (r"simulate (?:creating|scanning|checking|fetching|generating)", "simulates work"),
    (r"always clean in this example", "hardcodes a passing security verdict"),
    (r"this would (?:call|use|invoke) (?:an? )?(?:actual|real)", "defers the real call"),
    (r"placeholder (?:implementation|for now)", "declares itself a placeholder"),
)


def test_no_simulated_implementations() -> None:
    """AGENTS.md rule 1: a function does what its name says or does not exist.

    The motivating defect: a code-signing subsystem whose docstrings said
    "In a real implementation, this would..." -- a fresh random key per call,
    ``sha256(hash + key)`` in place of a signature, and a malware scan
    hardcoded to return clean -- called by ``release.yml`` on every tag.
    """
    offenders: List[str] = []
    for path in _source_files():
        text = path.read_text(encoding="utf-8")
        for pattern, why in STUB_MARKERS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                line = text[: match.start()].count("\n") + 1
                offenders.append(
                    f"{path.relative_to(SRC.parent.parent)}:{line} "
                    f"{why} -- {match.group(0)!r}"
                )

    assert not offenders, (
        "AGENTS.md rule 1: no simulated implementations.\n"
        "A function does what its name says, or it does not exist. If the real "
        "thing cannot be built now, file an issue and land nothing.\n\n"
        + "\n".join(offenders)
    )


# --------------------------------------------------------------------------
# Rule 3 -- landed code must be reachable
# --------------------------------------------------------------------------

# Names that are reachable by a mechanism this walk cannot see.
_REACHABLE_BY_CONVENTION = re.compile(
    r"^(?:_.*|main|test_.*|.*Error|.*Exception)$",
)


def _is_registered_by_decorator(node: ast.AST) -> bool:
    """Return whether a definition is reached by a registration decorator.

    A Typer command or a click callback is never referenced by name -- the
    decorator hands it to a registry at import time. Treating those as dead
    would fire on legitimate work, which AGENTS.md says is a bug in the check.

    Args:
        node: A function or class definition node.

    Returns:
        True when any decorator is applied.
    """
    return bool(getattr(node, "decorator_list", []))


def _defined_names(tree: ast.AST) -> Set[str]:
    """Return module-level function and class names defined in a tree.

    Args:
        tree: Parsed module.

    Returns:
        Set of public top-level definition names that are not registered by a
        decorator.
    """
    names: Set[str] = set()
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _REACHABLE_BY_CONVENTION.match(node.name):
                continue
            if _is_registered_by_decorator(node):
                continue
            names.add(node.name)
    return names


def test_every_public_definition_has_a_reference() -> None:
    """AGENTS.md rule 3: unreached code does not land.

    Dead code is worse than absent code -- every future reader has to
    re-derive that it is dead, and tests written against it give false
    confidence. This repository carried a 189-line module with zero callers
    and a scoring branch whose only coverage came from tests supplying data
    production never sends.
    """
    # Scan the tests too: a function reached only by a test is still reached,
    # and calling it dead here would fire on legitimate work. "Production code
    # whose only caller is a test" is a real but *weaker* finding and is
    # tracked separately rather than conflated with this one.
    tests_dir = Path(__file__).resolve().parents[1]
    files = _source_files()
    corpus: Dict[Path, str] = {p: p.read_text(encoding="utf-8") for p in files}
    for extra in tests_dir.rglob("*.py"):
        corpus[extra] = extra.read_text(encoding="utf-8")

    unreferenced: List[str] = []
    # Definitions come from src/ only. Test helpers and test classes are
    # discovered by pytest rather than referenced by name, so treating them as
    # definitions would fire on legitimate work.
    for path in files:
        text = corpus[path]
        try:
            tree = ast.parse(text)
        except SyntaxError:  # pragma: no cover - a syntax error fails elsewhere
            continue
        for name in _defined_names(tree):
            word = re.compile(rf"\b{re.escape(name)}\b")
            hits = 0
            for other, other_text in corpus.items():
                if other == path:
                    # Its own file may reference it, but not only in the
                    # definition line itself.
                    hits += max(0, len(word.findall(other_text)) - 1)
                else:
                    hits += len(word.findall(other_text))
            if hits == 0:
                unreferenced.append(f"{path.relative_to(SRC.parent.parent)}: {name}")

    assert not unreferenced, (
        "AGENTS.md rule 3: landed code must be reachable.\n"
        "A new function needs a caller; a new class needs a user. If nothing "
        "references it, delete it.\n"
        "(Names exported as public API are still referenced by their "
        "__init__ -- a name reaching zero means truly nothing.)\n\n"
        + "\n".join(unreferenced)
    )


# --------------------------------------------------------------------------
# Rule 8 -- the bar
# --------------------------------------------------------------------------


def test_no_type_or_lint_suppressions_in_source() -> None:
    """AGENTS.md rule 8: no ``# type: ignore`` and no ``# noqa`` in ``src/``.

    The repository reached zero of both and the point of this check is that it
    stays there.
    """
    offenders: List[str] = []
    banned = (
        (re.compile(r"#\s*type:\s*ignore"), "# type: ignore"),
        (re.compile(r"#\s*noqa"), "# noqa"),
    )
    for path in _source_files():
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for pattern, label in banned:
                if pattern.search(line):
                    offenders.append(
                        f"{path.relative_to(SRC.parent.parent)}:{lineno} {label}"
                    )

    assert not offenders, (
        "AGENTS.md rule 8: the bar.\n"
        "Fix the type rather than silencing the checker. Fixing 63 errors in "
        "one pass and 11 in another, both with zero suppressions, is the "
        "precedent -- the bar is demonstrably achievable.\n\n"
        + "\n".join(offenders)
    )


# ``Any`` was stated as banned but never enforced: mypy's
# ``disallow_any_explicit`` is not set, so every use passed silently. This
# ratchet records where the repository actually is. It only moves DOWN --
# see the issue linked in AGENTS.md for the work to reach zero.
MAX_EXPLICIT_ANY: Dict[str, int] = {
    "aggregator.py": 20,
    "aggregator_async.py": 7,
    "async_http.py": 22,
    "cache.py": 4,
    "registry.py": 4,
    "toml.py": 5,
    "trends.py": 17,
    "utils.py": 3,
}


def test_explicit_any_never_increases() -> None:
    """AGENTS.md rule 8: the ``Any`` count ratchets down, never up.

    Stating a bar the tooling does not enforce is how this repository ended up
    with eleven mypy-exempt modules. Rather than weaken the rule or claim a
    zero that is not real, the current count is recorded and frozen.
    """
    any_pattern = re.compile(r"(?<![\w.])Any(?![\w])")
    counts: Dict[str, int] = {}
    for path in _source_files():
        hits = 0
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            hits += len(any_pattern.findall(line))
        if hits:
            counts[path.name] = hits

    regressions: List[str] = []
    for name, count in sorted(counts.items()):
        ceiling = MAX_EXPLICIT_ANY.get(name, 0)
        if count > ceiling:
            regressions.append(f"{name}: {count} uses of Any, ceiling is {ceiling}")

    assert not regressions, (
        "AGENTS.md rule 8: explicit Any ratchets down, never up.\n"
        "A new Any needs a real type instead. If a module drops to zero, "
        "remove its entry -- ceilings only move down.\n\n" + "\n".join(regressions)
    )


def test_uv_lock_is_tracked_and_not_ignored() -> None:
    """AGENTS.md rule 8: ``uv.lock`` is committed.

    The rule used to say the opposite, and the commit that introduced it
    committed ``uv.lock`` in the same change -- a bar and its violation
    shipping together. A 7-0 consensus vote resolved the contradiction in
    favour of committing the lockfile: it never reaches a consumer of this
    library, so it pins only the development environment, and a tool that
    scores other projects on pinning does not get to except itself.

    This check exists because the direction of the rule is not the lesson.
    The lesson is that three separate bars in this repository were stated and
    never enforced, so a fourth prose sentence was not going to hold either.
    """
    root = PYPROJECT.parent
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "uv.lock"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert tracked.returncode == 0, (
        "AGENTS.md rule 8: `uv.lock` is committed.\n"
        "It pins the development environment, which is the only environment it "
        "can reach -- the lockfile is not packaged into the wheel or the sdist.\n"
        "If this rule should change, change AGENTS.md and this test in the same "
        "diff. That coupling is the entire point of this check.\n\n"
        f"git ls-files said: {tracked.stderr.strip() or 'not tracked'}"
    )

    gitignore = root / ".gitignore"
    if gitignore.exists():
        ignored = [
            line
            for line in gitignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
            and line.strip().lstrip("/") == "uv.lock"
        ]
        assert not ignored, (
            "AGENTS.md rule 8: `uv.lock` is committed, so .gitignore must not "
            "list it. A tracked file that is also ignored is a trap: the next "
            "person to delete it locally will not see it come back.\n\n"
            + "\n".join(ignored)
        )


# --------------------------------------------------------------------------
# Rule 6 -- a required check must analyse its own subject
# --------------------------------------------------------------------------

# File extensions CodeQL associates with each language we enrol. Only the
# languages this repository actually enrols need an entry; an unmapped language
# fails loudly below rather than being skipped, because a silent skip here would
# be the very defect this check exists to catch.
_CODEQL_LANGUAGE_SUFFIXES: Dict[str, Tuple[str, ...]] = {
    "python": (".py",),
    "actions": (".yml", ".yaml"),
    "go": (".go",),
    "javascript-typescript": (".js", ".jsx", ".ts", ".tsx"),
    "java-kotlin": (".java", ".kt"),
    "ruby": (".rb",),
    "csharp": (".cs",),
}

# `actions` only ever analyses workflow definitions, wherever they live.
_CODEQL_LANGUAGE_ROOTS: Dict[str, str] = {"actions": ".github/workflows"}


def _fnmatch_any(path: str, patterns: List[str]) -> bool:
    """Return whether a repo-relative path matches any CodeQL ignore pattern.

    CodeQL's ``paths-ignore`` uses ``**`` to mean any number of directories.
    ``fnmatch`` treats ``*`` as crossing separators, which is close enough to
    over-match rather than under-match -- and over-matching here can only make
    this check stricter, never laxer.

    Args:
        path: Repository-relative path with forward slashes.
        patterns: Raw ``paths-ignore`` entries.

    Returns:
        True when the path is excluded from analysis.
    """
    for raw in patterns:
        pattern = raw.strip().strip('"')
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch("/" + path, pattern):
            return True
        # `**/testing/**` should also exclude a top-level `testing/...`.
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
            return True
    return False


def test_every_required_codeql_language_has_something_to_analyse() -> None:
    """AGENTS.md rule 6: a required check must analyse its own subject.

    ``Analyze (go)`` was one of six required merge-gate checks and reported
    SUCCESS for months while analysing **zero lines of Go**. Every ``.go`` file
    in the repository sat under ``testing/``, which ``codeql-config.yml``
    excludes, so the check's own scope excluded its own subject. It became a
    hard failure the moment that directory was deleted (#231) -- not because
    anything regressed, but because the emptiness finally became visible.

    A check that measures nothing is worse than an absent one: it occupies a
    slot in the required list and answers for a language nobody is analysing.
    """
    root = PYPROJECT.parent
    workflow = root / ".github" / "workflows" / "codeql.yml"
    config = root / ".github" / "codeql" / "codeql-config.yml"
    if not workflow.exists():  # pragma: no cover - workflow is committed
        return

    # Read the enrolled languages without a YAML dependency: the matrix entries
    # are `- language: <name>` lines under `include:`.
    languages = re.findall(
        r"^\s*-\s*language:\s*([\w-]+)", workflow.read_text(encoding="utf-8"), re.M
    )
    assert languages, (
        "AGENTS.md rule 6: could not read any CodeQL language from "
        f"{workflow.relative_to(root)}. If the matrix moved, move this check "
        "with it -- a parser that silently finds nothing is the defect."
    )

    ignore: List[str] = []
    if config.exists():
        block = re.search(
            r"^paths-ignore:\s*\n((?:\s*-\s*.+\n)+)",
            config.read_text(encoding="utf-8"),
            re.M,
        )
        if block:
            ignore = re.findall(r"-\s*(.+)", block.group(1))

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=False
    )
    assert tracked.returncode == 0, "git ls-files failed; cannot verify check scope"
    paths = tracked.stdout.splitlines()

    empty: List[str] = []
    for language in languages:
        suffixes = _CODEQL_LANGUAGE_SUFFIXES.get(language)
        assert suffixes is not None, (
            f"AGENTS.md rule 6: CodeQL language {language!r} is enrolled but this "
            "check does not know which files it analyses, so it cannot tell "
            "whether the check is vacuous. Add it to _CODEQL_LANGUAGE_SUFFIXES."
        )
        prefix = _CODEQL_LANGUAGE_ROOTS.get(language)
        analysed = [
            p
            for p in paths
            if p.endswith(suffixes)
            and (prefix is None or p.startswith(prefix))
            and not _fnmatch_any(p, ignore)
        ]
        if not analysed:
            empty.append(
                f"{language}: 0 tracked files survive paths-ignore "
                f"(suffixes {suffixes})"
            )

    assert not empty, (
        "AGENTS.md rule 6: a required check must analyse its own subject.\n"
        "One or more enrolled CodeQL languages have nothing left to analyse "
        "after paths-ignore. The check will report SUCCESS over an empty set, "
        "which is what `Analyze (go)` did for months.\n"
        "Either remove the language from the matrix, or fix the scope so it "
        "reaches the files it claims to cover.\n\n" + "\n".join(empty)
    )


# --------------------------------------------------------------------------
# Rule 5 -- a captured fixture may not carry a credential
# --------------------------------------------------------------------------

# High-confidence credential shapes. Deliberately narrow: this check runs over
# decoded fixture payloads, which are third-party source files full of ordinary
# identifiers, so a broad entropy heuristic would fire constantly and teach
# people to ignore it. Each pattern here is issued by a named provider in a
# fixed format.
_CREDENTIAL_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"AIza[0-9A-Za-z_-]{35}", "Google API key"),
    (r"sk_live_[0-9A-Za-z]{20,}", "Stripe secret key"),
    (r"pk_live_[0-9A-Za-z]{20,}", "Stripe publishable key"),
    (r"gh[pousr]_[0-9A-Za-z]{36}", "GitHub token"),
    (r"github_pat_[0-9A-Za-z_]{50,}", "GitHub fine-grained token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"glpat-[0-9A-Za-z_-]{20}", "GitLab token"),
    (r"npm_[0-9A-Za-z]{36}", "npm token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
)

# Values written by a redaction, which must not be mistaken for the thing they
# replaced.
_REDACTION_MARKER = re.compile(r"REDACTED-[A-Z-]+")


def _decoded_strings(node: object) -> List[str]:
    """Return every string value in a parsed JSON document.

    Args:
        node: A value from ``json.loads``.

    Returns:
        Every string reachable from the node, decoded -- so a payload stored as
        an escaped JSON string is searched as the text it represents.
    """
    found: List[str] = []
    if isinstance(node, str):
        found.append(node)
    elif isinstance(node, dict):
        for value in node.values():
            found.extend(_decoded_strings(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_decoded_strings(value))
    return found


def test_captured_fixtures_carry_no_credentials() -> None:
    """AGENTS.md rule 5: a capture may not republish someone's credentials.

    Conformance fixtures are captured verbatim from live third-party projects,
    which is what makes them able to reveal a dead read -- and what makes them
    able to carry a real key. Signal's Android build file arrived with a Google
    Maps key and two Stripe publishable keys.

    This check exists because a general secret scanner cannot see them. A
    fixture stores its payload as a JSON string, so a key inside it is written
    ``\\"AIza...\\"`` -- the escaped quote defeats the trailing word boundary
    that provider rules use, and the scanner reports the file clean. Verified
    against gitleaks: the identical key is found in a ``.txt`` file, found in a
    ``.json`` file as raw text, and **missed** once JSON-encoded.

    So the payloads are decoded first and searched as the source they are.
    """
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    if not fixtures.is_dir():  # pragma: no cover - fixtures are committed
        return

    offenders: List[str] = []
    for path in sorted(fixtures.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):  # pragma: no cover
            continue
        for text in _decoded_strings(document):
            for pattern, label in _CREDENTIAL_PATTERNS:
                for match in re.finditer(pattern, text):
                    if _REDACTION_MARKER.search(match.group(0)):
                        continue
                    offenders.append(
                        f"{path.relative_to(fixtures.parent.parent)}: {label}"
                    )

    assert not offenders, (
        "AGENTS.md rule 5: a captured fixture may not carry a credential.\n"
        "Capturing from a live project is what lets a fixture reveal a dead "
        "read; it is also how a real key arrives. Redact the value, record the "
        "redaction and its reason in the fixture, and keep the capture "
        "otherwise verbatim.\n\n" + "\n".join(sorted(set(offenders)))
    )


def test_secret_scan_reads_the_tree_and_proves_it_can_fail() -> None:
    """AGENTS.md rule 6: a required check must analyse its own subject.

    The secret scan is the second check to fail this rule, and it failed it
    twice over. It ran ``gitleaks-action``, which scans a commit range on
    ``pull_request`` events:

    * The range never resolved. ``actions/checkout`` fetches shallow, so
      ``<base>^`` was absent, git errored, and the scan printed
      ``scanned ~0 bytes (0)`` and then ``no leaks found``. The job went red
      only because the action surfaced git's exit code; the scanner's own
      verdict on zero bytes was a pass.
    * A range scan cannot see a secret already in the tree. Signal's key
      entered in ``b43e41e`` and was redacted in ``ec45676``; every pull
      request in between was clean under a diff scan because the key was in
      no diff. GitHub's scanner found it. This job could not have.

    So two properties are asserted, not one. Reading the whole tree is what
    makes the scan capable of finding the thing; scanning the canary first is
    what makes a pass mean something, because a scanner that cannot fail is
    indistinguishable from one that found nothing.
    """
    root = PYPROJECT.parent
    workflow = root / ".github" / "workflows" / "ci.yml"
    if not workflow.exists():  # pragma: no cover - workflow is committed
        return
    text = workflow.read_text(encoding="utf-8")

    step = re.search(
        r"^\s*-\s*name:\s*Scan for secrets\s*$(.*?)(?=^\s*-\s*name:|\Z)",
        text,
        re.M | re.S,
    )
    assert step, (
        "AGENTS.md rule 6: no 'Scan for secrets' step in ci.yml. If it was "
        "renamed, rename it here too -- a parser that silently finds nothing "
        "is the defect it is meant to catch."
    )
    body = step.group(1)

    assert "--no-git" in body and "--source ." in body, (
        "AGENTS.md rule 6: the secret scan must read the working tree "
        "(`--no-git --source .`), not a commit range. A diff scan is clean "
        "for every secret that is already in the tree -- which is how "
        "Signal's key survived from b43e41e to ec45676."
    )
    assert "gitleaks-action" not in body, (
        "AGENTS.md rule 6: gitleaks-action scans a commit range on "
        "pull_request and its scan mode is not overridable. It reported "
        "'no leaks found' over ~0 bytes here. Invoke the binary directly."
    )

    canary = root / ".github" / "secret-scan-canary.txt"
    assert canary.exists(), (
        "AGENTS.md rule 6: the secret scan's canary is missing. Without a "
        "planted credential to find first, a passing scan and a broken "
        "scanner produce the same output."
    )
    assert canary.name in body, (
        "AGENTS.md rule 6: the secret scan must scan "
        f"{canary.name} and require a finding before it trusts its own "
        "verdict on the tree."
    )


def test_the_readme_carries_the_result_that_bounds_its_own_claim() -> None:
    """The README states what the tool was measured to do, with the numbers.

    It used to argue that leading indicators beat lagging ones. A
    pre-registered pilot measured that and the claim lost: download count
    alone reached AUC 0.696 where the sixteen-signal score reached 0.577, and
    two of the protocol's own falsification lines fired.

    This asserts the *evidence* is present rather than that some phrase is
    absent, and the difference is the point. A banned-phrase list is trivially
    satisfied by a synonym, and it would also fire on the sentence that
    withdraws the claim. Requiring both figures and a link to the write-up
    means the claim cannot quietly re-broaden: whoever restores it has to
    delete a specific measured number, which is a visible act rather than a
    silent one.

    If a later study supports a stronger claim, this test should be updated to
    demand *that* study's numbers -- not deleted.
    """
    readme = PYPROJECT.parent / "README.md"
    if not readme.exists():  # pragma: no cover - README is committed
        return
    text = readme.read_text(encoding="utf-8")

    missing = [value for value in ("0.696", "0.577") if value not in text]
    assert not missing, (
        "The README must carry the measured result that bounds its claim. "
        f"Missing: {', '.join(missing)}. Download count alone reached AUC "
        "0.696 against the score's 0.577 on the abandonment pilot; a README "
        "that drops those figures is making a claim the repository's own "
        "evidence does not support."
    )
    assert "docs/abandonment-pilot.md" in text, (
        "The README must link the write-up its headline numbers come from, "
        "so a reader can check them rather than take them on trust."
    )


def test_the_compromise_backtest_stays_halted_until_its_gate_is_met() -> None:
    """AGENTS.md rule 6: a gate that fired must not be quietly stepped over.

    Stage 1 of the compromise backtest measured 43 distinct campaign-days
    against a pre-registered stop rule of 75, so the study halted before any
    control was built. The risk now is not that someone argues with that
    decision -- it is that a later run simply proceeds, because the reason it
    stopped lives in prose and prose does not fail a build.

    So the halt is asserted as a fact of the tree: the stage-1 record exists,
    it carries the measured count, and no results document has appeared for a
    study that is not supposed to have run. Producing one means either the
    gate was met on new data -- in which case update this test with the new
    count, deliberately -- or it was stepped over.

    Deliberately NOT asserting the number 75 alone. Both numbers are required
    together, because the failure mode worth catching is a re-run that quietly
    lowers the bar to whatever it happened to measure.
    """
    root = PYPROJECT.parent
    record = root / "docs" / "compromise-backtest-stage1.md"
    if not record.exists():  # pragma: no cover - committed with this test
        return
    text = record.read_text(encoding="utf-8")

    for needle, why in (
        ("43", "the measured campaign-day count"),
        ("below 75", "the pre-registered threshold it failed"),
    ):
        assert needle in text, (
            f"The stage-1 record has lost {why}. The halt is only meaningful "
            "while both numbers are stated together -- one alone lets a "
            "re-run move the bar to whatever it measured."
        )

    stray = sorted(
        path.name
        for path in (root / "research" / "results").glob("*compromise*")
        if path.is_file()
    )
    assert not stray, (
        "A compromise-backtest results document exists, but the study is "
        "halted at stage 1: 43 campaign-days against a pre-registered stop "
        "rule of 75.\n"
        "If the gate has since been met on new data, say so in "
        "docs/compromise-backtest-stage1.md and update this test with the "
        "new count. If it has not, the study should not have produced "
        "results.\n\n" + "\n".join(stray)
    )


def test_the_compromise_protocol_still_says_what_a_null_costs() -> None:
    """A pre-registration keeps the commitments that are inconvenient to keep.

    ``docs/compromise-backtest-protocol.md`` fixes, before any data is
    touched, what a null result means and what would license restoring the
    claim #330 withdrew. Those two sections are the ones with something to
    lose: the study is underpowered below a 0.05 gap, so a null will be
    ambiguous, and an ambiguous null is exactly where "we could not detect
    it" starts being read as "there is nothing there to detect".

    The commitments are asserted individually rather than by hashing the
    file, because a hash breaks on a typo fix and teaches people to
    re-baseline it on sight.

    This does not prove the document was written first -- git does that. It
    proves the terms have not quietly gone missing since.
    """
    protocol = PYPROJECT.parent / "docs" / "compromise-backtest-protocol.md"
    if not protocol.exists():  # pragma: no cover - committed with this test
        return
    text = protocol.read_text(encoding="utf-8")

    required = {
        "a null leaves the claim withdrawn": (
            "A null leaves the withdrawn claim withdrawn"
        ),
        "the reinstatement bar": "≥ 0.05",
        "the negative-control band": "[0.47, 0.53]",
        "the stop rule on campaign count": "below 75",
        "clustering on campaign-day": "campaign-day",
        "born-malicious entries excluded": "2,074",
    }
    missing = sorted(name for name, needle in required.items() if needle not in text)
    assert not missing, (
        "The compromise backtest's pre-registration has lost commitments it "
        "fixed in advance: " + ", ".join(missing) + ".\n"
        "These are the terms that cost something to keep. If one genuinely "
        "needs to change, change it before the data is touched and say so in "
        "the document -- a falsification line edited after seeing results is "
        "not a falsification line."
    )


def test_no_test_has_another_test_s_docstring_stranded_in_its_body() -> None:
    """AGENTS.md rule 6: catch a test that was absorbed into its neighbour.

    #330 added a test by replacing the ``def`` line of the one below it and
    not restoring it. The neighbour's docstring and assertions were absorbed
    into the new function, so ``test_mypy_first_party_exemption_list_stays_
    empty`` -- the rule-8 ratchet -- stopped existing under its own name and
    became trailing statements behind another test's early ``return``.

    It shipped green. Every assertion still ran in the ordinary case, so no
    count changed and no failure appeared; the gate was present, passing, and
    no longer guarding what it named. Nothing in CI could have caught it,
    because "this file has fewer tests than it used to" is not something
    pytest knows.

    The syntactic fingerprint is specific and cheap to find: a bare string
    expression somewhere other than position 0 of a function body. Python
    evaluates it and throws it away, so it is never anything but a mistake --
    either two functions merged, or a docstring that drifted below a
    statement and stopped being a docstring.

    Scoped to the test tree because that is where the damage is silent. The
    same slip in ``src/`` tends to surface as a failure somewhere.
    """
    root = PYPROJECT.parent
    offenders: List[str] = []
    for path in sorted((root / "testing").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for index, statement in enumerate(node.body):
                if index == 0:
                    continue  # position 0 is the docstring, which is the point
                if isinstance(statement, ast.Expr) and isinstance(
                    statement.value, ast.Constant
                ):
                    if isinstance(statement.value.value, str):
                        offenders.append(
                            f"{path.relative_to(root)}:{statement.lineno} "
                            f"in {node.name}()"
                        )

    assert not offenders, (
        "AGENTS.md rule 6: a string literal is being evaluated and discarded "
        "inside a test body, which is the fingerprint of two functions "
        "merged into one -- the second one's name, and whatever it guarded, "
        "is gone while the suite stays green.\n\n" + "\n".join(offenders)
    )


def test_mypy_first_party_exemption_list_stays_empty() -> None:
    """AGENTS.md rule 8: the first-party mypy exemption list stays empty.

    It once held eleven modules -- including every module where this
    session's defects lived -- defended by a test asserting the exemptions
    stay in place. Ratchets only move down.
    """
    text = PYPROJECT.read_text(encoding="utf-8")
    exempt = re.findall(
        r'module\s*=\s*"(dependency_risk_profiler[^"]*)"\s*\nignore_errors\s*=\s*true',
        text,
    )
    assert not exempt, (
        "AGENTS.md rule 8: the first-party mypy exemption list stays empty.\n"
        "Unmask the module and fix the errors, or leave the work undone and "
        "say so -- do not re-exempt.\n\n" + "\n".join(sorted(exempt))
    )
