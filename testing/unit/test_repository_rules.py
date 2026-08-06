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
