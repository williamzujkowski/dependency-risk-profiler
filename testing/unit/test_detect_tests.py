"""`has_tests` must find tests where languages actually put them.

Before #411 the check looked only at the repository root for a
conventionally-named directory. Measured on the #385 cohort that produced a
confident ``False`` for ``python/cpython`` and ``ossf/scorecard`` — two of the
most heavily tested codebases in existence — because CPython's suite is
``Lib/test`` and Go keeps ``*_test.go`` beside the source.

A confident False the collector cannot justify is this repository's recurring
defect class, so these pin both halves: the shapes it must now find, and the
shapes it must still refuse.
"""

from __future__ import annotations

from pathlib import Path

from dependency_risk_profiler.utils import detect_tests


def test_an_empty_tree_has_no_tests(tmp_path: Path) -> None:
    """The negative half. Variation alone cannot prove a check discriminates."""
    assert detect_tests(tmp_path) is False


def test_source_without_tests_is_false(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.go").write_text("package main")
    (tmp_path / "README.md").write_text("#")
    assert detect_tests(tmp_path) is False


def test_a_root_test_directory(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    assert detect_tests(tmp_path) is True


def test_cpython_keeps_its_suite_one_level_down(tmp_path: Path) -> None:
    """`Lib/test` — the layout that motivated #411."""
    (tmp_path / "Lib" / "test").mkdir(parents=True)
    assert detect_tests(tmp_path) is True


def test_maven_and_gradle_keep_src_test(tmp_path: Path) -> None:
    (tmp_path / "src" / "test" / "java").mkdir(parents=True)
    assert detect_tests(tmp_path) is True


def test_go_puts_tests_beside_the_source(tmp_path: Path) -> None:
    """`go test` requires it, so no directory check can ever find them."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server_test.go").write_text("package pkg")
    assert detect_tests(tmp_path) is True


def test_javascript_colocated_spec_files(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "button.test.ts").write_text("")
    assert detect_tests(tmp_path) is True


def test_vendored_trees_do_not_count(tmp_path: Path) -> None:
    """Another project's tests are not this project's tests."""
    for vendored in ("node_modules", "vendor", "third_party", ".venv"):
        (tmp_path / vendored / "dep" / "tests").mkdir(parents=True)
    assert detect_tests(tmp_path) is False


def test_the_git_directory_is_never_descended(tmp_path: Path) -> None:
    """`.git` alone can hold hundreds of thousands of objects."""
    (tmp_path / ".git" / "objects" / "test").mkdir(parents=True)
    assert detect_tests(tmp_path) is False


def test_an_unreadable_subdirectory_does_not_abort_the_search(tmp_path: Path) -> None:
    """A partial answer stays partial; one bad directory is not a verdict (#236)."""
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (tmp_path / "tests").mkdir()
    blocked.chmod(0o000)
    try:
        assert detect_tests(tmp_path) is True
    finally:
        blocked.chmod(0o755)


def test_the_search_is_depth_bounded(tmp_path: Path) -> None:
    """Cheap on a large repository: a suite buried very deep is not found.

    Recorded as a deliberate limit rather than a bug — an unbounded walk on a
    monorepo costs more than the signal is worth, and the bound is documented
    where the constant lives.
    """
    deep = tmp_path / "a" / "b" / "c" / "d" / "e" / "tests"
    deep.mkdir(parents=True)
    assert detect_tests(tmp_path) is False
