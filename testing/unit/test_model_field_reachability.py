"""Every model field the code reads must have somewhere that writes it (#166).

``CommunityMetrics.commit_frequency`` was read in six places, declared with a
``None`` default, and assigned nowhere in ``src/``. Half of ``community_score``
was therefore a constant, and the "low commit frequency" risk factor could
never fire — but because the other half *was* measured, the score reported as a
confident number rather than an honest unknown. The same sweep found the
mirror-image case in #161.

This is a whole class of defect, not one field, so it gets a test rather than a
one-line fix. The invariant is narrow on purpose:

    a model field declared ``= None`` that some module reads, and that no
    module ever assigns, can only ever be None

Fields with a real default (``0``, ``False``, ``default_factory=list``) are
excluded: those carry a meaningful value without anyone assigning them. Fields
that are written but never read are a different smell — wasted work, not a
fabricated signal — and are left to review.

The sweep is a plain AST walk over ``src/``. Attribute names are matched
without resolving types, so it is deliberately generous about what counts as a
write: any ``obj.field = ...`` anywhere, or any ``field=`` keyword in a call.
A generous write-detector keeps this from crying wolf; the failure it exists to
catch is a field with *zero* writes, which no amount of generosity invents.
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple

SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "dependency_risk_profiler"
MODELS_PATH = SRC_ROOT / "models.py"


def _none_defaulted_model_fields() -> Dict[str, Set[str]]:
    """Return ``{field_name: {declaring class, ...}}`` for ``= None`` fields.

    Returns:
        Mapping of field name to the model classes that declare it with a
        literal ``None`` default.
    """
    tree = ast.parse(MODELS_PATH.read_text(encoding="utf-8"), str(MODELS_PATH))
    fields: Dict[str, Set[str]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.AnnAssign):
                continue
            target = statement.target
            if not isinstance(target, ast.Name):
                continue
            default = statement.value
            # `x: Optional[int] = (None  # comment)` parses to the bare
            # constant, so no unwrapping beyond the literal check is needed.
            if not (isinstance(default, ast.Constant) and default.value is None):
                continue
            fields.setdefault(target.id, set()).add(node.name)

    return fields


def _attribute_reads_and_writes() -> Tuple[Set[str], Set[str]]:
    """Scan ``src/`` for attribute reads and writes by name.

    Returns:
        A ``(read_names, written_names)`` pair. Reads are ``obj.attr`` in load
        position; writes are ``obj.attr = ...``, augmented assignment, ``del``,
        and ``attr=`` keyword arguments to any call (which is how the dataclass
        constructors are populated).
    """
    read_names: Set[str] = set()
    written_names: Set[str] = set()

    for path in sorted(SRC_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if isinstance(node.ctx, ast.Load):
                    read_names.add(node.attr)
                else:  # Store / Del
                    written_names.add(node.attr)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg is not None:
                        written_names.add(keyword.arg)

    return read_names, written_names


def test_every_read_model_field_has_a_writer() -> None:
    """A read field that nothing assigns is a constant wearing a signal's name."""
    fields = _none_defaulted_model_fields()
    read_names, written_names = _attribute_reads_and_writes()

    unreachable: List[str] = sorted(
        f"{'/'.join(sorted(fields[name]))}.{name}"
        for name in fields
        if name in read_names and name not in written_names
    )

    assert unreachable == [], (
        "These model fields default to None, are read somewhere in src/, and "
        "are assigned nowhere — so they are permanently None and every signal "
        "derived from them is fabricated: " + ", ".join(unreachable)
    )


def test_the_sweep_understands_the_models_it_is_sweeping() -> None:
    """Guard the guard: a scan that parses nothing would pass vacuously."""
    fields = _none_defaulted_model_fields()
    read_names, written_names = _attribute_reads_and_writes()

    # The field this test was written for, now that it has a producer.
    assert "commit_frequency" in fields
    assert "commit_frequency" in read_names
    assert "commit_frequency" in written_names
    # Enough of src/ actually parsed for the absence of a write to mean
    # something.
    assert len(fields) > 20
    assert len(written_names) > 200
