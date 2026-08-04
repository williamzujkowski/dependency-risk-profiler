"""purl strings are untrusted input (#164, binding security condition).

They arrive from registry payloads and from user-supplied manifests, so the
parser is a trust boundary. The condition ratified on #164 was that parsing
must enforce input-length limits, reject control characters and malformed
percent-encoding, and *never* turn a package identifier into an unchecked
filesystem path, URL, query, or shell argument.

The first three are testable by feeding the parser hostile strings. The fourth
is a property of the module rather than of any one call, so it is tested
structurally: :func:`test_module_has_no_filesystem_network_or_process_sinks`
walks the AST of ``purl.py`` and asserts that the dangerous sinks are simply
not present. A test that only checked today's call sites would pass forever
while someone added ``open(purl.name)`` next year.
"""

import ast
from pathlib import Path
from typing import List, Set

import pytest

from dependency_risk_profiler import purl as purl_module
from dependency_risk_profiler.purl import (
    MAX_COMPONENT_LENGTH,
    MAX_PURL_LENGTH,
    MAX_QUALIFIERS,
    PurlError,
    identity_key,
    parse,
)

PURL_SOURCE = Path(purl_module.__file__)


# --------------------------------------------------------------------------
# Length limits
# --------------------------------------------------------------------------


def test_over_long_purl_is_rejected() -> None:
    """A megabyte of package name must not be parsed, only refused."""
    hostile = "pkg:pypi/" + ("a" * (MAX_PURL_LENGTH + 1))
    with pytest.raises(PurlError, match="character limit"):
        parse(hostile)


def test_a_long_but_legal_purl_is_still_accepted() -> None:
    """The ceilings are limits, not an off-by-one that refuses valid input.

    A deeply nested Go module path can be genuinely long. Anything under both
    ceilings must parse, or the limits would be a denial of service against
    ourselves rather than a defence.
    """
    segments = ["github.com"] + ["s" * 200] * 15
    candidate = "pkg:golang/" + "/".join(segments) + "/pkg@v1.0.0"
    assert len(candidate) < MAX_PURL_LENGTH
    assert parse(candidate).name == "pkg"


def test_over_long_component_is_rejected() -> None:
    """Component limits bound memory even when the whole string is short."""
    with pytest.raises(PurlError, match="component length limit"):
        parse("pkg:pypi/" + "a" * (MAX_COMPONENT_LENGTH + 1))


def test_over_long_version_is_rejected() -> None:
    """Every decoded component is bounded, not just the name."""
    with pytest.raises(PurlError, match="component length limit"):
        parse("pkg:pypi/django@" + "1" * (MAX_COMPONENT_LENGTH + 1))


def test_over_long_qualifier_value_is_rejected() -> None:
    """Qualifier values are attacker-controlled too."""
    with pytest.raises(PurlError, match="component length limit"):
        parse("pkg:pypi/django@1.0?file_name=" + "x" * (MAX_COMPONENT_LENGTH + 1))


def test_too_many_qualifiers_are_rejected() -> None:
    """A qualifier flood is bounded before any decoding work happens."""
    pairs = "&".join(f"k{index}=v" for index in range(MAX_QUALIFIERS + 1))
    with pytest.raises(PurlError, match="qualifiers"):
        parse(f"pkg:pypi/django@1.0?{pairs}")


def test_empty_and_non_string_inputs_are_rejected() -> None:
    """Degenerate inputs fail closed rather than producing a partial purl."""
    with pytest.raises(PurlError):
        parse("")
    with pytest.raises(PurlError):
        parse(None)


# --------------------------------------------------------------------------
# Control characters
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "pkg:pypi/dja\x00ngo@1.0",
        "pkg:pypi/django@1.0\x00",
        "pkg:pypi/django\nmalicious@1.0",
        "pkg:pypi/django\r\nmalicious@1.0",
        "pkg:pypi/django\x1b[31m@1.0",
        "pkg:pypi/django@1.0?file_name=a\x07b",
        "pkg:pypi/django@1.0#sub\x00path",
    ],
    ids=[
        "nul-in-name",
        "nul-in-version",
        "newline-in-name",
        "crlf-in-name",
        "ansi-escape-in-name",
        "bell-in-qualifier",
        "nul-in-subpath",
    ],
)
def test_raw_control_characters_are_rejected(hostile: str) -> None:
    """A literal control character anywhere in the string is refused.

    Args:
        hostile: A purl string carrying a control character.
    """
    with pytest.raises(PurlError, match="control character"):
        parse(hostile)


@pytest.mark.parametrize(
    "hostile",
    [
        "pkg:pypi/dja%00ngo@1.0",
        "pkg:pypi/django@1.0%00",
        "pkg:pypi/django%0amalicious@1.0",
        "pkg:pypi/django%1b%5b31m@1.0",
        "pkg:pypi/django@1.0?file_name=a%00b",
        "pkg:pypi/django@1.0#sub%00path",
        "pkg:npm/%00/pkg@1.0",
    ],
    ids=[
        "encoded-nul-in-name",
        "encoded-nul-in-version",
        "encoded-newline-in-name",
        "encoded-ansi-escape",
        "encoded-nul-in-qualifier",
        "encoded-nul-in-subpath",
        "encoded-nul-in-namespace",
    ],
)
def test_percent_encoded_control_characters_are_rejected(hostile: str) -> None:
    """Percent-encoding is the obvious way to smuggle a NUL past a naive check.

    Args:
        hostile: A purl string whose *decoded* form holds a control character.
    """
    with pytest.raises(PurlError, match="control character"):
        parse(hostile)


def test_non_ascii_input_is_rejected() -> None:
    """A canonical purl string is ASCII; a homoglyph name is not one of ours."""
    with pytest.raises(PurlError, match="non-ASCII"):
        parse("pkg:pypi/djangо@1.0")  # Cyrillic 'о' (U+043E)


# --------------------------------------------------------------------------
# Malformed percent-encoding
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "pkg:pypi/django%@1.0",
        "pkg:pypi/django%2@1.0",
        "pkg:pypi/django%zz@1.0",
        "pkg:pypi/django%2g@1.0",
        "pkg:pypi/django@1.0%",
        "pkg:pypi/django@1.0?file_name=a%",
        "pkg:pypi/django@1.0#a%2",
    ],
    ids=[
        "bare-percent-in-name",
        "truncated-escape-in-name",
        "non-hex-escape",
        "half-hex-escape",
        "bare-percent-in-version",
        "bare-percent-in-qualifier",
        "truncated-escape-in-subpath",
    ],
)
def test_malformed_percent_escapes_are_rejected(hostile: str) -> None:
    """``urllib.parse.unquote`` passes these through; we must not.

    Args:
        hostile: A purl string with a malformed percent-escape.
    """
    with pytest.raises(PurlError, match="malformed percent-escape"):
        parse(hostile)


def test_invalid_utf8_percent_escapes_are_rejected() -> None:
    """Strict UTF-8 decoding: no silent U+FFFD substitution.

    ``unquote`` defaults to ``errors="replace"``, which would turn a mangled
    byte sequence into a plausible-looking package name. Two different invalid
    sequences would then collapse to the same replacement-character name.
    """
    with pytest.raises(PurlError, match="valid percent-encoded UTF-8"):
        parse("pkg:pypi/django%ff%fe@1.0")


# --------------------------------------------------------------------------
# Path traversal and injection shapes
# --------------------------------------------------------------------------


def test_traversal_shaped_name_stays_inert_and_is_re_encoded() -> None:
    """A traversal payload survives as data and never as a path separator.

    The decoded name really does contain ``../../etc/passwd`` — the spec allows
    any character in a decoded name — so the guarantee cannot be "it is
    rejected". It is that the value never reaches a path API, and that
    rendering it back out re-encodes every slash, so the canonical string
    cannot be pasted into a path and traverse anything.
    """
    parsed = parse("pkg:pypi/..%2F..%2Fetc%2Fpasswd@1.0")
    assert parsed.name == "../../etc/passwd"

    rendered = parsed.to_string()
    assert rendered == "pkg:pypi/..%2F..%2Fetc%2Fpasswd@1.0"
    assert "/" not in rendered.split("pkg:pypi/", 1)[1].split("@", 1)[0]
    assert identity_key(parsed) == rendered


def test_traversal_shaped_subpath_is_normalized_away() -> None:
    """ECMA-427 drops ``.`` and ``..`` subpath segments; verify it happens."""
    parsed = parse("pkg:golang/github.com/foo/bar#../../etc/passwd")
    assert parsed.subpath == "etc/passwd"
    assert ".." not in parsed.to_string()


def test_absolute_path_shaped_name_does_not_become_absolute() -> None:
    """A leading-slash payload cannot escape into an absolute path."""
    parsed = parse("pkg:pypi/%2Fetc%2Fpasswd@1.0")
    assert parsed.name == "/etc/passwd"
    assert parsed.to_string() == "pkg:pypi/%2Fetc%2Fpasswd@1.0"


def test_url_shaped_qualifier_value_is_fully_encoded() -> None:
    """A qualifier holding a URL is encoded, so it cannot split the purl.

    ``repository_url`` is the field most likely to be reflected into an HTTP
    client by a careless consumer. Canonical rendering percent-encodes every
    slash, so the value cannot be mistaken for structure by a downstream
    parser that splits on ``/``.
    """
    parsed = parse("pkg:maven/g/a@1.0?repository_url=https://evil.example/%3Fx%3D1")
    assert parsed.qualifiers["repository_url"] == "https://evil.example/?x=1"
    rendered = parsed.to_string()
    assert "https:%2F%2Fevil.example%2F%3Fx%3D1" in rendered
    assert rendered.count("?") == 1


def test_injected_separators_cannot_forge_extra_components() -> None:
    """An encoded separator in a value stays a value on the way back out."""
    parsed = parse("pkg:pypi/django@1.0?file_name=a%26evil%3Dtrue")
    assert dict(parsed.qualifiers) == {"file_name": "a&evil=true"}
    assert parsed.to_string() == "pkg:pypi/django@1.0?file_name=a%26evil%3Dtrue"
    assert parse(parsed.to_string()).qualifiers == parsed.qualifiers


def test_shell_metacharacters_survive_only_as_encoded_data() -> None:
    """Nothing here execs, but the identifier must not carry live shell text."""
    parsed = parse("pkg:pypi/django@1.0?file_name=%3B%20rm%20-rf%20%2F")
    assert parsed.qualifiers["file_name"] == "; rm -rf /"
    rendered = parsed.to_string()
    for metacharacter in (";", " ", "|", "$", "`"):
        assert metacharacter not in rendered


def test_qualifier_key_injection_is_rejected() -> None:
    """Keys are a closed charset, so a key can never carry structure."""
    for hostile in (
        "pkg:pypi/django@1.0?in%20production=true",
        "pkg:pypi/django@1.0?a/b=c",
        "pkg:pypi/django@1.0?1abc=c",
        "pkg:pypi/django@1.0?=novalue",
    ):
        with pytest.raises(PurlError):
            parse(hostile)


def test_duplicate_qualifier_keys_are_rejected() -> None:
    """Last-write-wins on a duplicated key is a parameter-smuggling primitive."""
    with pytest.raises(PurlError, match="duplicate"):
        parse("pkg:maven/g/a@1.0?classifier=safe&classifier=evil")
    with pytest.raises(PurlError, match="duplicate"):
        parse("pkg:maven/g/a@1.0?classifier=safe&CLASSIFIER=evil")


# --------------------------------------------------------------------------
# The structural guarantee: no dangerous sinks exist in the module at all
# --------------------------------------------------------------------------

# Callables that would turn a package identifier into a path, a request, or a
# subprocess. Absence is the guarantee; presence is the bug.
_FORBIDDEN_CALLS: Set[str] = {
    "Path",
    "PurePath",
    "check_call",
    "check_output",
    "eval",
    "exec",
    "getattr",
    "open",
    "popen",
    "run",
    "system",
    "urlopen",
}

# Modules that have no business being imported by an identifier parser.
_FORBIDDEN_IMPORTS: Set[str] = {
    "http",
    "os",
    "pathlib",
    "pickle",
    "requests",
    "shutil",
    "socket",
    "subprocess",
    "tempfile",
    "urllib.request",
}

# The one import that must stay: percent-encoding, and nothing else from
# urllib.
_ALLOWED_URLLIB_NAMES = {"quote", "unquote"}


def _module_ast() -> ast.Module:
    """Parse the purl module source.

    Returns:
        The module AST.
    """
    return ast.parse(PURL_SOURCE.read_text(encoding="utf-8"))


def test_module_has_no_filesystem_network_or_process_sinks() -> None:
    """No purl value can reach a path, a URL fetch, or a shell from here.

    Structural rather than behavioural on purpose: this keeps holding as the
    module changes, which a per-call-site assertion would not.
    """
    called: List[str] = []
    for node in ast.walk(_module_ast()):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name):
            called.append(function.id)
        elif isinstance(function, ast.Attribute):
            called.append(function.attr)

    offenders = sorted(set(called) & _FORBIDDEN_CALLS)
    assert not offenders, f"purl.py must not call: {offenders}"


def test_module_imports_nothing_that_touches_the_outside_world() -> None:
    """The import list is the other half of the no-sinks guarantee.

    The lazy ``go_modules`` import inside :func:`rollup_group_key` is the one
    deliberate exception, and it is a level-2 rollup helper that takes an
    already-parsed purl. It is allowed because ``go_modules`` owns its own
    hardened fetch path (#130); what matters here is that *parsing* never
    reaches it.
    """
    imported: Set[str] = set()
    for node in ast.walk(_module_ast()):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)

    offenders = sorted(imported & _FORBIDDEN_IMPORTS)
    assert not offenders, f"purl.py must not import: {offenders}"


def test_only_percent_encoding_is_taken_from_urllib() -> None:
    """Guard the one stdlib URL import so it cannot grow a fetch."""
    names: Set[str] = set()
    for node in ast.walk(_module_ast()):
        if isinstance(node, ast.ImportFrom) and node.module == "urllib.parse":
            names.update(alias.name for alias in node.names)
    assert names == _ALLOWED_URLLIB_NAMES


def test_parsing_never_imports_the_http_stack() -> None:
    """Behavioural companion to the structural checks.

    ``rollup_group_key`` may reach ``go_modules``; ``parse`` must not, even
    transitively, or every manifest read would drag in the HTTP client.
    """
    source = PURL_SOURCE.read_text(encoding="utf-8")
    parse_body = source.split("def parse(", 1)[1].split("\ndef ", 1)[0]
    assert "go_modules" not in parse_body
    assert "import" not in parse_body
