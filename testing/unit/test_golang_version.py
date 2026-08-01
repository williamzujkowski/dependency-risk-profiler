"""Go latest-version resolution via the module proxy JSON API (#82)."""

from unittest import mock

from dependency_risk_profiler.analyzers import golang


def test_latest_version_from_module_proxy() -> None:
    """The version comes from proxy.golang.org's @latest JSON endpoint."""
    analyzer = golang.GoAnalyzer()
    with mock.patch.object(
        golang, "fetch_json", return_value={"Version": "v1.9.1"}
    ) as fetch:
        version = analyzer._get_latest_version("github.com/gin-gonic/gin")

    assert version == "v1.9.1"
    assert (
        fetch.call_args[0][0]
        == "https://proxy.golang.org/github.com/gin-gonic/gin/@latest"
    )


def test_module_path_uppercase_is_escaped() -> None:
    """Uppercase letters are proxy-escaped as !<lower> (Go module convention)."""
    analyzer = golang.GoAnalyzer()
    with mock.patch.object(
        golang, "fetch_json", return_value={"Version": "v1.0.0"}
    ) as fetch:
        analyzer._get_latest_version("github.com/Azure/azure-sdk-for-go")

    assert (
        fetch.call_args[0][0]
        == "https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@latest"
    )


def test_latest_version_none_on_missing_data() -> None:
    """A failed lookup (or malformed payload) resolves to None."""
    analyzer = golang.GoAnalyzer()
    with mock.patch.object(golang, "fetch_json", return_value=None):
        assert analyzer._get_latest_version("example.com/x/y") is None
    with mock.patch.object(golang, "fetch_json", return_value={"no": "version"}):
        assert analyzer._get_latest_version("example.com/x/y") is None
