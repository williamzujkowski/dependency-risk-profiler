# Vendored purl-spec conformance fixtures

These files are copied **verbatim** from the official package-url specification
repository. They are the binding CI gate on `src/dependency_risk_profiler/purl.py`
(#164): the ratified condition was that if our stdlib canonicalizer cannot pass
the official suite, that is the evidence to take `packageurl-python` as a
dependency instead.

Do not hand-edit these files. Re-vendor them from upstream and re-run
`testing/unit/test_purl_conformance.py`.

## Source

| Field | Value |
|-------|-------|
| Repository | <https://github.com/package-url/purl-spec> |
| Revision | `b5454e75c29b48e483290689fe635f2517925925` (`main`) |
| Upstream commit date | 2026-07-29 |
| Vendored on | 2026-08-04 |
| Test-case schema | <https://packageurl.org/schemas/purl-test.schema-0.1.json> |
| Specification | ECMA-427, 1st edition |

## Files

Each file is byte-identical to the upstream path shown.

| Local file | Upstream path | SHA-256 |
|------------|---------------|---------|
| `specification-test.json` | `tests/spec/specification-test.json` | `5e10331dc6f81b06130c0e4e878794b10ddc87c635cb3f78e97e2ecfae46b5bd` |
| `cargo-test.json` | `tests/types/cargo-test.json` | `2765c859364c02e37904ce8823f9e0b847fa3dbaf81cdfba4592455ed3aec768` |
| `composer-test.json` | `tests/types/composer-test.json` | `e0fe9f6d4b42139df89b6f943a0519a85fa2c79e7e69272c30ea8cc2274b5f79` |
| `gem-test.json` | `tests/types/gem-test.json` | `75df4cc314375ce11478281c322c1abc08e43fc832dd7535b9785d331192f86b` |
| `golang-test.json` | `tests/types/golang-test.json` | `3124dde9114c90a733cd74e19f911c51f53a1f94f9ae779da8b03396d8df4821` |
| `maven-test.json` | `tests/types/maven-test.json` | `13ecbb6db32b88969945be148c52a744ad89732386f86945319d55e23a2878c1` |
| `npm-test.json` | `tests/types/npm-test.json` | `8e7d00358125a743e62163e8cc4875e7bfef4339d947a4c5e5cd8a25b3757db4` |
| `nuget-test.json` | `tests/types/nuget-test.json` | `78744103385c0933049a6184f6364952f3579a6864fe3ac96f2d8a21abc640d2` |
| `pypi-test.json` | `tests/types/pypi-test.json` | `da842b6563c74c52a4b3c2001fec370b9e857fdf0abf6c44bf30d2d243dbf07d` |

## Scope: which type files are vendored, and why

Upstream ships a type test file for all 42 registered purl types. We vendor the
core specification file plus the eight types our ecosystem registry maps to
(`src/dependency_risk_profiler/vulnerabilities/ecosystems.py`). Nine registry
keys yield eight purl types because `java` and `maven` share the `maven` type.

The other 34 type files are omitted because we do not model those ecosystems,
and a passing test for `pkg:swid/...` would assert nothing about this tool.
This is a scope boundary, not a test exclusion: **no test case in any vendored
file is skipped, filtered, or narrowed.** Both `base` and `advanced` test groups
run, and all three test types (`build`, `parse`, `roundtrip`) run.

Adding an ecosystem to the registry must come with its upstream type test file
vendored here. `testing/unit/test_purl_conformance.py` fails if the two sets
disagree, so this cannot be forgotten.

## Two equivalences applied when comparing results

Neither narrows the suite; both reconcile JSON's shape with Python's.

1. **Absent versus empty.** Upstream writes an absent `namespace`, `version`,
   `qualifiers` or `subpath` as JSON `null`; we model absent qualifiers as an
   empty mapping. An empty mapping compares equal to `null`.
2. **Qualifier key order.** `expected_output` qualifier objects are compared as
   mappings, not as ordered pairs. Canonical *string* output is compared byte
   for byte, which is where qualifier ordering is actually specified.

## Re-vendoring

```sh
REV=<commit-sha>
for f in tests/spec/specification-test.json \
         tests/types/{cargo,composer,gem,golang,maven,npm,nuget,pypi}-test.json; do
  curl -fsSL "https://raw.githubusercontent.com/package-url/purl-spec/$REV/$f" \
    -o "testing/fixtures/purl-spec/$(basename "$f")"
done
```

Then update the revision, date and hashes in the tables above.
