# Basic Usage

The CLI has three commands:

```bash
dependency-risk-profiler --help
dependency-risk-profiler analyze --help
dependency-risk-profiler list-ecosystems
dependency-risk-profiler generate-config dependency-risk-profiler.toml
```

## Analyze One Manifest

Pass the manifest path as a positional argument:

```bash
dependency-risk-profiler analyze requirements.txt
```

Supported formats are detected from the file name and contents.

## JSON Output

Use `--output json` when another tool needs to consume the result:

```bash
dependency-risk-profiler analyze requirements.txt --output json
```

## Recursive Directory Scans

Use `--recursive` to scan supported manifests under a directory:

```bash
dependency-risk-profiler analyze path/to/project --recursive
```

Without `--recursive`, directory analysis only checks the provided directory level.

## Dependency Graph Data

Generate graph data during analysis:

```bash
dependency-risk-profiler analyze requirements.txt --generate-graph out.json --graph-format d3
```

Available graph formats are `d3`, `graphviz`, and `cytoscape`.

For Graphviz DOT output, use a `.dot` path:

```bash
dependency-risk-profiler analyze go.mod --generate-graph graph.dot --graph-format graphviz
```

## Trends

Save a scan to local history:

```bash
dependency-risk-profiler analyze requirements.txt --save-history
```

Analyze saved history:

```bash
dependency-risk-profiler analyze requirements.txt --analyze-trends
```

Limit the number of historical scans used:

```bash
dependency-risk-profiler analyze requirements.txt --analyze-trends --trend-limit 5
```

Generate trend visualization data:

```bash
dependency-risk-profiler analyze requirements.txt --trend-visualization overall
```

Trend visualization types are `overall`, `distribution`, `dependencies`, and `security`.

## Vulnerability Sources And Noise Filtering

OSV is enabled by default. NVD and GitHub Advisory data can be enabled when needed:

```bash
dependency-risk-profiler analyze requirements.txt --enable-nvd
dependency-risk-profiler analyze requirements.txt --enable-github-advisory --github-token "$GITHUB_TOKEN"
```

Control which advisory severities affect scoring:

```bash
dependency-risk-profiler analyze requirements.txt --minimum-vulnerability-severity MEDIUM
```

The default threshold is `LOW`. `INFO`, withdrawn, and low-confidence findings are kept out of scoring noise.

## Configuration

Generate a sample config file:

```bash
dependency-risk-profiler generate-config dependency-risk-profiler.toml
```

Use a specific config file with the top-level `--config` option:

```bash
dependency-risk-profiler --config dependency-risk-profiler.toml analyze requirements.txt
```

## Supported Ecosystems

```bash
dependency-risk-profiler list-ecosystems
```

- Python: `requirements.txt`, `Pipfile.lock`, `pyproject.toml`
- Node.js: `package-lock.json`
- Go: `go.mod`
- Rust: `Cargo.toml`

## Next Steps

- [Configuration](configuration.md)
- [Scoring](SCORING.md)
- [Information Sources](INFORMATION_SOURCES.md)
