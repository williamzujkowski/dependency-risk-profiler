# Enhancement Roadmap

Below are the enhancements planned for the dependency-risk-profiler project. Implemented features are marked with ✅.

## Implementation Status Summary:

**Completed:**
- ✅ We successfully implemented the Plugin-Like Mechanism (Prompt 2) to provide a more systematic way to register and detect ecosystem parsers.
- ✅ We added Disk-Based Caching for Vulnerability Data (Prompt 3) that stores data locally to reduce network calls across runs.
- ✅ We enhanced Error Handling and Robustness (Prompt 1) with retry mechanisms and better error recovery.

**Remaining Enhancements:**
- Parallelized Repository Analysis (Prompt 4)
- Configuration File Support (Prompt 5)
- CLI Refactoring with Typer/Click (Prompt 6)
- Single vs. Multi-Maintainer Checking (Prompt 7)
- Automated Documentation Generation (Prompt 8)

Note: ENHANCEMENTS2.md contains requirements for the Secure Code Signing feature that is planned but not yet implemented.

## ✅ Prompt 1: Enhanced Error Handling and Robustness (IMPLEMENTED)

*"Refactor the code to improve error handling and resilience for external network calls and subprocess operations. Specifically:*

1. **Wrap `requests.get` and `requests.post`** in a retry mechanism (e.g., using an exponential backoff strategy).
2. **Add try/except blocks** around `subprocess.run` calls to catch `subprocess.CalledProcessError` and log a warning instead of crashing the program.
3. **Gracefully handle missing or malformed data** from external calls (e.g., if JSON responses lack expected fields, log the issue and continue without halting).
4. **Document** each new exception or fallback path in docstrings or inline comments, ensuring we clearly explain how partial failures are handled.

Implementation notes:
- Added exponential backoff retry mechanism for all network requests in vulnerability sources
- Improved error handling for different types of errors (client errors, server errors, connectivity)
- Added detailed error logging for better debugging

---

## ✅ Prompt 2: Plugin-Like Mechanism for New Ecosystems (IMPLEMENTED)

*"Implement a plugin or registry pattern so that adding support for new ecosystems is more systematic. Specifically:*

1. **Create a 'plugin registry'** (e.g., in `BaseParser`) where each parser (NodeJSParser, PythonParser, etc.) can register itself with a unique ecosystem identifier.
2. **Modify `get_parser_for_file`** so it loops through the registered plugins to detect the best parser, rather than having large if/else blocks.
3. **Allow external modules** to provide new parser/analyzer pairs by registering them at runtime (e.g., `EcosystemRegistry.register_parser('rust', RustParser)`).
4. **Update the CLI** to display a list of available ecosystems if a user tries to parse an unrecognized manifest file.

Implementation notes:
- Created an `EcosystemRegistry` class to manage parsers and file patterns
- Implemented file pattern matching with three strategies (filename, extension, content)
- Updated CLI to display available ecosystems when a user tries to parse an unrecognized manifest file
- Added `--list-ecosystems` command to display all supported ecosystems

---

## ✅ Prompt 3: Disk-Based Caching for Vulnerability Data (IMPLEMENTED)

*"Augment the existing `vulnerabilities/aggregator.py` module to store fetched vulnerability data on disk (rather than in memory only), enabling reuse across multiple runs. Specifically:*

1. **Implement a simple file-based cache** using JSON (e.g., stored in a `.vuln_cache` directory).
2. **Load cached data** if available and recent (e.g., within 24 hours), instead of making new network calls.
3. **Implement a safe fallback** so that if the cached file is corrupt or out-of-date, the code seamlessly fetches fresh data.
4. **Allow the user to override or clear the cache** (e.g., `--no-cache` command-line flag or an environment variable).
5. **Document** in the docstrings how the caching logic works, and update the logging to indicate whether data is served from cache or from a fresh request.

Implementation notes:
- Added `VulnerabilityCache` class for disk-based caching in `~/.dependency_risk_profiler/vuln_cache/`
- Implemented cache expiry, validation, and robust error handling
- Added `--no-cache` and `--clear-cache` CLI options
- Maintained backward compatibility with the in-memory cache
- Added comprehensive unit tests for the cache system

---

## Prompt 4: Parallelized or Asynchronous Repository Analysis

*"Refactor the repository-cloning and data-fetching steps to run concurrently, reducing overall execution time in large projects. Specifically:*

1. **Use Python's `asyncio`** or `concurrent.futures.ThreadPoolExecutor` to clone multiple repositories in parallel.
2. **Add a configuration parameter** (`max_concurrent_clones`, defaulting to 4) so that we limit concurrency for environment constraints.
3. **Refactor analyzers** (e.g., in `analyzers/common.py`) so that `clone_repo`, `get_last_commit_date`, etc., do not block the main thread. Each step can be asynchronous or in a worker pool.
4. **Include error-handling** so that if some tasks fail (e.g., a repo clone times out), the rest of the tasks still continue. Log partial failures but keep going.
5. **Maintain a global concurrency limit** so that we don't spawn too many processes, especially in large monorepos.

---

## Prompt 5: Configuration File Support for Risk Scoring

*"Add a simple configuration file feature to manage risk scoring weights and other user settings. Specifically:*

1. **Create a config loader** (e.g., `config.py`) that looks for a YAML or JSON file (`dependency_risk_config.yaml` or `json`) in the current directory or a user-specified path.
2. **Extend the CLI** to accept a `--config` argument which overrides default or command-line-provided values. If no config file is found, proceed with existing defaults.
3. **Merge** any config file values with the existing CLI flags so that CLI flags take precedence for quick one-off changes.
4. **Document** the structure of the config file with an example snippet (e.g., keys for staleness_weight, maintainers_weight, etc.).
5. **Add test cases** verifying that the config file is correctly loaded, overrides default values, and merges properly if partial config keys are missing.

---

## Prompt 6: Refactoring the CLI with Typer or Click

*"Refactor the command-line interface to use a more modern framework (e.g., Typer or Click) to improve code readability and user help text. Specifically:*

1. **Create a new `cli.py`** that uses Typer for subcommands (`analyze`, `score`, `visualize`, `trends`, `release`, etc.).
2. **Organize** subcommands so that each functional area (e.g., `dependency-risk-profiler analyze <options>`) has its own subcommand help section with typed arguments.
3. **Maintain backward compatibility** if possible, or at least provide deprecation messaging for old flags.
4. **Automatically generate** help text from function docstrings or parameter annotations (Typer feature).
5. **Include error codes** or exit statuses for known error conditions (e.g., missing manifest).

---

## Prompt 7: Single Maintainer vs. Multi-Maintainer Checking

*"Enhance the logic that checks whether a package is maintained by a single individual or a team. Specifically:*

1. **Add checks** that read the repository's contributor/committer data (already shallow cloned) to count unique authors.
2. **Compare** the number of unique authors, using thresholds for 1=single, 2-3=small, 4+ = moderate, 10+ = large.
3. **In the risk scoring** give a higher penalty to single-maintainer dependencies, a smaller penalty to small teams, and no penalty to large communities.
4. **Log** the results in the final terminal output (e.g., "Maintainers: 3 → moderate") and reflect that in the final risk factors list.
5. **Write or update tests** where you clone example repos with dummy commits so that at least one test covers the scenario of single vs. multiple maintainers.

---

## Prompt 8: Automated Documentation Generation

*"Set up automated API documentation generation so that docstrings are reflected in user-friendly docs. Specifically:*

1. **Add a Sphinx or MkDocs** configuration in a `docs/` folder.
2. **Scan** the `src/dependency_risk_profiler` directory to autodoc all public classes and functions.
3. **Generate an index page** summarizing the modules and sub-packages (e.g., `CLI & Parsers`, `Risk Scoring`, `Analyzer Plugins`, etc.).
4. **In README** and/or `docs/README.md`, instruct contributors how to run `sphinx-build` (or `mkdocs build`) to regenerate docs.
5. **Optionally** set up a GitHub Actions workflow to automatically build and deploy the docs to GitHub Pages if the build is successful.