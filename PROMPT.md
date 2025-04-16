Below is an example of a comprehensive prompt you can give to a code‐creation LLM. This prompt clearly outlines the concept, features, technical requirements, and desired output of your “Open-Source Dependency Risk Profiler” CLI tool. You can copy this and adjust details as needed:

---

**Prompt for Code Creation LLM: Build an Open-Source Dependency Risk Profiler CLI Tool**

**Overview:**

Create a command-line tool (CLI) called **“Dependency Risk Profiler”** that goes beyond traditional vulnerability scanners by assessing the overall “health” of a project’s open-source dependencies. The tool will analyze a software project’s dependency manifest (e.g., package-lock.json for Node.js, requirements.txt for Python, go.mod for Go) and evaluate each dependency according to quality and maintenance risk indicators. This profiler should help developers quickly identify libraries that may be outdated, undermaintained, or potentially risky—even if they have no reported CVEs.

**Core Features and Requirements:**

1. **Input & File Parsing:**
   - The tool should accept a path to a dependency file (or multiple files) as an input argument.
   - It must support common manifest or lock files:
     - **Node.js:** `package-lock.json`
     - **Python:** `requirements.txt` (and optionally, `Pipfile.lock`)
     - **Go:** `go.mod`
   - Modular design is preferred so that support for additional package managers can be added later.

2. **Data Collection for Each Dependency:**
   For each dependency extracted from the manifest, the tool should attempt to collect and compute the following metrics without requiring any API credentials (using only anonymous access or local analysis):
   - **Version Comparison:**
     - Determine the installed version versus the latest available version (e.g., by scraping package repositories or inspecting local metadata).
   - **Update Recency:**
     - Calculate how long ago the dependency was last updated (e.g., using commit or release date information). If needed, the tool can clone the dependency’s repository locally to inspect its commit history.
   - **Maintenance and Community Indicators:**
     - Check whether the project appears to be maintained by a single maintainer or by a team (for example, by estimating the number of contributors or checking if multiple maintainer names appear).
     - Flag if the dependency is marked as deprecated (e.g., from repository metadata or tags).
     - Optionally, check for the presence of standard repository files that indicate healthy maintenance (e.g., existence of tests, CI configuration files, contribution guidelines).
   - **Public Exploit Information:**
     - Optionally, scan for any public exploit or vulnerability warnings (this can be integrated by scraping public feeds or searching for alerts associated with the package, always using publicly available data).
     
3. **Risk Scoring and Output:**
   - Compute a composite risk score for each dependency based on weighted factors:
     - Example weights might be: 
       - **Staleness:** Longer time since last update increases risk.
       - **Single Maintainer:** Fewer maintainers increases risk.
       - **Deprecated Status:** A deprecated flag adds a significant risk factor.
       - **Exploit Info:** Presence of any public exploit info further increases the risk.
   - Display the results in a clear, color-coded report in the terminal. For example:
     - Green for low-risk dependencies.
     - Yellow for moderate risk.
     - Red for high-risk dependencies.
   - Optionally, support output in JSON format as well.

4. **CLI Interface and Options:**
   - The CLI should include command-line arguments to specify:
     - The file path(s) to dependency manifests.
     - The output format (default colorized text report; an option for JSON).
     - Verbosity or “debug” mode for more detailed logging.
     - Optional parameters such as custom thresholds for risk scoring.
   - Provide a helpful usage message when invoked with a `--help` flag.

5. **Technical and Architectural Requirements:**
   - **Language:** The implementation can be in Python (or another language, but Python is recommended for rapid prototyping and ease of handling file I/O and HTTP scraping).
   - **Modular Structure:** Structure your code so that parsing logic, data fetching/analysis, risk scoring, and CLI output are contained in separate modules or functions. This will make future extension easier.
   - **No External Credentials:** All data-gathering must be done anonymously (e.g., scraping public repositories or using public endpoints) to avoid needing API keys or logins.
   - **Error Handling:** Implement robust error handling—if a dependency cannot be analyzed (e.g., due to missing data), the tool should log a warning but continue processing others.
   - **Documentation:** Include inline documentation and a README section within the code comments that explains how to run the tool and extend its functionality.

**Example Usage Scenario:**

A developer runs the command:
```
$ dependency-risk-profiler --manifest /path/to/package-lock.json --output terminal
```
The tool parses the package-lock.json file, evaluates each dependency according to the metrics listed above, computes risk scores, and then outputs a color-coded report that might look like:
```
Dependency         Installed   Latest    Last Update     Maintainers    Risk Score    Status
---------------------------------------------------------------------------------------------
lodash             4.17.15     4.17.21   6 months ago    3              2.1/5         LOW
some-old-lib       1.0.0       1.2.0     4 years ago     1              4.7/5         HIGH (Outdated)
...
```
Optionally, the developer can also get the output in JSON format by adding a flag `--output json`.

**Final Instruction:**
Using the above specifications, produce a complete, well-documented script that implements this CLI tool, keeping the code modular and maintainable. Include error handling, logging, and a user-friendly CLI interface.

---

Feel free to ask for clarifications or modifications if needed. This prompt should guide the code creation LLM to generate a solution that aligns closely with your design objectives for assessing dependency health and supply chain risk.