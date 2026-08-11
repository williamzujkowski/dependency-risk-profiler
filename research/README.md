# research/

Research harnesses. **Not product code, not packaged, not importable by
`dependency_risk_profiler`.** Nothing under `src/` may import anything here; the
dependency runs one way, from research to product.

## `abandonment_pilot/`

Stage 2 of `docs/validation-protocol.md`: does the shipped risk score predict
that a live npm package goes silent, once release cadence and version drift are
ablated? Results in `docs/abandonment-pilot.md`; the raw numbers in
`research/results/`.

### Layout

| Path | What it is |
|---|---|
| `abandonment_pilot/snapshot.py` | The pinned record shape, and checksum-verified loading |
| `abandonment_pilot/cohort.py` | Eligibility, the abandonment label, and how N is measured |
| `abandonment_pilot/features.py` | As-of-T inputs for the production scorer, and the baselines |
| `abandonment_pilot/stats.py` | AUC, average precision, calibration, clustered bootstrap |
| `abandonment_pilot/experiment.py` | The run, in the pre-registered order |
| `abandonment_pilot/harvest.py` | **The only module that opens a socket** |
| `data/npm-2026-08-06/` | The pinned snapshot: four gzipped files and a manifest of digests |
| `results/` | Whatever `experiment.py` last wrote |

### Reproducing the published numbers

Offline, from the pinned snapshot. No network, no API keys.

```bash
uv sync --extra dev
PYTHONPATH=research uv run python -m abandonment_pilot.experiment \
    --snapshot research/data/npm-2026-08-06 \
    --out research/results/npm-2026-08-06.json
```

The loader verifies every file against the SHA-256 in `MANIFEST.json` and
refuses to run on a snapshot that has drifted, so a run either reproduces the
published numbers or says why it cannot.

### Re-harvesting

Two passes, both hitting live registries, both run by hand. CI never runs
either — `testing/unit/test_abandonment_pilot.py` asserts that no analysis
module can even import an HTTP client.

```bash
# The name universe. Pin the version; the manifest records the digest.
curl -sLO https://registry.npmjs.org/all-the-package-names/-/all-the-package-names-2.0.2524.tgz
tar xzf all-the-package-names-2.0.2524.tgz package/names.json

# Pass 1: ~35 minutes. 60,000 packuments.
PYTHONPATH=research uv run python -m abandonment_pilot.harvest packuments \
    --names package/names.json --out research/data/npm-YYYY-MM-DD

# Pass 2: needs T, which is only known once N is read off pass 1's life table.
GITHUB_TOKEN=... PYTHONPATH=research uv run python -m abandonment_pilot.harvest baselines \
    --out research/data/npm-YYYY-MM-DD --at 2024-08-01
```

A re-harvest will not be byte-identical to a previous one: npm unpublishes
versions and GitHub stars move. Every record carries the SHA-256 of the
packument it was reduced from, so drift is detectable per package rather than
only in aggregate.

## `transfer_study/`

The fifth and final outcome, pre-registered in
`docs/transfer-outcome-protocol.md`: does the composite identify packages whose
GitHub repository changes owner? It is the only outcome measured to be
independent of project activity (release cadence scores 0.5104 against it), and
it is the capstone — either branch completes `docs/outcome-landscape.md`.

| Path | What it is |
|---|---|
| `transfer_study/detect.py` | The pre-registered decision procedure. Pure; takes fetched documents, opens nothing |

**Nothing has been harvested.** The procedure exists before the cohort on
purpose: it is condition 3 of the protocol's review, and its fixtures live in
`testing/unit/test_transfer_detection.py`.

The discriminator is the GitHub account **id**, not the login. A rename and a
transfer are indistinguishable through `GET /repos/{owner}/{repo}`, which
follows both transparently — and account renames are not distributed like
handovers, so a procedure that conflates them re-couples the outcome to project
activity through the measurement channel, which is the coupling the whole
outcome was chosen to escape.
