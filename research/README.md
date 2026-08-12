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
| `transfer_study/pilot.py` | **Opens a socket.** Measures the detection channel on the burned cohort |
| `transfer_study/maintainer_now.py` | **Opens a socket.** Harvests current top-level maintainer sets for the band-crossing study |
| `transfer_study/band_crossing.py` | Band logic and rates. Pure |
| `transfer_study/band_run.py` | The band-crossing run. `docs/band-crossing-result.md` |

**Nothing has been harvested.** The procedure exists before the cohort on
purpose: it is condition 3 of the protocol's review, and its fixtures live in
`testing/unit/test_transfer_detection.py`.

The discriminator is the GitHub account **id**, not the login. A rename and a
transfer are indistinguishable through `GET /repos/{owner}/{repo}`, which
follows both transparently — and account renames are not distributed like
handovers, so a procedure that conflates them re-couples the outcome to project
activity through the measurement channel, which is the coupling the whole
outcome was chosen to escape.

The first version of the procedure was **rejected 7-0** for a subtler form of
the same defect: the id at T was never observed, only the login, so every
id-at-T came from resolving that login today — and GitHub frees renamed logins
for re-registration. A squatted login resolves to a live account with a
different id, which read as a transfer. Details and the fix in §14 of the
protocol; the creation-date guard and the same-login id check are both
mutation-verified.

### The pilot must clear before the harvest

```bash
GITHUB_TOKEN=$(gh auth token) PYTHONPATH=research \
  uv run python -m transfer_study.pilot \
    --declarations research/results/transfer-pilot-declarations.json \
    --limit 300 --out research/results/transfer-pilot.json
```

It runs on the **burned** 2026-08-06 cohort, which §1 already excludes from the
fresh frame, so the two populations are disjoint by construction and no pilot
row can reach the confirmatory analysis. It reads classification buckets only —
enforced by a test, not by a promise. Its decision rule was fixed in §15 before
the module existed.

## `composition/`

`docs/composition-protocol.md`, result in `docs/composition-result.md`. Asks
what the composite score **is**, not what it predicts — **no outcome, no label,
no window**, so none of the four requirements that closed
`docs/outcome-landscape.md` apply. There is nothing for the signals to be
coupled to.

| Path | What it is |
|---|---|
| `composition/battery.py` | The five activity measures at T, and the two composites |
| `composition/analysis.py` | Rank statistics: Spearman, rank-R², clustered bootstrap and permutation null, grouped cross-validation |
| `composition/experiment.py` | The run, in the pre-registered order |
| `composition/lookup.py` | The composite's input surface, reduced to what it can distinguish |
| `composition/enumerate_table.py` | Prints the whole table. `docs/lookup-table-result.md` |
| `composition/manipulation.py` | Prices the attacker moves the table exposes |
| `composition/price_manipulation.py` | Runs the pricing. `docs/manipulation-result.md` |
| `composition/attacker_surface.py` | What share of the composite's weight a package chooses. Reads the scorer's own constructor |
| `composition/substitution_demo.py` | The arithmetic ceiling on repository substitution, through the real scorer |

Offline and seeded; two runs produce identical files.

```bash
PYTHONPATH=research uv run python -m composition.experiment \
    --snapshot research/data/npm-2026-08-06 \
    --t 2024-08-01 --out research/results/composition-2024.json
```

**Result: the claim was withdrawn.** Five direct measures of publication
activity explain R² ≈ 0.099 of the composite's rank variance (0.075 / 0.094 /
0.099 at three dates), about forty times the permutation null and well under
the 0.15 floor. The composite is *not* an activity proxy — which corrects a
sentence this project had been carrying as an inference for five studies.

## `additive/`

`docs/additive-value-protocol.md`, result in `docs/additive-value-result.md`.
Gates the reweighting question: **does anything the composite measures add to
download count?**

| Path | What it is |
|---|---|
| `additive/logistic.py` | Two-predictor logistic regression by IRLS, standard library only |
| `additive/experiment.py` | Four arms out of fold, maintainer-clustered CV |

```bash
PYTHONPATH=research uv run python -m additive.experiment \
    --snapshot research/data/npm-2026-08-06 \
    --t 2024-08-01 --out research/results/additive-2024.json
```

**Result: absent.** Freeing all three signal weights adds **−0.0114** over
download count out of fold, 95% CI [−0.0246, +0.0010], with a minimum
detectable delta of 0.0128 — so the study could have seen a 0.02 improvement
and did not. There is nothing to reweight.

Every predictor is oriented as **risk**, higher meaning more likely abandoned,
so downloads enter **negated**. Unnegated the baseline scores 0.3040, which is
1 − 0.696, and every arm appears to beat it by a quarter of an AUC.

## `remediation/`

`docs/remediation-protocol.md`, result in `docs/remediation-result.md`. Tests
the substitution the whole abandonment programme stood in for: **if nobody
maintains a package, nobody patches it when a CVE lands.**

| Path | What it is |
|---|---|
| `remediation/build.py` | Predictors as of each advisory's publication date, and the three outcomes |
| `remediation/evaluate.py` | Per-predictor AUC with a package-clustered bootstrap |

**Of npm GHSA advisories with no fix at disclosure, 77.2% of packages never
published again.** Among those that did, about half shipped the fix — and
nothing measured exceeds AUC 0.67 at telling which half.

Two scoping facts that would have wrecked this if missed: **97% of the npm OSV
corpus is malicious-package takedowns** (unpublished, not patched), and **61%
of real advisories arrive already fixed** because coordinated disclosure
publishes after the patch. Both are excluded by rule in the protocol.
