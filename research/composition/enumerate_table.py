"""Print the registry-only composite as the finite table it is.

`docs/leading-indicator-protocol.md` claim A; result in
`docs/lookup-table-result.md`. Offline, exact, no statistics: score every
cohort member, record the input tuple the composite can actually distinguish,
and fold. Twelve cells, eleven scores, no exceptions.

    PYTHONPATH=research uv run python -m composition.enumerate_table
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from abandonment_pilot.cohort import build_cohort
from abandonment_pilot.snapshot import load_snapshot
from dependency_risk_profiler.scoring.risk_scorer import RiskScorer
from composition.battery import ablated_metadata
from composition.lookup import build_table, cell_of, scorer_fingerprint

m = datetime.fromisoformat("2024-08-01").replace(tzinfo=timezone.utc)
s = load_snapshot(Path("research/data/npm-2026-08-06"))
members, _ = build_cohort(s.packages, m, 2, s.harvested_at)
rec = {r.name: r for r in s.packages}
sc = RiskScorer()
obs = []
for mem in members:
    md = ablated_metadata(rec[mem.name], mem)
    r = sc.score_dependency(md)
    obs.append((cell_of(md, sc), r.total_score / sc.max_score, r.insufficient_data))
table = build_table(obs)
out: dict = dict(table)
out["scorer_fingerprint"] = scorer_fingerprint(sc)
out["cohort"] = len(members)
out["t"] = "2024-08-01"
Path("research/results/lookup-table-2024.json").write_text(json.dumps(out, indent=2) + "\n")
print("cells", out["cells"], "scores", out["distinct_scores"], "is_a_function", out["is_a_function"])
for row in out["table"]:
    print(round(row["score"], 4), row["packages"], row["inputs"])
