#!/usr/bin/env bash
# Merge gate: every required check must be PRESENT and SUCCESS.
# "Nothing failed" is not green -- a PR that conflicts with main gets zero CI
# runs, and absence then reads as pass. Assert presence explicitly.
#
#   ./gate.sh <pr>            report only, exit 0 pass / 1 fail
#   ./gate.sh <pr> --merge    squash-merge, and ONLY if the gate passes
#
# Use --merge. Do not write `./gate.sh N && gh pr merge N` yourself, and above
# all never pipe this script into anything: `./gate.sh N | tail -3 && gh pr
# merge N` merges on a FAILING gate, because the pipeline's exit status is
# tail's. That is not hypothetical -- it happened on #254, and it is the same
# defect as #173, where `gh pr merge` was chained after a `jq` that exits 0
# whatever it prints. Both times the `&&` gated nothing and the merge was
# saved by luck rather than by the check. Keeping the decision and the action
# in one process is the only version of this that cannot be mis-invoked.
set -uo pipefail
PR="${1:?usage: gate.sh <pr-number> [--merge]}"
MERGE="${2:-}"
REPO=williamzujkowski/dependency-risk-profiler
# "Analyze (go)" was here until #231. It passed for months while analysing zero
# lines -- every .go file was under testing/, which codeql-config.yml ignores --
# and became a hard failure the moment that directory was deleted. A required
# check that measures nothing is worse than an absent one.
REQUIRED=("test (3.10)" "test (3.11)" "test (3.12)" "security" "Analyze (actions)" "Analyze (python)")

HEAD_SHA=$(gh pr view "$PR" --repo "$REPO" --json headRefOid -q .headRefOid)
BASE_OK=$(gh pr view "$PR" --repo "$REPO" --json mergeable -q .mergeable)
echo "PR #$PR head=$HEAD_SHA mergeable=$BASE_OK"

# Assert the head commit is actually on top of current origin/main.
#
# GitHub does not index a newly pushed head immediately, so the compare
# endpoint 404s for a short window after a branch is pushed or a PR opened.
# Without the retry the error body lands in $BEHIND, the string comparison
# below is not "0", and the gate fails with a JSON blob where a number should
# be. It fails CLOSED, which is right, but "1 commits behind" and "GitHub has
# not caught up yet" are different facts and the operator has to be able to
# tell them apart.
MAIN_SHA=$(gh api "repos/$REPO/commits/main" -q .sha)
BEHIND=""
for attempt in 1 2 3; do
  BEHIND=$(gh api "repos/$REPO/compare/$MAIN_SHA...$HEAD_SHA" -q .behind_by 2>/dev/null)
  case "$BEHIND" in
    ''|*[!0-9]*) ;;          # empty or non-numeric: not an answer yet
    *) break ;;
  esac
  [ "$attempt" -lt 3 ] && sleep 5
done
case "$BEHIND" in
  ''|*[!0-9]*)
    echo "behind_by=UNDETERMINED (compare endpoint gave no number after 3 tries)"
    BEHIND="undetermined"
    ;;
  *)
    echo "behind_by=$BEHIND (must be 0: checks on a stale base prove nothing)"
    ;;
esac

RUNS=$(gh api "repos/$REPO/commits/$HEAD_SHA/check-runs?per_page=100" \
  -q '.check_runs[] | "\(.name)\t\(.status)\t\(.conclusion)"')
echo "--- all check-runs on $HEAD_SHA ---"
echo "$RUNS"
echo "--- gate ---"
FAIL=0
if [ "$BEHIND" = "undetermined" ]; then
  echo "FAIL: could not establish whether head is current -- refusing rather than guessing"
  FAIL=1
elif [ "$BEHIND" != "0" ]; then
  echo "FAIL: head is $BEHIND commits behind main"
  FAIL=1
fi
for name in "${REQUIRED[@]}"; do
  line=$(echo "$RUNS" | grep -P "^\Q$name\E\t" | head -1)
  if [ -z "$line" ]; then
    echo "FAIL: required check ABSENT: $name"; FAIL=1; continue
  fi
  status=$(echo "$line" | cut -f2); concl=$(echo "$line" | cut -f3)
  if [ "$status" != "completed" ] || [ "$concl" != "success" ]; then
    echo "FAIL: $name status=$status conclusion=$concl"; FAIL=1
  else
    echo "ok:   $name"
  fi
done
[ "$FAIL" = "0" ] && echo "GATE: PASS" || echo "GATE: FAIL"

if [ "$MERGE" = "--merge" ]; then
  if [ "$FAIL" != "0" ]; then
    echo "REFUSING TO MERGE: gate failed above."
    exit 1
  fi
  echo "--- merging #$PR ---"
  gh pr merge "$PR" --repo "$REPO" --squash --delete-branch
  exit $?
elif [ -n "$MERGE" ]; then
  echo "unknown argument: $MERGE (expected --merge)"
  exit 2
fi

exit $FAIL
