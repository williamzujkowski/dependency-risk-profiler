#!/usr/bin/env bash
# Merge gate: every required check must be PRESENT and SUCCESS.
# "Nothing failed" is not green -- a PR that conflicts with main gets zero CI
# runs, and absence then reads as pass. Assert presence explicitly.
set -uo pipefail
PR="$1"
REPO=williamzujkowski/dependency-risk-profiler
# "Analyze (go)" was here until #231. It passed for months while analysing zero
# lines -- every .go file was under testing/, which codeql-config.yml ignores --
# and became a hard failure the moment that directory was deleted. A required
# check that measures nothing is worse than an absent one.
REQUIRED=("test (3.10)" "test (3.11)" "test (3.12)" "security" "Analyze (actions)" "Analyze (python)")

HEAD_SHA=$(gh pr view "$PR" --repo "$REPO" --json headRefOid -q .headRefOid)
BASE_OK=$(gh pr view "$PR" --repo "$REPO" --json mergeable -q .mergeable)
echo "PR #$PR head=$HEAD_SHA mergeable=$BASE_OK"

# Assert the head commit is actually on top of current origin/main
MAIN_SHA=$(gh api "repos/$REPO/commits/main" -q .sha)
BEHIND=$(gh api "repos/$REPO/compare/$MAIN_SHA...$HEAD_SHA" -q .behind_by)
echo "behind_by=$BEHIND (must be 0: checks on a stale base prove nothing)"

RUNS=$(gh api "repos/$REPO/commits/$HEAD_SHA/check-runs?per_page=100" \
  -q '.check_runs[] | "\(.name)\t\(.status)\t\(.conclusion)"')
echo "--- all check-runs on $HEAD_SHA ---"
echo "$RUNS"
echo "--- gate ---"
FAIL=0
[ "$BEHIND" != "0" ] && { echo "FAIL: head is $BEHIND commits behind main"; FAIL=1; }
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
exit $FAIL
