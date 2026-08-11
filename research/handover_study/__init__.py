"""The maintainer-handover study, pre-registered in
``docs/handover-outcome-protocol.md``.

Stage 1 is the harvest (§10 step 1), stage 2 the base rate and effective n
(§10 step 2), and stages 3 to 6 the negative control, the trivial baselines,
the model head-to-head and the per-signal ablations (§10 steps 3-6).

**Step 7, the misclassification audit, is not implemented here.** §7 forbids
any "evidence of absence" claim until it bounds the rename and silent-transfer
error rates, and a module that could produce such a claim without that audit is
a module that could be run without it.
"""
