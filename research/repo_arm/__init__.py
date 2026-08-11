"""The repository arm: stages 2-4 of ``docs/repository-arm-protocol.md``.

Stage 2 resolves the cohort's declared GitHub repositories and clones them
under §10's hardening. Stage 3 reconstructs six signals at T from the clone
alone. Stage 4 runs the negative control the protocol makes primary. Nothing
here computes a model AUC: stages 5-7 are a separate run, and §9 orders the
control strictly before any model result.
"""
