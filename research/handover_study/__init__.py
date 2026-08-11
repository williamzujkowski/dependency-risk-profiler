"""Stage 1 and 2 of the maintainer-handover study.

Pre-registered in ``docs/handover-outcome-protocol.md``. This package holds
only the harvest (§10 step 1) and the base-rate / effective-n computation
(§10 step 2). Nothing downstream of the §10 step-2 gate lives here, by design:
the gate is a stop rule, and a module that could score a model is a module that
could be run before the gate is read.
"""
