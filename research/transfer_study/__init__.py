"""Harness for `docs/transfer-outcome-protocol.md`, the fifth and final outcome.

Nothing here opens a socket except `harvest.py`. `detect.py` is pure
classification over already-fetched documents so that the procedure the
protocol pre-registers can be tested against fixtures before any package is
fetched, which is condition 3 of the protocol's review.
"""
