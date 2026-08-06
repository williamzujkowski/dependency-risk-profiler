"""Abandonment pilot: stage 2 of `docs/validation-protocol.md`.

A research harness, not product code. It asks one question the protocol says is
not circular: with release cadence and version drift ablated, do maintainer
concentration and provenance predict whether a live package goes silent?

The analysis modules are offline by construction. :mod:`.harvest` is the only
one that opens a socket, and nothing imports it.
"""
