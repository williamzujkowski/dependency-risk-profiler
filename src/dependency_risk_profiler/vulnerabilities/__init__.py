"""Vulnerability aggregation module for dependency risk assessment."""

from .aggregator import aggregate_vulnerability_data, normalize_cvss_score

__all__ = ["aggregate_vulnerability_data", "normalize_cvss_score"]
