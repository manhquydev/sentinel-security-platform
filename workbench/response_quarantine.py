"""Strict B3 provider-response quarantine.

This module is deliberately a separate boundary so dispatchers cannot import a
general-purpose provider parser and accidentally persist raw provider material.
"""
from __future__ import annotations

from .egress import EgressViolation, QuarantinedResponse, quarantine_response

__all__ = ("EgressViolation", "QuarantinedResponse", "quarantine_response")
