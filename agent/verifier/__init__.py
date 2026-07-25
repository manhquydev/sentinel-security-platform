"""Clean-room guided-question SAST verifier (AI-SAST inherit-and-upgrade, Phase 1 spike).

Inherits the *method* (per-finding guided-question triage) from VulnHunterX's Vulnhalla — never its
templates or source (LGPL-2.1; clean-room per the user decision 2026-07-25). The verdict is MEASURED
against a labelled FP-trap corpus, never trusted: see docs/ai-sast-verifier-design.md.
"""
