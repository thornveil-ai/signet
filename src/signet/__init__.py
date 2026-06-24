"""signet -- capability-based safety gates for LLM agents.

The model proposes; signet authorizes. signet sits between an LLM and any
system that can execute its outputs, providing programmatic checks (owner
resolution, classification gating, dual-judge dissent, sandbox preview, HMAC-
chained audit) that decide whether the model's proposed action is allowed to
actually run.

The model never holds commit authority. Same shape as a junior employee who
can fill out a purchase order but cannot sign the check.
"""

from __future__ import annotations

__version__ = "0.1.11"

__all__ = ["__version__"]
