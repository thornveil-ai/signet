"""Built-in checks shipped with signet.

A check is one policy-evaluation step. The eleven built-in checks cover the
most common controls; anything else is a plugin (see :mod:`signet.plugins`
for the discovery interface).

By stage:

ADMISSION
    * :class:`OwnerResolutionCheck` -- refuse if no resolvable commit owner
    * :class:`LoopbackTrustCheck` -- auto-resolve owner for trusted internal IPs
    * :class:`ClassificationGateCheck` -- 5-level architectural enforcement
    * :class:`RateLimitCheck` -- per-owner token-bucket
    * :class:`TokenBudgetCheck` -- per-owner per-window output token quota
    * :class:`PromptInjectionCheck` -- pattern + heuristic scan on input
    * :class:`RegexContentCheck` (input mode) -- block/redact patterns in request

INSPECTION
    * :class:`RegexOutputCheck` -- same patterns, output side
    * :class:`ContinuingConsentCheck` -- re-evaluate owner authority mid-stream
    * :class:`ScopeDriftCheck` -- abort when output exceeds the originally-approved scope

COMMITMENT
    * :class:`ToolCallInspectorCheck` -- risk-tier gating + tool allowlist

These compose. A typical production pipeline runs all ADMISSION checks,
then the INSPECTION checks during streaming, then the COMMITMENT check
on each tool call. RECORD-stage checks are usually plugins (drift
detection, behavioral baselines).
"""

from __future__ import annotations

from signet.checks.classification_gate import ClassificationGateCheck, ClassificationLevel
from signet.checks.continuing_consent import ContinuingConsentCheck, RevalidateFn
from signet.checks.loopback_trust import LoopbackTrustCheck
from signet.checks.owner_resolution import OwnerResolutionCheck
from signet.checks.prompt_injection import PromptInjectionCheck, Severity
from signet.checks.rate_limit import (
    InMemoryRateLimitState,
    RateLimitCheck,
    RateLimitState,
)
from signet.checks.regex_content import Pattern, RegexContentCheck, RegexOutputCheck
from signet.checks.scope_drift import ScopeDriftCheck
from signet.checks.token_budget import TokenBudgetCheck, WindowSize
from signet.checks.tool_call_inspector import RiskTier, ToolCallInspectorCheck, ToolSpec

__all__ = [
    "ClassificationGateCheck",
    "ClassificationLevel",
    "ContinuingConsentCheck",
    "InMemoryRateLimitState",
    "LoopbackTrustCheck",
    "OwnerResolutionCheck",
    "Pattern",
    "PromptInjectionCheck",
    "RateLimitCheck",
    "RateLimitState",
    "RegexContentCheck",
    "RegexOutputCheck",
    "RevalidateFn",
    "RiskTier",
    "ScopeDriftCheck",
    "Severity",
    "TokenBudgetCheck",
    "ToolCallInspectorCheck",
    "ToolSpec",
    "WindowSize",
]
