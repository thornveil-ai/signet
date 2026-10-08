"""Plugin interface -- bring-your-own checks via Python entry points.

The 11 built-in checks in :mod:`signet.checks` cover the most common
cases. Anything else -- LLM-as-judge, sandbox preview, your own
PII detector, custom session-policy logic -- ships as a plugin.

Plugins are discovered via Python's standard ``importlib.metadata``
entry-point mechanism. A plugin package declares an entry under the
``signet.checks`` group:

.. code-block:: toml

    [project.entry-points."signet.checks"]
    tribunal = "my_signet_pkg.tribunal:TribunalCheck"
    sandbox  = "my_signet_pkg.sandbox:SandboxPreviewCheck"

signet then enumerates every entry under that group at startup
(or on demand) and offers them by name to whatever wires up the
:class:`signet.core.pipeline.Pipeline`.

This package provides:

* :func:`signet.plugins.discover_plugins` -- structured discovery
  report covering ``signet.checks``, ``signet.adapters`` and
  ``signet.anchors``, including load failures and ABI mismatches.
* :func:`signet.plugins.discover` -- back-compat dict of loaded
  ``signet.checks`` plugins (name → class).
* :func:`signet.plugins.load_by_name` -- fetch one Check class by
  entry-point name (raises ``KeyError`` if unknown).
* :func:`signet.plugins.resolve` -- like :func:`load_by_name` but also
  surfaces ``RuntimeError`` for plugins that failed to load or
  declared an incompatible ABI.
* :class:`signet.plugins.tribunal.TribunalCheck` -- reference dual-judge
  dissent check (caller supplies judge endpoint URLs).
* :class:`signet.plugins.sandbox.SandboxPreviewCheck` -- reference
  preview-before-commit check (caller supplies sandbox runner).

The two reference plugins illustrate the pattern but are intentionally
minimal -- production-tuned implementations live in the proprietary
Pyros engine, not in this OSS release.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from signet.plugins.discovery import (
    ENTRY_POINT_GROUP,
    ENTRY_POINT_GROUPS,
    DiscoveredPlugin,
    PluginStatus,
    discover,
    discover_plugins,
    load_by_name,
    reset_cache,
)
from signet.plugins.sandbox import (
    SandboxPolicy,
    SandboxPreviewCheck,
    SandboxResult,
    SandboxRunner,
)
from signet.plugins.tribunal import TribunalCheck

if TYPE_CHECKING:
    from signet.core.check import Check


def resolve(name: str, *, group: str = "signet.checks") -> type[Check]:
    """Look up a discovered plugin by entry-point name and return its class.

    Args:
        name: The entry-point name (the key on the left of
            ``[project.entry-points."signet.checks"]`` in
            ``pyproject.toml``).
        group: Which entry-point group to search. Defaults to
            ``"signet.checks"``.

    Returns:
        The plugin class.

    Raises:
        KeyError: When no plugin with that name is registered in
            ``group``. The message lists the known names so typos
            surface immediately.
        RuntimeError: When the plugin was discovered but is unsafe
            to use -- failed to load (status ``"load_error"``),
            declared an incompatible ABI (status
            ``"incompatible_abi"``), or has been registered by two
            or more packages under the same name (status
            ``"duplicate_name"``). The original error message is
            embedded; for duplicate names the message names the
            conflicting packages so the operator knows which one to
            uninstall.
    """
    plugins = discover_plugins()
    matches = [p for p in plugins if p.group == group and p.name == name]
    if not matches:
        known = sorted({p.name for p in plugins if p.group == group}) or ["(none registered)"]
        raise KeyError(
            f"no signet plugin named {name!r} in group {group!r}; known plugins: {', '.join(known)}"
        )
    plugin = matches[0]
    if plugin.status == "duplicate_name":
        raise RuntimeError(
            f"signet plugin {name!r} ({group}) has duplicate "
            f"registrations: {plugin.duplicate_with}; resolve "
            f"ambiguity by uninstalling the conflicting package"
        )
    if plugin.status != "loaded":
        raise RuntimeError(
            f"signet plugin {name!r} ({group}) is unavailable "
            f"[status={plugin.status}]: {plugin.error}"
        )
    assert plugin.obj is not None  # status == "loaded" implies obj set
    # ``plugin.obj`` is ``Any`` on the dataclass. The status check above
    # guarantees discovery validated it as a ``type[Check]``; the cast
    # makes the return-type narrowing explicit for mypy.
    return cast("type[Check]", plugin.obj)


__all__ = [
    "ENTRY_POINT_GROUP",
    "ENTRY_POINT_GROUPS",
    "DiscoveredPlugin",
    "PluginStatus",
    "SandboxPolicy",
    "SandboxPreviewCheck",
    "SandboxResult",
    "SandboxRunner",
    "TribunalCheck",
    "discover",
    "discover_plugins",
    "load_by_name",
    "reset_cache",
    "resolve",
]
