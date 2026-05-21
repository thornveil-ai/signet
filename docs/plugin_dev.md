# Writing a signet plugin

A plugin is just a `Check` subclass shipped in its own Python package, registered via Python's standard entry-point mechanism. signet discovers it at runtime; no patching, no monkey-business, no hard dependency on signet from the plugin side at import time (only at runtime).

## Minimal plugin

```python
# my_signet_plugins/cool_check.py

from signet.core.check import Check, CheckResult
from signet.core.context import RequestContext
from signet.core.stage import Stage


class CoolCheck(Check):
    name = "cool_check"
    stage = Stage.ADMISSION

    def __init__(self, *, threshold: int = 10) -> None:
        self.threshold = threshold

    async def pre_request(self, ctx: RequestContext) -> CheckResult:
        # Your policy logic here.
        if len(ctx.body.get("messages", [])) > self.threshold:
            return CheckResult.block(
                f"too many messages ({len(ctx.body['messages'])} > {self.threshold})",
                threshold=self.threshold,
            )
        return CheckResult.allow()
```

## Register the entry point

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."signet.checks"]
cool_check = "my_signet_plugins.cool_check:CoolCheck"
```

Multiple checks per package are fine:

```toml
[project.entry-points."signet.checks"]
cool_check = "my_signet_plugins.cool_check:CoolCheck"
fancy_check = "my_signet_plugins.fancy:FancyCheck"
```

After `pip install my-signet-plugins`, signet's `discover()` will find them:

```python
from signet.plugins import discover, load_by_name

print(discover())
# {'cool_check': <class 'my_signet_plugins.cool_check.CoolCheck'>,
#  'fancy_check': <class 'my_signet_plugins.fancy.FancyCheck'>}

CoolCheck = load_by_name("cool_check")
```

## Using a discovered plugin in a pipeline

```python
from signet.core.pipeline import Pipeline
from signet.plugins import load_by_name

CoolCheck = load_by_name("cool_check")

pipeline = Pipeline(checks=[
    CoolCheck(threshold=20),
    # ...other checks
])
```

## The four hooks

Every `Check` has four hook points. Override only the ones you need:

| Hook | Stage | When it fires |
|---|---|---|
| `pre_request(ctx)` | ADMISSION | Before forwarding to upstream |
| `inspect_response_chunk(ctx, chunk)` | INSPECTION | Per streamed chunk |
| `inspect_tool_call(ctx)` | COMMITMENT | Per proposed tool call |
| `post_complete(ctx)` | RECORD | After the response finishes |

Set `stage` on your class to declare *which one is your primary*. The pipeline orders checks by stage. A check can override multiple hooks if it spans stages (e.g. TokenBudgetCheck does pre_request + post_complete).

## Decision types

Return one of:

```python
CheckResult.allow(reason="ok")
CheckResult.block(reason="...", **metadata)
CheckResult.redact(replacement="...", reason="...")
CheckResult.escalate(reason="needs human review")
```

Stage semantics:

- ADMISSION: any non-allow refuses the request (HTTP 403 or 429).
- INSPECTION: non-allow aborts the stream mid-flight; caller sees a trailer event.
- COMMITMENT: non-allow refuses the specific tool call; the model continues.
- RECORD: audit-only — non-allow is logged but doesn't modify the already-delivered response.

## Best practices

**Keep checks fast.** ADMISSION runs once per request; INSPECTION runs *per chunk*. If your check needs an external call, cache aggressively or move it to RECORD.

**Fail closed on errors.** When your check raises an exception or a dependency is unreachable, return `CheckResult.block` with a descriptive reason. Don't let exceptions bubble up to the pipeline — that's a security hole.

**Don't stash per-request state on `self`.** A check instance is reused across many requests. Use `ctx.scratch` for cross-hook state within one request, or `signet.server.session.Session` for cross-request state.

**Test with real adversarial inputs.** Add a test under `tests/adversarial/` (in your own repo) demonstrating the attack your check defends against and proving it blocks. This is the trust artifact for users evaluating your plugin.

## Reference plugins

The signet repo ships two reference plugins that demonstrate the pattern:

- `signet.plugins.tribunal.TribunalCheck` — dual-judge dissent, caller supplies judge endpoints.
- `signet.plugins.sandbox.SandboxPreviewCheck` — preview-before-commit, caller supplies sandbox runner.

Both are intentionally minimal. Production-grade implementations of the same patterns ship in the proprietary Pyros engine; the OSS reference is for educational purposes and as a starting point for your own.

## Publishing your plugin

1. Standard Python packaging: `python -m build` produces sdist + wheel.
2. Publish to PyPI: `twine upload dist/*`.
3. Add the `signet-plugin` topic to your GitHub repo so other signet users can find it.
4. Open an issue in thornveil-ai/signet to add your plugin to the community list (optional).

## Contributing reference plugins back to signet

If your plugin is genuinely useful to the broader community AND has no proprietary IP concerns, consider contributing it as a reference implementation to `signet.plugins.*`. See `CONTRIBUTING.md` — the bar is real engineering quality, comprehensive tests, and one of the maintainers willing to vouch.
