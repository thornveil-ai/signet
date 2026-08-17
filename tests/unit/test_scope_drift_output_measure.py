"""ScopeDriftCheck must measure model output, not the inspection surface.

The check compares a cap expressed as ``max_tokens * chars_per_token`` against
a character count. It used to take that count from ``accumulated_text``, which
is the INSPECTION surface and deliberately carries event-level metadata
(``id``, ``model``, other non-structural strings) because a hostile upstream
can smuggle markers through those fields.

That metadata repeats on every chunk, so the inspection surface grows with
CHUNK COUNT rather than with how much the model said. Against a real vLLM
stream a chunk carrying ONE character of content contributed 58 characters.
The result was 20 consecutive false aborts on compliant output, each landing a
few dozen characters past whatever cap was configured -- raising the cap only
moved where the same runaway counter crossed it.
"""

import json

import pytest

from signet.checks.scope_drift import ScopeDriftCheck
from signet.core.context import RequestContext, ResponseContext
from signet.core.owner import Owner
from signet.server.app import _SSEBuffer


def _req(max_tokens: int) -> RequestContext:
    return RequestContext(
        owner=Owner.unresolved(),
        headers={},
        body={"max_tokens": max_tokens, "messages": []},
        client_ip=None,
    )


def _chunk(content: str, *, model: str = "nemotron-3-super") -> str:
    body = json.dumps(
        {
            "id": "chatcmpl-891ccb863c6776c7a3788fcf9607456e",
            "object": "chat.completion.chunk",
            "created": 1786920862,
            "model": model,
            "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
        }
    )
    return f"data: {body}\n\n"


def test_metadata_dominates_the_inspection_surface():
    """The measurement that made the old behaviour inevitable."""
    buf = _SSEBuffer()
    inspected = buf.feed(_chunk("x"))

    assert buf.output_char_count == 1, "one character of content is one character of output"
    assert len(inspected) > 50, (
        "the inspection surface should still carry event metadata -- markers "
        "hide there and it must keep being scanned"
    )
    # The whole bug in one assertion.
    assert len(inspected) > 40 * buf.output_char_count


def test_output_counter_tracks_content_not_chunk_count():
    buf = _SSEBuffer()
    for _ in range(100):
        buf.feed(_chunk("x"))

    assert buf.output_char_count == 100, (
        f"expected 100 characters of output, counted {buf.output_char_count}"
    )


def test_reasoning_tokens_count_as_output():
    """A reasoning model spends real budget on them and they stream to the client."""
    buf = _SSEBuffer()
    body = json.dumps(
        {
            "id": "chatcmpl-1",
            "model": "m",
            "choices": [{"index": 0, "delta": {"reasoning": "thinking hard"}}],
        }
    )
    buf.feed(f"data: {body}\n\n")
    assert buf.output_char_count == len("thinking hard")


@pytest.mark.asyncio
async def test_compliant_stream_is_not_aborted():
    """500 chunks of one character, against a 400-token budget.

    Real output is 500 characters, comfortably inside a cap of
    400 * 4 * 1.1 = 1760. The inspection surface for the same stream is
    ~29,000 characters, which is what used to trip the check.
    """
    check = ScopeDriftCheck()
    req = _req(400)
    rctx = ResponseContext(request=req)
    buf = _SSEBuffer()

    for _ in range(500):
        rctx.extend_text(buf.feed(_chunk("x")))
        rctx.output_char_count = buf.output_char_count
        result = await check.inspect_response_chunk(rctx, "x")
        assert not result.is_block, (
            f"compliant stream aborted: {result.reason} "
            f"(output={rctx.output_char_count}, inspected={len(rctx.accumulated_text)})"
        )

    assert len(rctx.accumulated_text) > 10 * rctx.output_char_count


@pytest.mark.asyncio
async def test_genuine_overrun_is_still_caught():
    """The check must still do its job."""
    check = ScopeDriftCheck()
    req = _req(10)
    rctx = ResponseContext(request=req)

    # Cap is 10 * 4 * 1.1 = 44 characters. Produce far more than that.
    rctx.output_char_count = 5000
    result = await check.inspect_response_chunk(rctx, "x" * 100)

    assert result.is_block, "a genuine runaway was allowed through"
    assert "5000" in (result.reason or ""), (
        f"the reported count should be what was measured: {result.reason}"
    )


@pytest.mark.asyncio
async def test_falls_back_when_the_counter_is_absent():
    """A caller on an older context must not silently lose enforcement."""
    check = ScopeDriftCheck()
    req = _req(10)
    rctx = ResponseContext(request=req)
    rctx.extend_text("y" * 5000)
    # output_char_count left at 0, as a pre-counter caller would leave it.

    result = await check.inspect_response_chunk(rctx, "y")
    assert result.is_block, "enforcement was lost when the counter was unset"
