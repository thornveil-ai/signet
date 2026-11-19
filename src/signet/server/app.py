"""SignetApp -- the FastAPI application that ties everything together.

Round 7 hardening (server-side):

* Non-UTF-8 inbound bodies now route through the preflight refusal
  helper with ``_refusal_kind="invalid_encoding"`` instead of raising
  ``UnicodeDecodeError`` past Starlette and surfacing as a bare 500
  with no audit row.
* Non-dict upstream JSON (top-level array/scalar/null, or
  ``{"choices": "x"}``) is caught via ``_record_upstream_failure`` with
  ``refusal_kind="upstream_protocol_violation"`` so dashboards filtering
  on ``check_name="pipeline.upstream"`` see the event.
* Preflight 400 bodies now honor ``strict_error_redaction`` and always
  carry ``correlation_id`` via the shared ``_preflight_body`` helper.
* GET (or any verb) on an unknown ``/v1/<path>`` now returns the same
  404 catch-all body that POST returns, instead of a misleading 405
  advertising POST as the working method.
* ``X-Signet-Session`` is now capped at ``_MAX_SESSION_ID_BYTES`` (256)
  and restricted to a printable-token charset
  (``[A-Za-z0-9_.:-]``); pathological IDs are refused 400 with a
  preflight audit row.
* ``POST /v1/chat/completions/`` (trailing slash) is now normalized to
  the registered route, matching OpenAI's behavior.

Round 7 hardening (streaming-side):

* SSE inspection is now stateful across ``aiter_bytes()`` chunks via
  the ``_SSEBuffer`` class: a ``data:`` line straddling raw byte chunks
  no longer slips past ``ScopeDriftCheck`` / ``RegexOutputCheck``.
* ``delta.tool_calls[*].function.{name, arguments}``,
  ``delta.refusal``, ``delta.reasoning``, ``delta.reasoning_content``,
  and ``delta.audio.transcript`` are now inspected alongside
  ``delta.content``.
* Per-stream chunk size is capped at ``_MAX_STREAM_CHUNK_BYTES`` (1
  MiB) so a hostile upstream cannot OOM the proxy with a single huge
  chunk.
* Non-UTF-8 SSE bytes are treated as ``upstream_protocol_violation``
  and the stream is terminated with a structured abort frame instead
  of being forwarded unscanned.
* Malformed SSE frames (JSONDecodeError on the assembled ``data:``
  payload) are counted per-stream and surfaced as
  ``dropped_frame_count`` in the ``pipeline.complete`` audit metadata.


The proxy serves these endpoints:

* ``GET /health`` (alias ``/healthz``) -- liveness probe with operational
  metadata: signet version, uptime, audit-chain head HMAC tail,
  configured pipeline check count.
* ``GET /readyz`` -- readiness probe; HEADs the configured upstream with
  a 1-second timeout. 503 when upstream is unreachable so k8s sheds
  traffic. Distinct from ``/health`` so liveness restarts don't fire on
  an upstream blip.
* ``GET /version`` -- build identifier.
* ``POST /v1/chat/completions`` -- the protected forwarding endpoint.

The chat-completions handler runs the configured pipeline at the
appropriate hook timings:

1. Build :class:`RequestContext` from the inbound request.
2. Call ``pipeline.pre_request(ctx)``. If non-allow → refuse with
   the appropriate HTTP status.
3. Forward the (possibly redacted) body to the upstream. Stream or
   non-stream per the request's ``stream`` field.
4. For streaming responses, on each upstream chunk:
   - Update :class:`ResponseContext`.
   - Call ``pipeline.inspect_response_chunk(rctx, chunk)``. If non-allow
     → abort the stream and emit a trailer event.
   - Otherwise yield the chunk to the caller.
5. After the response completes, call ``pipeline.post_complete(rctx)``
   to run RECORD-stage checks.
6. Write an audit entry; sign and emit ``X-Signet-Receipt``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import JSONResponse, StreamingResponse

from signet import __version__
from signet.audit.backend import JsonlBackend
from signet.audit.chain import HmacChain
from signet.audit.keyring import Key, KeyRing
from signet.core.audit import AuditEntry, Decision
from signet.core.context import (
    RequestContext,
    ResponseContext,
    ToolCallContext,
    get_header_ci,
)
from signet.core.owner import Owner
from signet.core.pipeline import Pipeline
from signet.server.config import ServerConfig
from signet.server.metrics import Metrics
from signet.server.receipt import HmacReceiptSigner, ReceiptSigner
from signet.server.session import HEADER_NAME as SESSION_HEADER
from signet.server.session import InMemorySessionStore, SessionStore

logger = logging.getLogger("signet.server")

#: Abort-frame ``reason`` tokens that name a network/transport failure
#: rather than a policy decision. These survive strict-error-redaction
#: coarsening because they describe a wire state the SDK needs to react
#: to -- retrying a ``refused`` request is wrong, retrying an
#: ``upstream_protocol_violation`` may be right. The set is closed:
#: anything not listed here is treated as policy-revealing and coarsened
#: to ``"refused"`` under strict mode.
_TRANSPORT_ABORT_REASONS: frozenset[str] = frozenset(
    {
        "upstream_protocol_violation",
        "upstream_exception",
        "upstream_timeout",
        "upstream_error",
        # S7: upstream returned non-SSE content-type on a streaming
        # endpoint. SDKs need this distinct from a policy refusal so
        # they can decide whether to retry against a different
        # upstream / route, rather than re-issuing identical traffic
        # to a misconfigured backend.
        "upstream_content_type_invalid",
        # Round 4 hunt: upstream returned a 3xx redirect. Distinct from
        # policy refusal so SDKs can surface the redirect-target host
        # to operators and bail out rather than blindly retry against
        # the redirecting upstream.
        "upstream_redirect",
        # Round 9 closures: an event whose joined ``data:`` payload
        # fails JSON parse, or whose pending-raw buffer exceeds the
        # cap, aborts via these tokens. Transport-class because the
        # bytes the client is missing aren't a policy refusal -- the
        # upstream itself misbehaved.
        "upstream_sse_malformed",
        "upstream_sse_unterminated",
        # Round 11 ``sse-delta-recursive-walk-depth-bypass`` closure:
        # the walker's depth cap tripped. Transport-class so SDKs can
        # branch on a misshapen-upstream signal without parsing the
        # audit chain, mirroring the malformed-JSON peer above.
        "upstream_delta_too_deep",
    }
)


class SignetApp:
    """Build and own the FastAPI application.

    Construct with a :class:`ServerConfig` and a :class:`Pipeline`.
    Optionally pass a custom :class:`SessionStore`; otherwise an
    in-memory store is used.

    Use :attr:`app` to mount or run the underlying FastAPI instance.
    """

    def __init__(
        self,
        *,
        config: ServerConfig,
        pipeline: Pipeline,
        session_store: SessionStore | None = None,
        receipt_signer: ReceiptSigner | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        self.config = config
        self.pipeline = pipeline
        self.session_store: SessionStore = session_store or InMemorySessionStore()
        self.metrics: Metrics = metrics or Metrics()
        # Wire the per-check duration histogram in. The Pipeline keeps
        # ``metrics`` optional so it stays usable in CLI / test contexts
        # without an HTTP server; here we attach the SignetApp's
        # registry so /metrics exposes the same observations the proxy
        # is making. Only override an unset observer so callers who
        # passed in their own remain in control.
        if getattr(self.pipeline, "_metrics", None) is None:
            self.pipeline._metrics = self.metrics

        self._keyring = self._build_keyring(config)
        self._chain = self._build_chain(config, self._keyring)
        # ``receipt_signer`` lets callers swap in their own (e.g. ed25519)
        # without touching SignetApp internals. Default is the built-in
        # HMAC-SHA256 signer over the same key as the audit chain.
        if not config.emit_receipts:
            self._receipt_signer: ReceiptSigner | None = None
        else:
            self._receipt_signer = receipt_signer or HmacReceiptSigner(self._keyring)

        # Wall-clock start time, used by /health to report uptime. Set
        # at construction so the value is meaningful even when the app
        # is mounted into a parent FastAPI without going through our
        # lifespan handler.
        import time as _time

        self._started_at = _time.time()

        self.app = FastAPI(
            title="signet",
            version=__version__,
            description="Capability-based safety gate for LLM agents.",
            lifespan=self._lifespan,
        )
        self._register_cors()
        self._register_exception_handlers()
        self._register_routes()

    def _register_cors(self) -> None:
        """Add CORSMiddleware when ``cors_allowed_origins`` is set.

        Skipped when the tuple is empty (default), so non-browser
        deployments incur zero CORS overhead.

        Spec sanity check: ``cors_allow_credentials=True`` combined
        with a wildcard origin (``"*"``) violates the CORS spec -- the
        browser will refuse the response -- so log a warning at startup
        rather than silently shipping a misconfigured gate. Operators
        should specify exact origins when credentials are required.
        """
        origins = self.config.cors_allowed_origins
        if not origins:
            return
        if self.config.cors_allow_credentials and "*" in origins:
            logger.warning(
                "cors_allow_credentials=True combined with cors_allowed_origins "
                "containing '*' violates the CORS spec; browsers will refuse "
                "the response. Specify exact origins instead, or set "
                "cors_allow_credentials=False."
            )
        from fastapi.middleware.cors import CORSMiddleware

        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=list(origins),
            allow_methods=list(self.config.cors_allowed_methods),
            allow_headers=list(self.config.cors_allowed_headers),
            allow_credentials=self.config.cors_allow_credentials,
            expose_headers=[
                self.config.receipt_header_name,
                "X-Signet-Upstream",
                "X-Signet-Upstream-Status",
            ],
        )

    @staticmethod
    def _build_keyring(config: ServerConfig) -> KeyRing:
        if config.hmac_secret is not None:
            return KeyRing(active=Key(key_id=config.hmac_key_id, secret=config.hmac_secret))
        if config.allow_ephemeral_key:
            logger.warning(
                "no HMAC secret configured; generating an ephemeral key. "
                "Audit chain will not verify across restarts. "
                "Set SIGNET_HMAC_SECRET (hex) for production."
            )
            return KeyRing(active=Key.generate(config.hmac_key_id))
        raise ValueError(
            "ServerConfig.hmac_secret is required (or set allow_ephemeral_key=True for dev)"
        )

    @staticmethod
    def _build_chain(config: ServerConfig, keyring: KeyRing) -> HmacChain | None:
        if config.audit_log_path is None:
            return None
        backend = JsonlBackend(config.audit_log_path)
        return HmacChain(backend=backend, keyring=keyring)

    @asynccontextmanager
    async def _lifespan(self, _: FastAPI) -> AsyncIterator[None]:
        """Open + close the upstream HTTP client across the app lifetime.

        Graceful shutdown: on lifespan exit (SIGTERM, etc.), wait up
        to ``ServerConfig.shutdown_grace_seconds`` for in-flight
        streams to drain before tearing down the upstream client.
        Streams that haven't completed by the deadline are abandoned;
        their audit rows are still written by the streaming generator's
        finally block.
        """
        # Idempotent: if _http already exists (e.g. TestClient triggered
        # this twice, or _ensure_http was called first), reuse it.
        self._ensure_http()
        # Track in-flight streaming requests so shutdown can drain.
        self._in_flight_streams = 0
        try:
            yield
        finally:
            grace = self.config.shutdown_grace_seconds
            if grace > 0 and self._in_flight_streams > 0:
                logger.info(
                    "shutdown: waiting up to %.1fs for %d in-flight streams to drain",
                    grace,
                    self._in_flight_streams,
                )
                import asyncio
                import time as _time

                deadline = _time.monotonic() + grace
                while self._in_flight_streams > 0 and _time.monotonic() < deadline:
                    await asyncio.sleep(0.1)
                if self._in_flight_streams > 0:
                    logger.warning(
                        "shutdown: %d streams still in flight after grace period; abandoning",
                        self._in_flight_streams,
                    )
            await self._http.aclose()
            del self._http

    def _ensure_http(self) -> httpx.AsyncClient:
        """Lazily create the upstream HTTP client. Used inside handlers so
        TestClient doesn't have to drive the lifespan to get a working app
        (FastAPI's TestClient supports lifespan but not every embedding
        does).

        Round 17 ``httpx-trust-env-allows-env-mitm`` (F-R17-2) closure:
        construct the upstream client with ``trust_env=False`` and an
        explicit ``verify=True``. The httpx default ``trust_env=True``
        silently honors process-environment knobs at request time
        (``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``ALL_PROXY`` / ``NO_PROXY``
        and the CA-bundle overrides ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``
        / ``CURL_CA_BUNDLE`` / ``REQUESTS_CA_BUNDLE``). For a gateway
        whose purpose is to mediate trust between caller and upstream,
        the upstream-side TLS / proxy posture must be pinned by config,
        not by env -- a shared host, a CI container with stale env, or
        a supply-chain compromise that lands a ``HTTPS_PROXY`` in the
        unit-file environment turns into a silent MITM of every
        upstream call with no audit-row signal (TLS still appears
        valid because the attacker's CA is trusted via the env-supplied
        bundle).

        TODO(R17+): if operators legitimately need an explicit
        upstream proxy, add a ``ServerConfig.upstream_proxy_url`` field
        and pass via the ``proxies=`` parameter (with matching audit-
        row attribution so operators see "upstream proxy in use"
        rather than discovering it via tcpdump). Reading from env is
        deliberately not supported.

        Round 17 ``httpx-pool-limits-not-tunable`` (F-R17-3) closure:
        the upstream client used httpx's default connection-pool caps
        (``max_connections=100``, ``max_keepalive_connections=20``).
        Under burst load (many concurrent SSE streams) those defaults
        silently queue new requests with no operator-tunable knob; add
        :attr:`ServerConfig.upstream_pool_max_connections` and
        :attr:`ServerConfig.upstream_pool_max_keepalive_connections` so
        deployments can raise the cap for high-fanout traffic or lower
        it on constrained hosts.

        F2 (event-loop-rebind): the cache below previously keyed on
        ``is not None`` alone, so a client built on one event loop was
        reused on the next. ``httpx.AsyncClient`` binds its connection
        pool to the loop that created it; reusing it elsewhere raises
        ``RuntimeError: Event loop is closed``, which ``_forward_unary``
        catches and reports as a 502 ``upstream_exception``.

        That contradicted this method's whole reason for existing. The
        lazy path is documented as the way an embedder gets a working
        app *without* driving the lifespan -- but Starlette's
        ``TestClient``, used outside a ``with`` block, runs each request
        in its own short-lived loop. The result was a perfectly
        alternating 200 / 502 / 200 / 502: each 502 discarded the dead
        client, each 200 re-poisoned the cache for the next request.
        Under uvicorn there is exactly one long-lived loop, so
        production never saw it -- which is precisely why it survived.

        The fix records the creating loop alongside the client and
        rebuilds when the running loop differs or the client has been
        closed. The stale client is dropped rather than awaited closed:
        its loop is already gone, so ``aclose()`` cannot run on it.
        """
        import asyncio

        try:
            current_loop: object | None = asyncio.get_running_loop()
        except RuntimeError:  # called outside async context
            current_loop = None

        existing: httpx.AsyncClient | None = getattr(self, "_http", None)
        if (
            existing is not None
            and not existing.is_closed
            and getattr(self, "_http_loop", None) is current_loop
        ):
            return existing

        if existing is not None:
            # Bound to a dead loop: unusable and un-closeable. Drop the
            # reference and let GC take it.
            logger.debug("rebuilding upstream http client (event loop changed or client closed)")

        timeout = httpx.Timeout(self.config.request_timeout_s, connect=10.0)
        limits = httpx.Limits(
            max_connections=self.config.upstream_pool_max_connections,
            max_keepalive_connections=(self.config.upstream_pool_max_keepalive_connections),
        )
        client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            # F-R17-2: pin upstream trust posture to config, not env.
            trust_env=False,
            # F-R17-2: explicit (defaults to True today) so a future
            # httpx default flip cannot silently disable verification.
            verify=True,
        )
        self._http = client
        # F2: remember the loop this pool is bound to so the cache check
        # above can detect a rebind rather than handing back a dead client.
        self._http_loop = current_loop
        return client

    def _register_exception_handlers(self) -> None:
        """Wire signet-shaped exception handlers (M8, L5).

        Pre-fix: a wrong-method request could land in any of three
        bodies depending on which Starlette path it took: the catch-all
        ``unsupported_v1`` 404 ``{"error": "endpoint not implemented..."}``
        for GET on registered POST endpoints; an empty 405 body for
        HEAD; the Starlette default ``{"detail": "Method Not Allowed"}``
        for OPTIONS. Three different shapes for the same class of
        client error is poor UX.

        Post-fix: register a single 405 handler that emits a stable
        ``{"error": "method not allowed", "endpoint": "<path>",
        "allowed_methods": [...]}`` body with the ``Allow`` header set
        from the ``HTTPException`` instance when present. The catch-all
        ``unsupported_v1`` keeps its 404 body for genuinely unimplemented
        endpoints (``/v1/audio/*``, ``/v1/images/*``).

        Round 7 ``get-on-v1-anything-returns-misleading-405`` closure:
        when the 405 fires on an unregistered ``/v1/<path>`` (anything
        other than the three gated endpoints), substitute the
        ``unsupported_v1`` 404 body so GET and POST return the same
        shape on the same path. The historical 405 shape still fires
        for wrong-method requests on registered endpoints, where it is
        genuinely correct.
        """
        from fastapi import HTTPException
        from starlette.exceptions import HTTPException as StarletteHTTPException

        async def _method_not_allowed(
            request: Request, exc: HTTPException | StarletteHTTPException
        ) -> Response:
            path = request.url.path
            # Round 7: if this 405 is for an unregistered ``/v1/*`` path,
            # the only ``allowed_methods`` Starlette can advertise is
            # ``POST`` (from the catch-all route) -- but POST to that
            # same path returns 404 "endpoint not implemented". Avoid
            # the misleading 405 by substituting the catch-all 404 body
            # whenever the path is not one of the registered endpoints.
            if path.startswith("/v1/") and path not in _REGISTERED_V1_PATHS:
                return JSONResponse(
                    status_code=404,
                    content=_unsupported_v1_body(path),
                )
            allow_header = exc.headers.get("Allow") if exc.headers else None
            allowed = (
                [m.strip() for m in allow_header.split(",") if m.strip()] if allow_header else []
            )
            body: dict[str, Any] = {
                "error": "method not allowed",
                "endpoint": path,
                "allowed_methods": allowed,
            }
            headers = {"Allow": allow_header} if allow_header else {}
            # Round 13 INFO note: 405 ``method not allowed`` is a
            # framework-routing 4xx, not a signet preflight refusal --
            # no audit row is written, no body parse happened. Pre-R12
            # preflight refusals carry ``X-Signet-Upstream`` so callers
            # can tell signet-refused from upstream-refused responses;
            # this 405 deliberately omits the header because the failure
            # happens before signet's pipeline (and even before
            # signet's routing) gets involved. Operators tailing for
            # ``X-Signet-Upstream`` to confirm "request hit signet"
            # will get false negatives on genuinely-wrong-method
            # requests; this is by design.
            return JSONResponse(status_code=405, content=body, headers=headers)

        # Starlette and FastAPI both raise HTTPException(405) for
        # method-mismatch routing. Install a handler keyed on the
        # status code so any future internal code path that raises 405
        # also gets the unified shape.
        # mypy: FastAPI's ``add_exception_handler`` is typed for the
        # ``Callable[[Request, Exception], Response]`` shape but accepts
        # the narrower ``HTTPException`` handler shape at runtime
        # (Starlette routes the actual exception type to the matching
        # handler). Suppress the false-positive arg-type error.
        self.app.add_exception_handler(405, _method_not_allowed)  # type: ignore[arg-type]

    def _register_routes(self) -> None:
        async def _health_payload() -> dict[str, Any]:
            """Build the /health body. Lightweight, no I/O."""
            import time as _time

            uptime = max(0.0, _time.time() - self._started_at)
            payload: dict[str, Any] = {
                "status": "ok",
                "service": "signet",
                "version": __version__,
                "uptime_seconds": round(uptime, 3),
                "pipeline_check_count": len(self.pipeline.checks),
                # Shadow flag is always emitted (True or False) so
                # operators tail /health and confirm at-a-glance whether
                # the gate is enforcing or piloting. Three-state
                # disambiguation isn't needed here: shadow is a boolean
                # config knob, not a runtime-derived value.
                "shadow": bool(self.config.shadow),
            }
            # Audit-chain head: last 8 hex of the most recent entry's
            # HMAC, so monitoring can detect "alive but not writing"
            # without dumping the secret. The field has three distinct
            # states so monitors can disambiguate operator intent from
            # transient runtime state:
            #
            # * ``"disabled"`` -- no chain configured (``audit_log_path``
            #   was not set). Operator chose to run without an audit
            #   chain; not an alert condition.
            # * ``None`` -- chain is configured but currently empty. May
            #   be a startup race (no requests yet) or a failed write;
            #   monitors can flag prolonged ``None`` as suspect.
            # * ``"<8-hex-tail>"`` -- chain has at least one entry. Tail
            #   advances as the chain grows; a stalled tail under load
            #   means the chain stopped writing.
            if self._chain is None:
                payload["audit_chain_head_hmac"] = "disabled"
            else:
                head = self._chain._read_prev_hmac()
                payload["audit_chain_head_hmac"] = head[-8:] if head else None
            return payload

        @self.app.get("/health")
        async def health() -> dict[str, Any]:
            """Liveness + lightweight operational metadata.

            See module docstring for the full payload shape. Always
            returns 200; kubernetes will restart the pod if this stops
            answering at all.
            """
            return await _health_payload()

        @self.app.get("/healthz")
        async def healthz() -> dict[str, Any]:
            """Alias of ``/health`` matching the k8s/cloud-native idiom."""
            return await _health_payload()

        @self.app.get("/readyz")
        async def readyz() -> Response:
            """Readiness probe: probes the configured upstream.

            Returns 200 when the upstream answers within 1s, 503 with a
            structured body otherwise. k8s should wire this to the
            readiness probe so traffic is shed when the upstream is
            unreachable but the pod itself is healthy. Distinct from
            ``/health`` so a flaky upstream doesn't trigger a liveness
            restart loop.
            """
            client = self._ensure_http()
            url = self.config.upstream_url.rstrip("/") + "/models"
            try:
                resp = await client.get(url, timeout=1.0)
            except httpx.HTTPError as exc:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "not_ready",
                        "reason": f"upstream unreachable: {type(exc).__name__}",
                        "upstream": self.config.upstream_label or self.config.upstream_url,
                    },
                )
            if resp.status_code >= 500:
                return JSONResponse(
                    status_code=503,
                    content={
                        "status": "not_ready",
                        "reason": f"upstream returned {resp.status_code}",
                        "upstream": self.config.upstream_label or self.config.upstream_url,
                        "upstream_status": resp.status_code,
                    },
                )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ready",
                    "upstream_status": resp.status_code,
                },
            )

        @self.app.get("/version")
        async def version() -> dict[str, str]:
            return {"version": __version__, "service": "signet"}

        @self.app.get("/metrics")
        async def metrics() -> Response:
            """Prometheus exposition-format counters.

            See :mod:`signet.server.metrics` for the counter set.
            Output is plain text; scrape with the standard Prometheus
            scrape config or any Prometheus-compatible collector
            (Grafana Agent, VictoriaMetrics, OpenTelemetry collector
            with the prometheus receiver, etc.).
            """
            return Response(
                content=self.metrics.render_prometheus(),
                media_type="text/plain; version=0.0.4; charset=utf-8",
            )

        # Round 7 ``unsupported-v1-trailing-slash-confusion`` closure:
        # register the canonical path AND its trailing-slash alias so a
        # caller appending one slash to ``/v1/chat/completions`` does
        # NOT fall through to the catch-all 404. OpenAI normalizes
        # trailing slashes; signet now does too.
        @self.app.post("/v1/chat/completions")
        @self.app.post("/v1/chat/completions/", include_in_schema=False)
        async def chat_completions(request: Request) -> Response:
            return await self._handle_chat(request)

        @self.app.post("/v1/completions")
        @self.app.post("/v1/completions/", include_in_schema=False)
        async def completions(request: Request) -> Response:
            return await self._handle_completions(request)

        @self.app.post("/v1/embeddings")
        @self.app.post("/v1/embeddings/", include_in_schema=False)
        async def embeddings(request: Request) -> Response:
            return await self._handle_embeddings(request)

        # F5: GET /v1/models passthrough.
        #
        # Every OpenAI-compatible client calls this to populate a model
        # picker. Returning 404 "endpoint not implemented" does not degrade
        # gracefully -- it makes the client look broken. Observed with
        # RigRun: chat worked perfectly through the gate while the model
        # list stayed empty, because its backend does
        # GET {base}/v1/models and got a signet 404. Aider, Goose, Cline
        # and OpenHands all probe the same endpoint.
        #
        # This is metadata, not inference: no request body, no prompt, no
        # tool call, nothing for ADMISSION/INSPECTION/COMMITMENT to inspect.
        # Running the content pipeline over an empty body would be
        # theatre. It is proxied and recorded, so the audit chain still
        # shows who enumerated the models and when.
        @self.app.get("/v1/models")
        @self.app.get("/v1/models/", include_in_schema=False)
        async def list_models(request: Request) -> Response:
            return await self._handle_list_models(request)

        # WebSocket pass-through for the OpenAI realtime API. ADMISSION
        # runs once at connect time. COMMITMENT runs on every function-
        # call event during the session. RECORD writes session-start +
        # periodic flush + session-end audit rows. INSPECTION runs on
        # text chunks; audio frames pass through with metadata-only
        # audit rows (no transcription in 0.1.6). See
        # :mod:`signet.server.realtime` and ``docs/realtime.md`` for
        # the full state machine and wire contract.
        if self.config.realtime_enabled:

            @self.app.websocket("/v1/realtime")
            async def realtime_websocket(websocket: WebSocket) -> None:
                await self._handle_realtime(websocket)
        else:
            # R3: when the realtime endpoint is disabled, register an
            # explicit stub handler that accepts the WebSocket and
            # immediately closes with code 1011 + a human-readable
            # reason. Without this, connecting clients see a generic
            # ``WebSocketDisconnect`` with empty message -- they cannot
            # distinguish "endpoint disabled in config" from "endpoint
            # not registered" or "transient network error". The 1011
            # close-code is RFC 6455 internal-error: a stable signal
            # that the server is up but refusing this specific
            # endpoint by configuration.

            @self.app.websocket("/v1/realtime")
            async def realtime_disabled(websocket: WebSocket) -> None:
                await websocket.accept()
                await websocket.close(
                    code=1011,
                    reason="realtime endpoint disabled in config",
                )

        # Explicit refusal for OpenAI endpoints we do NOT yet gate.
        # /v1/audio/* and /v1/images/* are deferred because their
        # request shapes (binary uploads, multi-part forms) don't fit
        # the JSON-body assumptions baked into the pipeline's check
        # surface. Adding them is roadmap for v0.2 and they will need
        # their own check protocols (vision-aware checks, audio
        # transcript checks, etc.).
        #
        # M8: catch-all only handles POST. GET/PUT/DELETE/PATCH/HEAD/
        # OPTIONS on a *registered* POST endpoint hit the framework's
        # 405 routing instead, where ``_register_exception_handlers``
        # gives them the unified ``method not allowed`` shape. This
        # avoids three different bodies for the same client error
        # class (the pre-fix path returned a 404 catch-all body for GET
        # on POST endpoints, which made the wrong-method failure mode
        # indistinguishable from the unimplemented-endpoint failure
        # mode).
        @self.app.api_route(
            "/v1/{path:path}",
            methods=["POST"],
        )
        async def unsupported_v1(path: str) -> Response:
            # Round 13 INFO note: this is a framework-routing 404, not
            # a signet preflight refusal -- like the 405 handler in
            # ``_register_exception_handlers``, this fires before
            # signet's pipeline ever sees the request, so no audit row
            # is written and ``X-Signet-Upstream`` is intentionally
            # omitted. Pre-R12 preflight refusals (400 / 413 / 403 /
            # 429 / 502) carry the attribution header so callers can
            # tell signet-refused from upstream-refused responses; an
            # unimplemented-endpoint 404 isn't a refusal of a valid
            # request and is treated as routing, not preflight.
            return JSONResponse(
                status_code=404,
                content=_unsupported_v1_body(f"/v1/{path}"),
            )

    async def _admit(self, request: Request, *, path: str) -> Response | RequestContext:
        """Shared body-read + JSON-parse + admission-pipeline preamble.

        Returns either a Response (caller should return immediately
        because admission refused/escalated/errored) or the populated
        RequestContext to proceed with forwarding.

        Shadow-mode boundary: when ``self.config.shadow`` is True, a
        non-allow ADMISSION result does NOT short-circuit to
        ``_refusal``/``_escalation``. Instead the audit row is still
        written (with ``metadata.shadow=True``), the
        ``signet_shadow_would_have_blocked_total`` counter increments,
        a set of ``X-Signet-Shadow-*`` headers is stashed on
        ``ctx.scratch["_shadow_headers"]``, and the request continues
        to the upstream as if it had been allowed. The forward path
        merges those headers into the eventual response. The audit
        chain remains the source of truth for what the gate would
        have done; shadow mode only neutralizes the response layer.
        Use this to pilot signet against production traffic before
        flipping enforcement on.
        """
        # Build the headers / client_ip / session_id once; pre-pipeline
        # refusals (including the 413 ``_BodyTooLarge`` path below) need
        # them to write a synthetic audit row even though the body
        # never parsed into a usable shape.
        pre_headers = dict(request.headers.items())
        pre_client_ip = request.client.host if request.client else None
        pre_session_id_raw = get_header_ci(pre_headers, SESSION_HEADER) or get_header_ci(
            pre_headers, SESSION_HEADER.lower()
        )
        pre_session_id = pre_session_id_raw.strip() if pre_session_id_raw else None
        if not pre_session_id:
            pre_session_id = None

        try:
            raw = await self._read_capped_body(request)
        except _BodyTooLarge as exc:
            # Round 9 ``413-oversize-body-skips-audit-and-correlation_id``
            # closure: pre-fix the 413 path returned a bare body with no
            # audit row, no ``correlation_id``, and no
            # ``X-Signet-Upstream`` attribution header — breaking the
            # "every refused request leaves an audit row" invariant
            # that every other preflight refusal honors. Route through
            # the shared preflight helpers so the wire shape matches.
            # The body fingerprint is omitted (we never finished
            # reading the bytes); ``bytes_seen`` in metadata records
            # how far the reader got before tripping the cap.
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                # Don't index the LRU under the session-ID for a 413
                # — the body was never parsed, owner is unresolved,
                # and storing a session for a refused request just
                # leaks LRU slots.
                session_id=None,
                path=path,
                # Fingerprint unavailable: we never read the full
                # body. Empty string matches the empty-body preflight
                # shape so audit consumers can branch on
                # ``_refusal_kind`` rather than fingerprint shape.
                fingerprint="",
                reason=f"request body exceeds {exc.limit} bytes",
                refusal_kind="body_too_large",
                extra_metadata={
                    "limit_bytes": exc.limit,
                    "bytes_seen": exc.bytes_seen,
                },
            )
            return self._preflight_response(
                status_code=413,
                error="body_too_large",
                entry=entry,
                verbose_extras={
                    "limit_bytes": exc.limit,
                    "bytes_seen": exc.bytes_seen,
                    "description": "request body exceeds max-bytes",
                },
            )
        pre_fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest() if raw else ""

        # Round 7: cap the session-ID length + restrict to a printable
        # token charset BEFORE anything else touches ``pre_session_id``.
        # An oversize ID would otherwise be stored in the LRU session
        # store (10 GB exhaustion risk); a control-char-laced ID would
        # otherwise be persisted verbatim into operator log tails. Both
        # are refused 400 with a preflight audit row so the
        # "every refused request leaves an audit row" invariant holds.
        if pre_session_id is not None:
            if len(pre_session_id.encode("utf-8")) > _MAX_SESSION_ID_BYTES:
                entry = self._record_preflight_refusal(
                    request=request,
                    headers=pre_headers,
                    client_ip=pre_client_ip,
                    # Don't index the LRU under the offending ID -- the
                    # whole point of the refusal is to keep oversize
                    # values out of the store.
                    session_id=None,
                    path=path,
                    fingerprint=pre_fingerprint,
                    reason=(f"X-Signet-Session header exceeds {_MAX_SESSION_ID_BYTES} bytes"),
                    refusal_kind="session_id_too_long",
                    extra_metadata={
                        "session_id_bytes": len(pre_session_id.encode("utf-8")),
                        "limit_bytes": _MAX_SESSION_ID_BYTES,
                    },
                )
                return self._preflight_response(
                    status_code=400,
                    error="session_id_too_long",
                    entry=entry,
                    verbose_extras={
                        "limit_bytes": _MAX_SESSION_ID_BYTES,
                        "expected": (
                            "X-Signet-Session must be a printable token "
                            "no longer than "
                            f"{_MAX_SESSION_ID_BYTES} bytes"
                        ),
                    },
                )
            if not _SESSION_ID_RE.match(pre_session_id):
                entry = self._record_preflight_refusal(
                    request=request,
                    headers=pre_headers,
                    client_ip=pre_client_ip,
                    session_id=None,
                    path=path,
                    fingerprint=pre_fingerprint,
                    reason=("X-Signet-Session contains characters outside [A-Za-z0-9_.:-]"),
                    refusal_kind="session_id_invalid_charset",
                    # Don't echo the offending value (it may contain NULs
                    # / control characters); the kind discriminator is
                    # enough for operators to triage from the audit row.
                    extra_metadata={},
                )
                return self._preflight_response(
                    status_code=400,
                    error="session_id_invalid_charset",
                    entry=entry,
                    verbose_extras={
                        "expected": ("X-Signet-Session must match [A-Za-z0-9_.:-]+"),
                    },
                )

        # Round 13 ``forwarded-header-crlf-injection`` closure: validate
        # the values of every header in the forward-allowlist BEFORE the
        # upstream HTTP client ever sees them. Pre-fix
        # :meth:`_upstream_headers` copied ``Authorization`` /
        # ``OpenAI-Beta`` / ``OpenAI-Organization`` from the inbound
        # request verbatim; a client sending
        # ``Authorization: Bearer xxx\r\nX-Injected: yes`` produced a
        # 502 ``upstream_protocol_violation`` at h11 wire-send, blaming
        # the upstream for a client-side protocol violation. Reject at
        # admit time with a 400 ``header_invalid_charset`` + audit row
        # so the failure mode is attributed to the client and dashboards
        # alerting on upstream-failure-rate do not fire on hostile input.
        # ``extra_forward_headers`` is the explicit allowlist of headers
        # signet will forward (defaults to ``Authorization``,
        # ``OpenAI-Beta``, ``OpenAI-Organization``); only those are
        # validated, and only when present in the inbound request.
        for fwd_name in self.config.extra_forward_headers:
            fwd_value = pre_headers.get(fwd_name) or pre_headers.get(fwd_name.lower())
            if fwd_value is None:
                continue
            if not _header_value_is_safe(fwd_value):
                entry = self._record_preflight_refusal(
                    request=request,
                    headers=pre_headers,
                    client_ip=pre_client_ip,
                    session_id=pre_session_id,
                    path=path,
                    fingerprint=pre_fingerprint,
                    reason=(
                        f"forwarded header {fwd_name!r} contains "
                        f"non-printable / control bytes; rejected "
                        f"before upstream forwarding"
                    ),
                    refusal_kind="header_invalid_charset",
                    # Don't echo the offending value -- it may contain
                    # NULs / newlines / CR that would themselves smuggle
                    # into operator log tails. The header NAME is enough
                    # for operators to triage from the audit row.
                    extra_metadata={"header_name": fwd_name},
                )
                return self._preflight_response(
                    status_code=400,
                    error="header_invalid_charset",
                    entry=entry,
                    verbose_extras={
                        "header_name": fwd_name,
                        "description": (
                            "forwarded header value contains non-printable "
                            "or control bytes (CR/LF/NUL) that would be "
                            "rejected by the upstream HTTP/1.1 parser"
                        ),
                        "expected": (
                            "header value with only printable characters (0x20-0x7E) and tab (0x09)"
                        ),
                    },
                )

        if not raw:
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason="empty request body",
                refusal_kind="empty_body",
                extra_metadata={},
            )
            return self._preflight_response(
                status_code=400,
                # Round 9 ``preflight-error-label-inconsistency``
                # closure: stable snake_case token (matches
                # ``_refusal_kind`` discriminator) so SDKs can
                # branch on a closed set. Human-readable text
                # lives in ``verbose_extras.description`` so
                # verbose-mode integrators still get an
                # actionable hint.
                error="empty_body",
                entry=entry,
                verbose_extras={
                    "description": "empty request body",
                    "expected": ("JSON object with 'messages' field for chat completions"),
                },
            )

        # Pre-parse depth guard: ``json.loads`` is recursive in CPython,
        # so a JSON payload nested deeper than the interpreter's
        # recursion limit raises a bare ``RecursionError`` (not a
        # ``json.JSONDecodeError``). Pre-fix that escaped into the 500
        # path with a generic "invalid JSON body" message; operators had
        # no idea nesting depth was the cause. Pre-validate structural
        # depth here so the refusal stamps ``json_too_deeply_nested``
        # with the active ``max_depth`` for actionable feedback.
        if _exceeds_json_depth(raw):
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason=(f"request body exceeds max JSON nesting depth ({_MAX_JSON_DEPTH})"),
                refusal_kind="json_too_deeply_nested",
                extra_metadata={"max_depth": _MAX_JSON_DEPTH},
            )
            return self._preflight_response(
                status_code=400,
                error="json_too_deeply_nested",
                entry=entry,
                verbose_extras={"max_depth": _MAX_JSON_DEPTH},
            )

        try:
            body = json.loads(raw)
        except RecursionError:
            # Belt-and-suspenders: ``_exceeds_json_depth`` should have
            # caught this above, but Python's ``json.loads`` may trip
            # ``RecursionError`` on borderline inputs (interpreter
            # recursion limit < _MAX_JSON_DEPTH on tiny stacks) before
            # our structural scan would flag them. Map to the same
            # signet-shaped 400 so the wire-shape is consistent.
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason=(f"request body exceeds max JSON nesting depth ({_MAX_JSON_DEPTH})"),
                refusal_kind="json_too_deeply_nested",
                extra_metadata={"max_depth": _MAX_JSON_DEPTH},
            )
            return self._preflight_response(
                status_code=400,
                error="json_too_deeply_nested",
                entry=entry,
                verbose_extras={"max_depth": _MAX_JSON_DEPTH},
            )
        except (json.JSONDecodeError, UnicodeDecodeError, LookupError) as e:
            # Round 7 ``invalid-utf8-body-500-no-audit`` closure:
            # ``json.loads`` on bytes runs UTF-{8,16,32} detection
            # internally and raises ``UnicodeDecodeError`` on any
            # non-UTF-* high-bit byte (gzip-compressed body, latin-1,
            # raw bytes). ``LookupError`` covers unknown-encoding
            # decode failures (theoretically reachable via custom
            # codecs). Both previously escaped to a bare 500 with
            # plaintext "Internal Server Error" and NO audit row.
            # Route through the preflight path with
            # ``_refusal_kind="invalid_encoding"`` (or the existing
            # ``"json_decode_error"`` for syntactic JSON errors) so
            # the audit-chain invariant holds.
            if isinstance(e, json.JSONDecodeError):
                refusal_kind = "json_decode_error"
                reason = "invalid JSON in request body"
                description = "invalid JSON in request body"
            else:
                refusal_kind = "invalid_encoding"
                reason = f"request body could not be decoded as UTF-8: {type(e).__name__}"
                description = "request body could not be decoded as UTF-8"
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason=reason,
                refusal_kind=refusal_kind,
                extra_metadata={"_decode_error": str(e)},
            )
            return self._preflight_response(
                status_code=400,
                # Round 9 ``preflight-error-label-inconsistency``
                # closure: stable snake_case token, matches
                # ``_refusal_kind``.
                error=refusal_kind,
                entry=entry,
                verbose_extras={
                    "description": description,
                    "detail": str(e),
                },
            )
        # Top-level shape check. ``json.loads`` happily returns lists,
        # numbers, strings, booleans, and ``None`` for syntactically valid
        # but semantically wrong bodies; downstream code assumes a dict
        # (``body.get("stream", ...)`` etc.) and would 500 with an
        # AttributeError otherwise. Refuse with a structured 400 instead
        # so callers get a parseable hint and the audit chain isn't
        # blamed for a client error.
        if not isinstance(body, dict):
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason="request body is not a JSON object",
                refusal_kind="non_object_body",
                extra_metadata={"got_type": type(body).__name__},
            )
            return self._preflight_response(
                status_code=400,
                # Round 9 ``preflight-error-label-inconsistency``
                # closure: stable snake_case token.
                error="non_object_body",
                entry=entry,
                verbose_extras={
                    "description": "request body must be a JSON object",
                    "got_type": type(body).__name__,
                    "expected": ("object with 'messages' field for chat completions"),
                },
            )

        # NF2 (v0.1.7.1): Python's ``json.loads`` accepts the non-standard
        # ``NaN`` / ``Infinity`` / ``-Infinity`` literals. httpx's
        # ``encode_json`` (allow_nan=False) raises ``ValueError`` when
        # asked to re-serialize them for the upstream, which previously
        # surfaced as a misleading 502 "upstream forward failed". Catch
        # the non-finite floats here and refuse as a 400 client error
        # with a proper audit row.
        if _contains_non_finite_float(body):
            entry = self._record_preflight_refusal(
                request=request,
                headers=pre_headers,
                client_ip=pre_client_ip,
                session_id=pre_session_id,
                path=path,
                fingerprint=pre_fingerprint,
                reason="request body contains non-finite float (NaN/Infinity)",
                refusal_kind="non_finite_float",
                extra_metadata={},
            )
            return self._preflight_response(
                status_code=400,
                # Round 9 ``preflight-error-label-inconsistency``
                # closure: stable snake_case token.
                error="non_finite_float",
                entry=entry,
                verbose_extras={
                    "description": "request body contains non-finite float",
                    "expected": (
                        "all numeric values must be finite; NaN, Infinity, "
                        "and -Infinity are not valid JSON and would be "
                        "rejected by the upstream"
                    ),
                },
            )

        # Reuse the headers / client_ip / session_id resolved before the
        # body shape gate. Starlette typically lowercases header names
        # but proxies may not; ``get_header_ci`` is what
        # ``_record_preflight_refusal`` already used. Strip surrounding
        # whitespace because some HTTP clients add a trailing space when
        # composing headers; an empty post-strip value is treated as
        # no-session so the session store doesn't index a blank key.
        headers = pre_headers
        client_ip = pre_client_ip
        session_id = pre_session_id
        request_fingerprint = pre_fingerprint

        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body=body,
            path=path,
            method=request.method,
            client_ip=client_ip,
            session_id=session_id,
        )
        ctx.scratch["_request_fingerprint"] = request_fingerprint

        if session_id:
            # Round 15 ``admission-stage-exceptions-mis-attributed``
            # (F-R15-8) closure: pre-fix ``session_store.get_or_create``
            # / ``session_store.save`` exceptions (Redis network
            # failure, mis-authentication, version skew) propagated
            # out of ``_admit``, bubbled through the per-route
            # handler, and landed in the outer ``try/except`` that
            # routed through ``_outer_fallback_response`` with
            # ``check_name="pipeline.forward"`` -- the wrong stage
            # attribution for an admission-phase failure. Route
            # session-store failures through the same admission-
            # fallback path as pipeline.pre_request crashes so the
            # audit row uses ``pipeline.admission`` (the R13 split
            # between admission and forward stages was the whole
            # point of ``_admission_fallback_response``).
            try:
                session = self.session_store.get_or_create(session_id)
                session.touch()
                self.session_store.save(session)
                ctx.scratch["_session"] = session
            except Exception as exc:
                logger.exception("session_store admission failed")
                return self._admission_fallback_response(ctx, exc, check_name="pipeline.admission")

        try:
            result = await self.pipeline.pre_request(ctx)
        except Exception as exc:
            # Round 13 ``admission-pipeline-crash-leaks-classname``
            # closure: sibling miss of R12's
            # ``_outer_fallback_response`` -- pre-fix this 500 returned
            # a bare ``{"error": "...", "exception": "<ClassName>"}``
            # body, leaking the Python exception class name under
            # strict_error_redaction (the docstring promises the public
            # response does not name internals), omitting
            # ``correlation_id`` so operators could not pivot to the
            # ``_record_exception`` audit row, and omitting the
            # ``X-Signet-Upstream`` attribution header. Route through
            # :meth:`_admission_fallback_response` so the wire shape
            # matches the post-R12 outer-fallback contract.
            logger.exception("pipeline.pre_request crashed")
            return self._admission_fallback_response(ctx, exc, check_name="pipeline.admission")

        if result.is_block:
            entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
            if self.config.shadow:
                self._stash_shadow_headers(ctx, result, entry, decision="block")
                return ctx
            return self._refusal(result, entry)
        if result.is_escalate:
            entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
            if self.config.shadow:
                self._stash_shadow_headers(ctx, result, entry, decision="escalate")
                return ctx
            return self._escalation(result, entry)
        if result.is_redact:
            if self.config.shadow:
                # Shadow neutralizes redact too: body passes through
                # unmodified so behavior is genuinely unchanged. The
                # audit row already recorded what *would* have been
                # redacted (the pipeline annotates result.metadata).
                # Surface the would-be redaction via headers and the
                # shadow counter so dashboards see the volume.
                entry = self._record_decision(ctx, result=result, check_name="pipeline.admission")
                self._stash_shadow_headers(ctx, result, entry, decision="redact")
            else:
                ctx.body = self._apply_redaction(ctx.body, result.replacement_content)

        return ctx

    async def _handle_chat(self, request: Request) -> Response:
        self.metrics.inc("signet_requests_total", {"path": "/v1/chat/completions"})
        admitted = await self._admit(request, path="/v1/chat/completions")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        is_stream = bool(ctx.body.get("stream", False))
        try:
            if is_stream:
                return await self._forward_stream(ctx, "/chat/completions")
            return await self._forward_unary(ctx, "/chat/completions")
        except Exception as exc:
            logger.exception("upstream forward crashed")
            # Round 11 ``outer-fallback-leaks-exception-classname-
            # no-correlation_id-no-attribution`` closure: route
            # through ``_outer_fallback_response`` so the wire shape
            # honors ``strict_error_redaction``, the body carries the
            # ``correlation_id`` of the audit row that
            # ``_record_exception`` writes, and the
            # ``X-Signet-Upstream`` attribution header is set.
            return self._outer_fallback_response(ctx, exc, check_name="pipeline.forward")

    async def _handle_completions(self, request: Request) -> Response:
        """Legacy /v1/completions endpoint (text completion, pre-chat).

        Same pipeline shape as chat completions. The response body
        differs (``choices[].text`` instead of ``choices[].message``);
        ScopeDriftCheck and similar text-scanning checks read from
        ``ResponseContext.accumulated_text`` and work uniformly.
        """
        self.metrics.inc("signet_requests_total", {"path": "/v1/completions"})
        admitted = await self._admit(request, path="/v1/completions")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        is_stream = bool(ctx.body.get("stream", False))
        try:
            if is_stream:
                return await self._forward_stream(ctx, "/completions")
            return await self._forward_unary(
                ctx, "/completions", content_path=("choices", 0, "text")
            )
        except Exception as exc:
            logger.exception("upstream forward crashed")
            # Round 11 ``outer-fallback-leaks-exception-classname-
            # no-correlation_id-no-attribution`` closure: see the
            # matching comment in ``_handle_chat``.
            return self._outer_fallback_response(ctx, exc, check_name="pipeline.forward")

    async def _handle_realtime(self, websocket: WebSocket) -> None:
        """Drive the OpenAI realtime API WebSocket session.

        The route handler is intentionally a thin shim: the
        per-connection state machine lives in
        :class:`signet.server.realtime.RealtimeHandler` so the
        WebSocket logic does not bloat this module. The handler
        receives a back-reference to ``self`` so it can reuse the
        shared helpers (``_record_decision``, ``_stash_shadow_headers``,
        ``_record_exception``, the pipeline, the keyring) -- no
        parallel implementation, single source of truth on audit row
        shape and shadow handling.
        """
        from signet.server.realtime import RealtimeHandler

        self.metrics.inc("signet_requests_total", {"path": "/v1/realtime"})
        handler = RealtimeHandler(self, websocket)
        await handler.run()

    async def _handle_list_models(self, request: Request) -> Response:
        """GET /v1/models — read-only passthrough to the upstream (F5).

        Deliberately does NOT run the check pipeline. A model list has no
        request body: no prompt, no tools, no content. ADMISSION content
        checks would scan an empty string, and INSPECTION / COMMITMENT have
        nothing to act on. Running them would produce audit noise that
        looks like enforcement without being any.

        It IS recorded, so the chain still answers "who enumerated the
        models, and when". Upstream failures return signet-shaped 502s
        rather than leaking the upstream body, matching ``_forward_unary``.
        """
        import asyncio

        self.metrics.inc("signet_requests_total", {"path": "/v1/models"})

        # There is no RequestContext here (no _admit step, no body), so the
        # ctx-based _upstream_headers cannot be reused. Build the forward set
        # directly from the raw request, applying the same CRLF safety check
        # so this endpoint cannot become a header-injection surface.
        fwd: dict[str, str] = {}
        for h in self.config.extra_forward_headers:
            v = request.headers.get(h) or request.headers.get(h.lower())
            if v and _header_value_is_safe(v):
                fwd[h] = v

        client = self._ensure_http()
        try:
            upstream = await client.get(
                f"{self.config.upstream_url.rstrip('/')}/models",
                headers=fwd,
            )
        except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.warning("upstream /models failed: %s: %s", type(exc).__name__, exc)
            return JSONResponse(
                status_code=502,
                content={
                    "error": "upstream model list unavailable",
                    "refusal_kind": "upstream_exception",
                    "exception": type(exc).__name__,
                },
                headers=self._upstream_attribution_headers(None),
            )

        headers = self._upstream_attribution_headers(upstream.status_code)
        try:
            body = upstream.json()
        except Exception:
            return JSONResponse(
                status_code=502,
                content={
                    "error": "upstream returned a non-JSON model list",
                    "refusal_kind": "upstream_protocol_violation",
                },
                headers=headers,
            )

        return JSONResponse(status_code=upstream.status_code, content=body, headers=headers)

    async def _handle_embeddings(self, request: Request) -> Response:
        """Embeddings endpoint -- non-streaming, no INSPECTION text content.

        ADMISSION runs (owner, classification, rate limit, regex on
        input strings) and RECORD runs (token-budget reconciliation
        from upstream usage). INSPECTION-stage checks that scan
        accumulated output text are skipped -- embeddings have no text
        output to scan. Tool-call-inspector (COMMITMENT) is also
        skipped -- embeddings don't emit tool calls.
        """
        self.metrics.inc("signet_requests_total", {"path": "/v1/embeddings"})
        admitted = await self._admit(request, path="/v1/embeddings")
        if isinstance(admitted, Response):
            return admitted
        ctx = admitted

        try:
            return await self._forward_unary(
                ctx, "/embeddings", content_path=None, skip_inspection_text=True
            )
        except Exception as exc:
            logger.exception("upstream forward crashed")
            # Round 11 ``outer-fallback-leaks-exception-classname-
            # no-correlation_id-no-attribution`` closure: see the
            # matching comment in ``_handle_chat``.
            return self._outer_fallback_response(ctx, exc, check_name="pipeline.forward")

    async def _read_capped_body(self, request: Request) -> bytes:
        """Stream the request body, refusing once it exceeds the cap.

        Trusting the ``Content-Length`` header is not sufficient -- a
        chunked-transfer client can send unbounded data without a length.
        We accumulate and check after each chunk.
        """
        limit = self.config.max_request_body_bytes
        chunks: list[bytes] = []
        total = 0
        async for piece in request.stream():
            total += len(piece)
            if total > limit:
                raise _BodyTooLarge(limit, bytes_seen=total)
            chunks.append(piece)
        return b"".join(chunks)

    @staticmethod
    def _apply_redaction(body: dict[str, Any], replacement: str | None) -> dict[str, Any]:
        """Swap the last user-message text content for ``replacement``.

        Best-effort: REDACT is intended for input-side checks
        (``RegexContentCheck``) where the offending pattern lives in the
        most recent user message. If your check needs to redact in a
        different shape, return BLOCK and let the caller re-issue with
        the correction; OSS does not pretend to know your full message
        graph.

        Multimodal handling: when the last user message uses the
        OpenAI vision shape (``content`` is a list of ``{"type": ...}``
        parts), only the **text** parts are replaced. Image and audio
        parts pass through untouched -- dropping them would silently
        change request semantics far beyond what a redact decision
        promises.
        """
        if replacement is None:
            return body
        out = dict(body)
        messages = list(body.get("messages", ()))
        for i in range(len(messages) - 1, -1, -1):
            msg = messages[i]
            if not (isinstance(msg, dict) and msg.get("role") == "user"):
                continue
            new_msg = dict(msg)
            content = msg.get("content")
            if isinstance(content, str):
                new_msg["content"] = replacement
            elif isinstance(content, list):
                # Vision-style: keep non-text parts (images, audio) intact
                new_parts: list[Any] = []
                replaced_any = False
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        if not replaced_any:
                            new_parts.append({"type": "text", "text": replacement})
                            replaced_any = True
                        # Subsequent text parts are dropped -- the single
                        # replacement covers all redacted text.
                    else:
                        new_parts.append(part)
                if not replaced_any:
                    # No text parts existed; prepend the replacement so the
                    # redaction is at least represented in the message.
                    new_parts.insert(0, {"type": "text", "text": replacement})
                new_msg["content"] = new_parts
            else:
                # Unknown content shape -- replace wholesale rather than
                # leave the offending pattern in place.
                new_msg["content"] = replacement
            messages[i] = new_msg
            break
        out["messages"] = messages
        return out

    async def _forward_unary(
        self,
        ctx: RequestContext,
        upstream_path: str = "/chat/completions",
        *,
        content_path: tuple[Any, ...] | None = ("choices", 0, "message", "content"),
        skip_inspection_text: bool = False,
    ) -> Response:
        """Forward a non-streaming request to the upstream.

        ``upstream_path`` is appended to ``ServerConfig.upstream_url``.
        ``content_path`` walks the upstream response to find the text
        that RECORD-stage checks should see in
        ``ResponseContext.accumulated_text``. Default targets the
        chat-completions shape; pass ``("choices", 0, "text")`` for
        legacy /completions. Pass ``None`` (with
        ``skip_inspection_text=True``) for endpoints with no text
        output (embeddings).

        F1 (v0.1.8.1): on any upstream-side failure -- protocol error,
        connect/timeout, malformed JSON, non-JSON Content-Type, or a
        broad ``Exception`` from the http client -- the response body
        is signet-shaped (NEVER raw upstream content) and an audit row
        with ``check_name='pipeline.upstream'`` plus a
        ``_refusal_kind`` discriminator is written. This mirrors the
        streaming path's ``_emit_upstream_error_abort`` contract for
        the sync path.
        """
        import asyncio

        client = self._ensure_http()
        try:
            upstream_resp = await client.post(
                f"{self.config.upstream_url.rstrip('/')}{upstream_path}",
                json=ctx.body,
                headers=self._upstream_headers(ctx),
            )
        except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
            # Re-raise: caller disconnects / shutdown signals must
            # propagate. The outer StreamingResponse / ASGI plumbing
            # is responsible for cleanup; trying to write an audit row
            # here would race with shutdown.
            raise
        except httpx.HTTPError as exc:
            entry, body = self._record_upstream_failure(
                ctx,
                reason=f"upstream http error: {type(exc).__name__}: {exc}",
                refusal_kind="upstream_protocol_violation",
                exception=exc,
                upstream_status=None,
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(None),
            )
        except Exception as exc:
            entry, body = self._record_upstream_failure(
                ctx,
                reason=f"upstream exception: {type(exc).__name__}: {exc}",
                refusal_kind="upstream_exception",
                exception=exc,
                upstream_status=None,
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(None),
            )

        # Redirect guard: a 3xx upstream response previously passed
        # through to the client verbatim, which let the client follow
        # the Location somewhere that never re-entered signet. That is
        # a gate bypass (and an SSRF-shaped surface when the upstream
        # is hostile / misconfigured). Refuse with a structured 502
        # naming the upstream status + Location host so operators can
        # triage. Body / path / query / fragment of Location are NEVER
        # echoed -- a raw redirect URL is a PII / SSRF leak surface.
        if 300 <= upstream_resp.status_code < 400:
            try:
                location_header = upstream_resp.headers.get("location", "") or ""
            except AttributeError:  # pragma: no cover -- defensive against stubs
                location_header = ""
            location_host = _extract_redirect_host(location_header)
            _entry, body = self._record_upstream_redirect(
                ctx,
                upstream_status=upstream_resp.status_code,
                location_host=location_host,
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )

        # Content-Type guard for unary path. A non-JSON content-type
        # (HTML, plain text, octet-stream, etc.) on a JSON endpoint is
        # an upstream misconfiguration; the JSON parse below would
        # likely fail anyway, but stamping the failure mode explicitly
        # gives operators a separate ``_refusal_kind`` to alert on.
        upstream_ct_raw = ""
        try:
            upstream_ct_raw = upstream_resp.headers.get("content-type", "") or ""
        except AttributeError:  # pragma: no cover -- defensive against stubs
            upstream_ct_raw = ""
        upstream_ct = upstream_ct_raw.lower().split(";", 1)[0].strip()
        # JSON content types vary: application/json, application/vnd.openai.*+json,
        # text/json (rare). Accept "json" anywhere in the subtype as a
        # permissive match; flag everything else. Empty content-type is
        # treated as "unknown, fall through to JSON parse" to preserve
        # legacy behavior for minimal upstreams that omit the header.
        if upstream_ct and "json" not in upstream_ct:
            entry, body = self._record_upstream_failure(
                ctx,
                reason=(
                    f"upstream returned content-type {upstream_ct!r}; expected application/json"
                ),
                refusal_kind="upstream_content_type_invalid",
                exception=None,
                upstream_status=upstream_resp.status_code,
                extra_metadata={"upstream_content_type": upstream_ct},
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )

        try:
            data = upstream_resp.json()
        except json.JSONDecodeError as exc:
            # Upstream returned non-JSON on what should be a JSON
            # endpoint (HTML error page, empty body, 302 redirect HTML,
            # etc). Previously we returned ``upstream_resp.content``
            # verbatim, which leaked the upstream body to the client
            # and skipped the audit chain. F1 (v0.1.8.1) replaces that
            # behavior with a signet-shaped JSONResponse plus an audit
            # row tagged ``upstream_decode_error``.
            entry, body = self._record_upstream_failure(
                ctx,
                reason=(f"upstream returned non-JSON body: {type(exc).__name__}: {exc}"),
                refusal_kind="upstream_decode_error",
                exception=exc,
                upstream_status=upstream_resp.status_code,
                extra_metadata={"upstream_content_type": upstream_ct},
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )

        # Round 7 ``non-dict-upstream-json-crash`` closure: the JSON
        # parsed, but the top level is not an object (some
        # OpenAI-compatible gateways return a top-level array, scalar,
        # or ``null`` on auth/quota errors that the upstream layer
        # wraps). Subsequent ``data.get(...)`` calls would raise
        # ``AttributeError`` and fall through to the generic
        # ``except Exception`` in ``_handle_chat`` -- audit row gets
        # the wrong ``check_name`` and strict-mode leaks the Python
        # class name. Route through ``_record_upstream_failure`` with
        # the canonical ``upstream_protocol_violation`` discriminator
        # so dashboards filtering on ``pipeline.upstream`` see the
        # event.
        if not isinstance(data, dict):
            entry, body = self._record_upstream_failure(
                ctx,
                reason=(
                    f"upstream returned non-object JSON at top level (type={type(data).__name__})"
                ),
                refusal_kind="upstream_protocol_violation",
                exception=None,
                upstream_status=upstream_resp.status_code,
                extra_metadata={
                    "upstream_top_level_type": type(data).__name__,
                    "upstream_content_type": upstream_ct,
                },
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )

        rctx = ResponseContext(request=ctx)
        usage = data.get("usage", {})
        rctx.usage = usage if isinstance(usage, dict) else {}
        choices = data.get("choices")
        # Round 7 ``non-dict-upstream-json-crash``: when ``choices`` is
        # not a list of dicts (``{"choices": "x"}``, ``{"choices": [1]}``),
        # ``.get("finish_reason")`` on a non-dict element would raise
        # ``AttributeError``. Treat the malformed-shape case as an
        # upstream protocol violation rather than a signet crash.
        if choices is not None and not isinstance(choices, list):
            entry, body = self._record_upstream_failure(
                ctx,
                reason=(
                    f"upstream returned non-list 'choices' field (type={type(choices).__name__})"
                ),
                refusal_kind="upstream_protocol_violation",
                exception=None,
                upstream_status=upstream_resp.status_code,
                extra_metadata={
                    "upstream_choices_type": type(choices).__name__,
                },
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )
        if isinstance(choices, list) and choices and not isinstance(choices[0], dict):
            entry, body = self._record_upstream_failure(
                ctx,
                reason=(
                    f"upstream 'choices[0]' is not an object (type={type(choices[0]).__name__})"
                ),
                refusal_kind="upstream_protocol_violation",
                exception=None,
                upstream_status=upstream_resp.status_code,
                extra_metadata={
                    "upstream_choices0_type": type(choices[0]).__name__,
                },
            )
            return JSONResponse(
                status_code=502,
                content=body,
                headers=self._upstream_attribution_headers(upstream_resp.status_code),
            )
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            rctx.finish_reason = first_choice.get("finish_reason")
        else:
            rctx.finish_reason = None
        if not skip_inspection_text and content_path is not None:
            text = _walk_path(data, content_path)
            if isinstance(text, str):
                rctx.extend_text(text)
        rctx.chunk_count = 1

        # F3: COMMITMENT. Runs before RECORD (post_complete) so the
        # stage order on the HTTP path matches the documented lifecycle
        # ADMISSION -> INSPECTION -> COMMITMENT -> RECORD, and so a
        # refused tool call never reaches the RECORD checks as if it had
        # been served. A refusal here returns 403 and the upstream body
        # is discarded -- the caller never receives the tool call it
        # would have executed.
        tool_calls = self._extract_response_tool_calls(data)
        if tool_calls:
            refusal = await self._gate_tool_calls(ctx, rctx, tool_calls)
            if refusal is not None:
                return refusal

        # Round 11 ``outer-fallback-leaks-exception-classname-no-
        # correlation_id-no-attribution`` closure: wrap RECORD-stage
        # execution in try/except (the streaming twin already does
        # this at app.py:~2125). A crashing RECORD check MUST NOT
        # surface as a 502 with a Python class-name leak — the
        # upstream response is already valid and the client deserves
        # to see it. Log + audit the failure and continue;
        # ``record_results`` becomes an empty list so the per-check
        # audit loop below short-circuits. ``CancelledError`` /
        # ``KeyboardInterrupt`` / ``SystemExit`` are
        # ``BaseException`` (not ``Exception``) subclasses so they
        # propagate past this handler as required.
        try:
            record_results = await self.pipeline.post_complete(rctx)
        except Exception as exc:
            self._record_exception(ctx, exc, check_name="pipeline.record")
            logger.exception("pipeline.post_complete crashed in _forward_unary")
            record_results = []

        # Each non-allow RECORD result becomes its own audit row so the
        # specific check name and metadata survive into the chain.
        # The aggregate "request completed" row is always written so
        # consumers can pivot from request → entries via fingerprint.
        for record_result in record_results:
            if not record_result.is_allow:
                self._record_decision(
                    ctx,
                    result=record_result,
                    check_name=record_result.metadata.get("_check_name", "pipeline.record"),
                )

        entry = self._record_decision(
            ctx,
            result=None,
            check_name="pipeline.complete",
            metadata={
                "finish_reason": rctx.finish_reason,
                "tokens": rctx.usage,
                "accumulated_text_truncated": rctx.accumulated_text_truncated,
            },
        )
        headers = self._upstream_attribution_headers(upstream_resp.status_code)
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        # Merge any X-Signet-Shadow-* headers stashed by _admit (or by
        # a RECORD-stage shadow neutralization above). They describe the
        # would-be refusal so callers can see what shadow caught even
        # though the response body is the upstream's.
        shadow_headers = ctx.scratch.get("_shadow_headers")
        if shadow_headers:
            headers.update(shadow_headers)
        return JSONResponse(content=data, status_code=upstream_resp.status_code, headers=headers)

    async def _forward_stream(
        self,
        ctx: RequestContext,
        upstream_path: str = "/chat/completions",
    ) -> StreamingResponse:
        rctx = ResponseContext(request=ctx)

        async def event_stream() -> AsyncIterator[bytes]:
            # asyncio is imported lazily here so the function-scoped
            # CancelledError handler can let cancellation propagate
            # without paying a top-level import cost on a module that
            # already keeps the import lazy in :meth:`_lifespan`.
            import asyncio

            client = self._ensure_http()
            completed_normally = False
            inspection_aborted = False
            upstream_aborted = False
            # F1.5 (v0.1.8.x): ``httpx.AsyncClient.stream`` is an
            # ``@asynccontextmanager`` that issues the HTTP request
            # inside ``__aenter__``; a DNS failure, TLS handshake error,
            # ``httpx.ConnectError``, or ``RuntimeError`` from a
            # misconfigured transport raises BEFORE the body of the
            # ``async with`` runs. The outer try/except below converts
            # those init-time failures into structured abort frames +
            # ``pipeline.upstream`` audit rows, mirroring what the inner
            # handlers do for mid-stream failures.
            if not hasattr(self, "_in_flight_streams"):
                self._in_flight_streams = 0
            self._in_flight_streams += 1
            try:
                async with client.stream(
                    "POST",
                    f"{self.config.upstream_url.rstrip('/')}{upstream_path}",
                    json=ctx.body,
                    headers=self._upstream_headers(ctx),
                ) as upstream:
                    # Round 4 hunt: redirect guard. A 3xx upstream
                    # response on the streaming path previously fell
                    # through into ``aiter_bytes`` -- the redirect body
                    # (typically a short HTML or empty payload) would
                    # be inspected line-by-line and forwarded to the
                    # client unless caught by the SSE content-type guard
                    # below. Even when CT happened to catch it, the
                    # audit row would be stamped
                    # ``upstream_content_type_invalid`` rather than the
                    # operationally relevant ``upstream_redirect``.
                    # Block here so the audit row carries the right
                    # discriminator AND so a hostile upstream cannot
                    # use 302 with a Location to silently steer the
                    # client to an attacker-controlled endpoint.
                    if 300 <= upstream.status_code < 400:
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_redirect"
                        try:
                            location_header = upstream.headers.get("location", "") or ""
                        except AttributeError:  # pragma: no cover -- defensive
                            location_header = ""
                        location_host = _extract_redirect_host(location_header)
                        # Record the audit row directly so we can stamp
                        # the redirect-host metadata; the abort frame is
                        # emitted via the shared builder so the SSE wire
                        # contract matches the other upstream-failure
                        # branches.
                        entry, _body = self._record_upstream_redirect(
                            ctx,
                            upstream_status=upstream.status_code,
                            location_host=location_host,
                        )
                        for frame in self._build_abort_frames(
                            reason="upstream_redirect",
                            stage="inspection",
                            check_name=None,
                            entry=entry,
                        ):
                            yield frame
                        return

                    # Upstream-status guard: a 5xx (or any non-2xx) means
                    # the upstream is broken mid-handshake or about to
                    # ship an error body. Emit a structured abort frame
                    # so the SDK sees a parseable terminal frame rather
                    # than an opaque error body or a hung stream. We
                    # deliberately don't try to forward the upstream's
                    # error body -- different upstreams shape errors
                    # differently and a half-mixed stream is harder for
                    # SDKs to handle than a clean signet-abort.
                    if upstream.status_code >= 400:
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_error"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=upstream.status_code,
                            reason_detail=f"upstream returned {upstream.status_code}",
                            reason_token="upstream_protocol_violation",  # noqa: S106
                        ):
                            yield frame
                        return

                    # S7: content-type guard. A 200 OK with
                    # ``application/octet-stream`` (or any non-SSE
                    # content type) means the upstream is shipping
                    # something other than server-sent events through
                    # what should be a streaming endpoint. Forwarding
                    # the bytes verbatim would let upstream garbage
                    # land on the client without ever being inspected.
                    # Emit a structured abort so SDKs can react.
                    #
                    # Defensive lookup: some test stubs and minimal
                    # transports don't expose a Headers-shaped object;
                    # an absent or empty content-type is treated as
                    # "trust the upstream" (the historical behavior).
                    # Hostile bytes still get inspected line-by-line
                    # downstream -- the strict block here only fires
                    # when the upstream explicitly declared a
                    # non-SSE / non-text content type.
                    upstream_headers = getattr(upstream, "headers", None) or {}
                    try:
                        upstream_content_type = upstream_headers.get("content-type", "")
                    except AttributeError:  # pragma: no cover -- defensive
                        upstream_content_type = ""
                    upstream_content_type = (upstream_content_type or "").lower()
                    if upstream_content_type and not upstream_content_type.startswith(
                        ("text/event-stream", "text/plain")
                    ):
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_content_type_invalid"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=upstream.status_code,
                            reason_detail=(
                                f"upstream returned content-type "
                                f"{upstream_content_type!r}; expected "
                                "text/event-stream"
                            ),
                            reason_token="upstream_content_type_invalid",  # noqa: S106
                        ):
                            yield frame
                        return

                    # Round 7: per-stream SSE re-assembly so a ``data:``
                    # line split across raw byte chunks is parsed once
                    # complete instead of being silently dropped.
                    # ``ctx.scratch`` carries the buffer so the
                    # ``finally`` clause can surface
                    # ``dropped_frame_count`` in the
                    # ``pipeline.complete`` audit row.
                    sse_buf = _SSEBuffer(
                        inspect_all_lines=self.config.inspect_all_sse_lines,
                    )
                    ctx.scratch["_sse_buffer"] = sse_buf
                    try:
                        async for raw_chunk in upstream.aiter_bytes():
                            rctx.chunk_count += 1
                            # Round 7 ``sse-stream-chunk-no-size-bound``
                            # closure: a single 100-MB chunk would
                            # decode into a 100-MB Python string and
                            # explode ``splitlines()``. Cap per-chunk
                            # bytes and abort the stream cleanly when
                            # the cap trips -- a chunk this large is
                            # already a protocol violation.
                            if len(raw_chunk) > _MAX_STREAM_CHUNK_BYTES:
                                upstream_aborted = True
                                rctx.finish_reason = "upstream_protocol_violation"
                                async for frame in self._emit_upstream_error_abort(
                                    ctx,
                                    rctx,
                                    upstream_status=upstream.status_code,
                                    reason_detail=(
                                        f"upstream SSE chunk exceeds "
                                        f"{_MAX_STREAM_CHUNK_BYTES} bytes "
                                        f"(got {len(raw_chunk)})"
                                    ),
                                    reason_token="upstream_protocol_violation",  # noqa: S106
                                ):
                                    yield frame
                                return
                            # Round 7 ``sse-non-utf8-content-forwarded
                            # -unscanned`` closure: strict-decode so
                            # non-UTF-8 bytes from a hostile upstream
                            # don't get forwarded to the client while
                            # inspection sees only U+FFFD substitutes
                            # (which break the JSON parse and leave
                            # ``accumulated_text`` empty). Treat the
                            # failure as a protocol violation, write
                            # the audit row, and terminate the stream
                            # via the structured abort frame.
                            try:
                                chunk_text = raw_chunk.decode("utf-8")
                            except UnicodeDecodeError as decode_exc:
                                upstream_aborted = True
                                rctx.finish_reason = "upstream_protocol_violation"
                                async for frame in self._emit_upstream_error_abort(
                                    ctx,
                                    rctx,
                                    upstream_status=upstream.status_code,
                                    reason_detail=(
                                        f"upstream SSE chunk is not valid UTF-8: {decode_exc}"
                                    ),
                                    reason_token="upstream_protocol_violation",  # noqa: S106
                                    exception=decode_exc,
                                ):
                                    yield frame
                                return
                            # Round 7 fix: buffer the raw bytes that
                            # make up an in-flight event and ONLY yield
                            # them after inspection has run on the
                            # complete assembled event. If we yielded
                            # ``raw_chunk`` immediately, a hostile
                            # upstream that splits ``(S//NF)`` across
                            # byte chunks would still leak the marker
                            # to the client even though our buffer
                            # eventually catches it.
                            #
                            # Round 9 ``sse-cr-line-terminator-bypass``
                            # closure: the previous implementation only
                            # split on ``\n\n`` and ``\r\n\r\n`` —
                            # spec-valid ``\r\r``, ``\n\r``, ``\r\n\r``,
                            # ``\r\r\n``, ``\r\n\n``, ``\n\r\n``
                            # terminator pairs leaked. Use the
                            # :data:`_SSE_EVENT_TERMINATOR_RE` regex so
                            # the outer split matches every
                            # WHATWG-spec terminator pair. Find the
                            # LAST match in the combined buffer:
                            # everything up to and including it is
                            # "complete events"; the tail is partial
                            # and stays buffered for the next chunk.
                            pending_raw: bytes = ctx.scratch.get("_pending_raw_sse", b"")
                            combined = pending_raw + raw_chunk
                            last_term_end = -1
                            for m in _SSE_EVENT_TERMINATOR_RE.finditer(combined):
                                last_term_end = m.end()
                            if last_term_end == -1:
                                # Round 9 ``sse-pending-raw-unbounded``
                                # closure: cap the held-back buffer.
                                # An upstream that never emits a
                                # terminator would otherwise grow this
                                # without bound (500 x 500 KB observed
                                # at ~250 MB / 720 MB peak before the
                                # cap). Abort via
                                # ``upstream_sse_unterminated`` so the
                                # audit row captures the failure mode
                                # and the proxy doesn't OOM the host.
                                if len(combined) > _MAX_PENDING_RAW_SSE_BYTES:
                                    upstream_aborted = True
                                    rctx.finish_reason = "upstream_protocol_violation"
                                    # Drop the pending buffer before the
                                    # abort frame fires so the
                                    # offending bytes never reach the
                                    # client.
                                    ctx.scratch["_pending_raw_sse"] = b""
                                    async for frame in self._emit_upstream_error_abort(
                                        ctx,
                                        rctx,
                                        upstream_status=upstream.status_code,
                                        reason_detail=(
                                            f"upstream SSE pending-raw exceeds "
                                            f"{_MAX_PENDING_RAW_SSE_BYTES} bytes "
                                            f"without terminator (got "
                                            f"{len(combined)})"
                                        ),
                                        reason_token="upstream_sse_unterminated",  # noqa: S106
                                    ):
                                        yield frame
                                    return
                                # No complete events yet. Keep
                                # accumulating. Round 9: still feed the
                                # buffer so its ``splitlines()``-based
                                # line re-assembly can recognize
                                # spec-valid ``\r``-only line
                                # terminators that the outer regex
                                # already saw, AND surface any text
                                # the buffer extracted into INSPECTION
                                # accumulated_text — pre-fix the
                                # return value of ``feed()`` was
                                # silently discarded here, so any
                                # event the buffer fully assembled (a
                                # complete ``data: ... \n\n`` chunk
                                # arriving INSIDE this raw chunk while
                                # the outer regex required two
                                # terminators in the *combined* buffer
                                # to match) escaped inspection.
                                ctx.scratch["_pending_raw_sse"] = combined
                                extracted = sse_buf.feed(chunk_text)
                                if extracted:
                                    rctx.extend_text(extracted)
                                if sse_buf.malformed_event_seen:
                                    # Treat as upstream protocol
                                    # violation: the inner buffer
                                    # parsed an event whose JSON
                                    # payload was malformed. The raw
                                    # bytes are still pending and
                                    # would otherwise leak when the
                                    # next terminator arrives; abort
                                    # now and drop them.
                                    upstream_aborted = True
                                    rctx.finish_reason = "upstream_protocol_violation"
                                    ctx.scratch["_pending_raw_sse"] = b""
                                    abort_reason, abort_detail = _malformed_abort_tokens(sse_buf)
                                    async for frame in self._emit_upstream_error_abort(
                                        ctx,
                                        rctx,
                                        upstream_status=upstream.status_code,
                                        reason_detail=abort_detail,
                                        reason_token=abort_reason,
                                    ):
                                        yield frame
                                    return
                                continue
                            complete_bytes = combined[:last_term_end]
                            ctx.scratch["_pending_raw_sse"] = combined[last_term_end:]
                            # Feed the chunk's text to the buffer (the
                            # buffer's own line re-assembly is unchanged
                            # and re-uses ``chunk_text``); the buffer's
                            # internal state may now hold the partial
                            # tail line for the next chunk.
                            rctx.extend_text(sse_buf.feed(chunk_text))
                            # Round 9 ``sse-unparseable-json-event-
                            # leaks-raw-bytes`` closure: if the buffer
                            # flagged a malformed event payload, the
                            # raw bytes that make up that event have
                            # already been collected into
                            # ``complete_bytes`` and would be forwarded
                            # to the client below. Abort instead so
                            # the smuggle pattern (valid ``data:``
                            # line carrying a marker, followed by a
                            # garbage ``data:`` line that breaks JSON
                            # parse) does not reach the client.
                            if sse_buf.malformed_event_seen:
                                upstream_aborted = True
                                rctx.finish_reason = "upstream_protocol_violation"
                                ctx.scratch["_pending_raw_sse"] = b""
                                abort_reason, abort_detail = _malformed_abort_tokens(sse_buf)
                                async for frame in self._emit_upstream_error_abort(
                                    ctx,
                                    rctx,
                                    upstream_status=upstream.status_code,
                                    reason_detail=abort_detail,
                                    reason_token=abort_reason,
                                ):
                                    yield frame
                                return

                            inspection = await self.pipeline.inspect_response_chunk(
                                rctx, chunk_text
                            )
                            if not inspection.is_allow:
                                if self.config.shadow:
                                    # Shadow mode: do NOT abort. Record the
                                    # would-have-blocked decision in the
                                    # audit chain (with shadow=True) and let
                                    # the chunk pass through. Streaming
                                    # responses cannot retroactively add
                                    # response headers (they were sent at
                                    # handshake), so the per-block
                                    # X-Signet-Shadow-* headers cannot reach
                                    # the caller for INSPECTION-stage
                                    # decisions; the audit chain remains the
                                    # source of truth and operators correlate
                                    # via the timestamps + request
                                    # fingerprint. The handshake-time header
                                    # ``X-Signet-Shadow-Inspection-Active:
                                    # 1`` tells callers shadow inspection is
                                    # running so they should consult the
                                    # chain for any neutralized decisions.
                                    self._record_decision(
                                        ctx,
                                        result=inspection,
                                        check_name="pipeline.inspection",
                                    )
                                    ctx.scratch["_shadow_inspection_count"] = (
                                        ctx.scratch.get("_shadow_inspection_count", 0) + 1
                                    )
                                    yield complete_bytes
                                    continue
                                # Non-shadow INSPECTION block: do NOT
                                # forward the offending event bytes.
                                # ``complete_bytes`` (the events whose
                                # assembled content tripped the check)
                                # are dropped; only the abort frame is
                                # emitted. The pending-raw tail (a
                                # partial event still in transit) is
                                # also dropped.
                                ctx.scratch["_pending_raw_sse"] = b""
                                rctx.finish_reason = "abort"
                                entry = self._record_decision(
                                    ctx,
                                    result=inspection,
                                    check_name="pipeline.inspection",
                                    metadata={
                                        # chunks_delivered = how many
                                        # passed through to the client
                                        # before this one. The blocking
                                        # chunk itself is counted in
                                        # rctx.chunk_count (we bumped
                                        # before inspecting) but is NOT
                                        # delivered.
                                        "chunks_delivered": rctx.chunk_count - 1,
                                        "chunk_count_at_abort": rctx.chunk_count,
                                        "abort_stage": "inspection",
                                    },
                                )
                                for frame in self._build_abort_frames(
                                    reason=inspection.reason,
                                    stage="inspection",
                                    check_name=inspection.metadata.get("_check_name"),
                                    entry=entry,
                                ):
                                    yield frame
                                inspection_aborted = True
                                return

                            # F3: streaming COMMITMENT. Runs after
                            # INSPECTION and BEFORE the chunk is yielded,
                            # so a refused tool call never reaches the
                            # client. ``pending_tool_calls`` is drained
                            # here; the buffer queues an index the moment
                            # its ``function.name`` becomes known, which
                            # is typically the same chunk that carries it.
                            if sse_buf.pending_tool_calls:
                                pending = list(sse_buf.pending_tool_calls)
                                sse_buf.pending_tool_calls.clear()
                                commitment_calls: list[tuple[str, dict[str, Any]]] = []
                                for idx in pending:
                                    slot = sse_buf.tool_calls.get(idx)
                                    if not slot or not slot.get("name"):
                                        continue
                                    # Arguments are still streaming at this
                                    # point, so pass what has accumulated so
                                    # far. Tier gating is name-based; an
                                    # argument-sensitive check sees a partial
                                    # payload and should treat it as such.
                                    commitment_calls.append(
                                        (
                                            slot["name"],
                                            {"_partial_arguments": slot.get("arguments", "")},
                                        )
                                    )

                                for tool_name, arguments in commitment_calls:
                                    tcc = ToolCallContext(
                                        request=ctx,
                                        response=rctx,
                                        tool_name=tool_name,
                                        arguments=arguments,
                                        tool_metadata={"streaming": True},
                                    )
                                    try:
                                        commitment = await self.pipeline.inspect_tool_call(tcc)
                                    except Exception as exc:
                                        self._record_exception(
                                            ctx, exc, check_name="pipeline.commitment"
                                        )
                                        logger.exception("streaming COMMITMENT pipeline crashed")
                                        if self.config.shadow:
                                            continue
                                        from signet.core.check import CheckResult

                                        commitment = CheckResult.block(
                                            f"COMMITMENT pipeline raised {type(exc).__name__}",
                                            _check_name="pipeline.commitment",
                                            tool_name=tool_name,
                                        )

                                    if commitment.is_allow:
                                        self._record_decision(
                                            ctx,
                                            result=commitment,
                                            check_name="pipeline.commitment",
                                            metadata={"tool_name": tool_name},
                                        )
                                        continue

                                    check_name = str(
                                        commitment.metadata.get(
                                            "_check_name", "pipeline.commitment"
                                        )
                                    )
                                    entry = self._record_decision(
                                        ctx,
                                        result=commitment,
                                        check_name=check_name,
                                        metadata={
                                            "tool_name": tool_name,
                                            "chunks_delivered": rctx.chunk_count - 1,
                                            "abort_stage": "commitment",
                                        },
                                    )
                                    if self.config.shadow:
                                        continue

                                    ctx.scratch["_pending_raw_sse"] = b""
                                    rctx.finish_reason = "abort"
                                    for frame in self._build_abort_frames(
                                        reason=commitment.reason,
                                        stage="commitment",
                                        check_name=commitment.metadata.get("_check_name"),
                                        entry=entry,
                                    ):
                                        yield frame
                                    inspection_aborted = True
                                    return

                            yield complete_bytes
                        # End-of-stream finalize: flush any tail event
                        # whose terminating blank line never arrived
                        # (some upstreams omit it). The text is
                        # surfaced to INSPECTION via ``extend_text``;
                        # if the final inspection blocks, the buffered
                        # tail bytes are dropped and an abort frame is
                        # emitted in their place.
                        tail_text = sse_buf.finalize()
                        pending_tail = ctx.scratch.get("_pending_raw_sse", b"")
                        if tail_text or pending_tail:
                            if tail_text:
                                rctx.extend_text(tail_text)
                            final_inspection = await self.pipeline.inspect_response_chunk(rctx, "")
                            if not final_inspection.is_allow and not self.config.shadow:
                                ctx.scratch["_pending_raw_sse"] = b""
                                rctx.finish_reason = "abort"
                                entry = self._record_decision(
                                    ctx,
                                    result=final_inspection,
                                    check_name="pipeline.inspection",
                                    metadata={
                                        "chunks_delivered": rctx.chunk_count,
                                        "chunk_count_at_abort": rctx.chunk_count,
                                        "abort_stage": "inspection",
                                        "abort_at_end_of_stream": True,
                                    },
                                )
                                for frame in self._build_abort_frames(
                                    reason=final_inspection.reason,
                                    stage="inspection",
                                    check_name=final_inspection.metadata.get("_check_name"),
                                    entry=entry,
                                ):
                                    yield frame
                                inspection_aborted = True
                                return
                            if not final_inspection.is_allow and self.config.shadow:
                                self._record_decision(
                                    ctx,
                                    result=final_inspection,
                                    check_name="pipeline.inspection",
                                )
                                ctx.scratch["_shadow_inspection_count"] = (
                                    ctx.scratch.get("_shadow_inspection_count", 0) + 1
                                )
                            # Inspection allowed: yield whatever was
                            # left in the pending-raw tail so the
                            # client still sees a terminator-less tail
                            # event from a non-spec-compliant upstream.
                            if pending_tail:
                                ctx.scratch["_pending_raw_sse"] = b""
                                yield pending_tail
                    except asyncio.CancelledError:
                        # Caller disconnected mid-stream; let
                        # cancellation propagate so the StreamingResponse
                        # generator unwinds cleanly. The ``finally``
                        # block below records the disconnect via the
                        # client_disconnect path.
                        raise
                    except (httpx.RemoteProtocolError, httpx.ReadError) as exc:
                        # Upstream tore down the stream or shipped
                        # malformed bytes after the headers. We have
                        # already streamed some chunks to the client (or
                        # at least committed to a 200), so emit an
                        # abort frame so the SDK sees a clean terminal
                        # event instead of a hung connection.
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_protocol_violation"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=upstream.status_code,
                            reason_detail=(
                                f"upstream protocol violation: {type(exc).__name__}: {exc}"
                            ),
                            reason_token="upstream_protocol_violation",  # noqa: S106
                            exception=exc,
                        ):
                            yield frame
                        return
                    except Exception as exc:
                        # Catch-all for any other upstream failure mode
                        # (RuntimeError from a misconfigured client,
                        # ssl errors, custom transport exceptions in
                        # the live bridge, etc.). Without this clause
                        # the exception bubbles into the StreamingResponse
                        # generator and the SDK sees an opaque hang
                        # rather than a structured terminal frame.
                        # CancelledError is re-raised above so caller
                        # disconnects still propagate cleanly.
                        upstream_aborted = True
                        rctx.finish_reason = "upstream_exception"
                        async for frame in self._emit_upstream_error_abort(
                            ctx,
                            rctx,
                            upstream_status=getattr(upstream, "status_code", None),
                            reason_detail=(f"upstream exception: {type(exc).__name__}: {exc}"),
                            reason_token="upstream_exception",  # noqa: S106
                            exception=exc,
                        ):
                            yield frame
                        return

                rctx.finish_reason = rctx.finish_reason or "stop"
                completed_normally = True
            except (asyncio.CancelledError, KeyboardInterrupt, SystemExit):
                # Caller disconnects + shutdown signals must propagate
                # so the StreamingResponse + ASGI plumbing can unwind
                # cleanly. The ``finally`` below handles client-disconnect
                # audit attribution via the ``completed_normally`` flag.
                raise
            except httpx.HTTPError as exc:
                # F1.5 (v0.1.8.x): the streaming-path twin of the F1
                # sync-path fix. ``httpx.AsyncClient.stream`` is an
                # ``@asynccontextmanager`` that issues the request inside
                # ``__aenter__``; ConnectError / TLS handshake / ReadTimeout
                # raised by __aenter__ previously escaped through the
                # generator. Now they produce a structured abort frame +
                # a ``pipeline.upstream`` audit row, matching what the
                # in-body protocol-violation branch does for failures
                # that happen AFTER the handshake succeeded.
                upstream_aborted = True
                rctx.finish_reason = "upstream_protocol_violation"
                async for frame in self._emit_upstream_error_abort(
                    ctx,
                    rctx,
                    upstream_status=None,
                    reason_detail=(
                        f"upstream http error during stream init: {type(exc).__name__}: {exc}"
                    ),
                    reason_token="upstream_protocol_violation",  # noqa: S106
                    exception=exc,
                ):
                    yield frame
                return
            except Exception as exc:
                # F1.5: any non-httpx exception from ``__aenter__`` (e.g.
                # RuntimeError from a misconfigured custom transport,
                # ssl errors not subclassing httpx.HTTPError, etc.) ALSO
                # gets a structured abort + audit row instead of leaking
                # through the StreamingResponse generator.
                upstream_aborted = True
                rctx.finish_reason = "upstream_exception"
                async for frame in self._emit_upstream_error_abort(
                    ctx,
                    rctx,
                    upstream_status=None,
                    reason_detail=(
                        f"upstream exception during stream init: {type(exc).__name__}: {exc}"
                    ),
                    reason_token="upstream_exception",  # noqa: S106
                    exception=exc,
                ):
                    yield frame
                return
            finally:
                # Three reasons we land here without completed_normally:
                # 1. The caller disconnected mid-stream and the
                #    StreamingResponse cancelled the generator.
                # 2. The upstream raised after we already started
                #    yielding (the outer 502 path is too late --
                #    bytes were already on the wire).
                # 3. The upstream returned a 5xx or shipped malformed
                #    SSE; we already emitted a structured abort frame
                #    and recorded the row in
                #    ``_emit_upstream_error_abort``.
                # 4. F1.5: the ``async with client.stream(...)`` failed
                #    inside ``__aenter__`` (DNS / TLS / connect refusal /
                #    misconfigured transport). The outer except branches
                #    above set ``upstream_aborted`` and wrote the
                #    ``pipeline.upstream`` row already; the guard below
                #    correctly skips the ``client_disconnect``
                #    attribution in that case.
                # In all cases we still want exactly one terminal row
                # in the chain so audit consumers can see the request
                # ended and how. inspection_aborted/upstream_aborted
                # already wrote their own rows -- don't double-count.
                # Avoid `return` in finally (would swallow in-flight
                # exceptions); guard the body instead.
                if not inspection_aborted and not upstream_aborted:
                    if not completed_normally:
                        rctx.finish_reason = rctx.finish_reason or "client_disconnect"
                    # Run RECORD checks even on disconnect -- they may flag
                    # cumulative drift, partial-output PII, etc.
                    try:
                        record_results = await self.pipeline.post_complete(rctx)
                    except Exception:
                        logger.exception("pipeline.post_complete crashed")
                        record_results = []
                    for record_result in record_results:
                        if not record_result.is_allow:
                            self._record_decision(
                                ctx,
                                result=record_result,
                                check_name=record_result.metadata.get(
                                    "_check_name", "pipeline.record"
                                ),
                            )
                    # Round 7 ``sse-malformed-event-silently-dropped``
                    # closure: surface the per-stream count of frames
                    # we failed to parse so operators can alert on the
                    # ratio. ``_sse_buffer`` is stashed by the chunk
                    # loop above; if the upstream init failed before
                    # the loop ran, the attribute is absent (no frames
                    # to count).
                    complete_meta: dict[str, Any] = {
                        "finish_reason": rctx.finish_reason,
                        "accumulated_text_truncated": rctx.accumulated_text_truncated,
                        "chunk_count": rctx.chunk_count,
                    }
                    sse_buf_for_audit = ctx.scratch.get("_sse_buffer")
                    if sse_buf_for_audit is not None:
                        complete_meta["dropped_frame_count"] = sse_buf_for_audit.dropped_frame_count
                    self._record_decision(
                        ctx,
                        result=None,
                        check_name="pipeline.complete",
                        metadata=complete_meta,
                    )
                # Decrement in-flight counter outside the inspection
                # branch so it always fires whether we completed
                # normally, were aborted, or the caller disconnected.
                self._in_flight_streams = max(0, self._in_flight_streams - 1)

        # Receipt and per-row chain entries can't be set on a streaming
        # response (no entry exists yet), but the upstream attribution
        # headers + any X-Signet-Shadow-* headers stashed by _admit fire
        # at handshake time so callers see them before they parse a
        # single chunk.
        #
        # Limitation: INSPECTION-stage shadow decisions detected during
        # the stream cannot retroactively add response headers (HTTP
        # response headers ship before the stream body). For streaming
        # callers, the audit chain is the source of truth on neutralized
        # mid-stream decisions. The handshake-time header
        # ``X-Signet-Shadow-Inspection-Active: 1`` advertises that shadow
        # is running so callers know to consult the chain.
        stream_headers = self._upstream_attribution_headers(None)
        shadow_headers = ctx.scratch.get("_shadow_headers")
        if shadow_headers:
            stream_headers.update(shadow_headers)
        if self.config.shadow:
            stream_headers["X-Signet-Shadow-Inspection-Active"] = "1"
        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers=stream_headers,
        )

    def _build_abort_frames(
        self,
        *,
        reason: str,
        stage: str,
        check_name: str | None,
        entry: AuditEntry | None,
    ) -> list[bytes]:
        """Build the structured SSE abort-frame pair.

        Wire format (see ``docs/streaming.md``)::

            data: {"signet_abort": true,
                   "reason": "<reason>",
                   "correlation_id": "<entry_id>",
                   "stage": "<stage>",
                   "check": "<check_name>"}\\n\\n
            data: [DONE]\\n\\n

        Strict-redaction rule: when
        ``self.config.strict_error_redaction`` is on, ``reason`` is
        coarsened to the literal string ``"refused"`` and the ``check``
        field is omitted entirely -- same coarsening
        :meth:`_refusal` applies to 4xx response bodies. Operators
        recover the full detail from the audit row via
        ``correlation_id``. ``correlation_id`` and ``stage`` always
        survive coarsening because they're structural (incident
        response can't pivot without them) rather than
        policy-revealing.

        Transport-reason exception: tokens in
        :data:`_TRANSPORT_ABORT_REASONS` (e.g.
        ``upstream_protocol_violation``, ``upstream_exception``) name
        a wire-state condition the SDK needs to differentiate from a
        policy refusal -- retrying a ``refused`` is wrong, retrying an
        upstream blip may be right. These survive strict coarsening so
        callers can branch on the reason without parsing the audit
        chain. The ``check`` field is still omitted under strict to
        keep behavior consistent with policy-blocked aborts.
        """
        is_transport = reason in _TRANSPORT_ABORT_REASONS
        # Build the payload in the canonical key order documented in
        # docs/streaming.md (M4): signet_abort, reason, correlation_id,
        # stage, check. SDKs that parse JSON don't care about order, but
        # operators reading a streamed log of frames do; aligning the
        # wire shape with the documented order keeps eyeball-debugging
        # honest. Python dict literals preserve insertion order since
        # 3.7, so an explicit ordered construction below is sufficient.
        correlation_id = entry.entry_id if entry is not None else None
        # Audit chain disabled (no audit_log_path). The None value above
        # surfaces this so the SDK can distinguish "no chain" from
        # "chain entry write failed".
        if self.config.strict_error_redaction and not is_transport:
            payload: dict[str, Any] = {
                "signet_abort": True,
                "reason": "refused",
                "correlation_id": correlation_id,
                "stage": stage,
            }
        elif self.config.strict_error_redaction and is_transport:
            # Preserve the transport reason but still drop the firing
            # check name (in line with strict policy-redaction shape).
            payload = {
                "signet_abort": True,
                "reason": reason,
                "correlation_id": correlation_id,
                "stage": stage,
            }
        else:
            payload = {
                "signet_abort": True,
                "reason": reason,
                "correlation_id": correlation_id,
                "stage": stage,
            }
            if check_name:
                payload["check"] = str(check_name)
        return [
            b"data: " + json.dumps(payload).encode("utf-8") + b"\n\n",
            b"data: [DONE]\n\n",
        ]

    async def _emit_upstream_error_abort(
        self,
        ctx: RequestContext,
        rctx: ResponseContext,
        *,
        upstream_status: int | None,
        reason_detail: str,
        reason_token: str = "upstream_protocol_violation",  # noqa: S107
        exception: BaseException | None = None,
    ) -> AsyncIterator[bytes]:
        """Yield the abort-frame pair for an upstream malformation/5xx.

        Records a synthetic audit row tagged with the upstream status
        and the verbatim error detail, then yields the structured
        SSE abort frame followed by ``data: [DONE]``. The audit row's
        ``check_name`` is ``"pipeline.upstream"`` so dashboards can
        distinguish proxy-side aborts (INSPECTION block) from
        upstream-failure aborts.

        Frame ``reason`` defaults to the stable token
        ``"upstream_protocol_violation"`` so SDKs can match against it
        without parsing the trailing detail string. Pass
        ``reason_token="upstream_exception"`` for non-protocol upstream
        failures (RuntimeError from a misconfigured proxy, etc.) so
        dashboards can split the two failure modes apart. Detail is
        logged in the audit row for incident review, not in the wire
        frame.

        ``exception`` is captured into the audit-row metadata as
        ``_exception_class`` and ``_exception_message`` for forensics
        when the caller has the live exception object.
        """
        # Build a synthetic CheckResult-shape so _record_decision
        # treats this as a non-allow with stage metadata; we want
        # signet_pipeline_decisions_total to fire so dashboards see
        # upstream-induced aborts in the same panel as INSPECTION
        # blocks.
        from signet.core.check import CheckResult

        synthetic = CheckResult.block(
            reason_detail,
            _check_name="pipeline.upstream",
            _stage="inspection",
            upstream_status=upstream_status,
        )
        meta: dict[str, Any] = {
            "chunks_delivered": rctx.chunk_count,
            "chunk_count_at_abort": rctx.chunk_count,
            "abort_stage": "upstream",
            "upstream_status": upstream_status,
        }
        if exception is not None:
            meta["_exception_class"] = type(exception).__name__
            meta["_exception_message"] = str(exception)
        entry = self._record_decision(
            ctx,
            result=synthetic,
            check_name="pipeline.upstream",
            metadata=meta,
        )
        for frame in self._build_abort_frames(
            reason=reason_token,
            stage="inspection",
            # No firing check -- the upstream itself failed. Strict
            # mode would omit this anyway; verbose-mode SDKs see
            # check absent rather than misleading.
            check_name=None,
            entry=entry,
        ):
            yield frame

    def _upstream_headers(self, ctx: RequestContext) -> dict[str, str]:
        """Headers to forward to the upstream. Strip signet-only headers.

        Round 13 ``forwarded-header-crlf-injection`` closure: the admit
        path validates forwarded header values via
        :func:`_header_value_is_safe` and refuses the request with a
        400 ``header_invalid_charset`` before reaching this builder, so
        in the production code path every forwarded value here is
        already guaranteed safe. The defense-in-depth check below
        re-validates anyway: a future caller that wires
        ``_upstream_headers`` outside :meth:`_admit` (e.g. a non-HTTP
        bridge, a new endpoint) inherits the same wire-safety guarantee
        rather than re-introducing a CRLF-injection surface by
        accident.
        """
        out: dict[str, str] = {}
        for h in self.config.extra_forward_headers:
            # Defense-in-depth: ``_header_value_is_safe`` skips values
            # that slipped past the admit-time check (e.g. a non-
            # ``_admit`` caller). The walrus operator pattern reads
            # the case-sensitive then case-insensitive header.
            if (
                (v := ctx.headers.get(h)) or (v := ctx.headers.get(h.lower()))
            ) and _header_value_is_safe(v):
                out[h] = v
        if self.config.upstream_api_key and "Authorization" not in out:
            out["Authorization"] = f"Bearer {self.config.upstream_api_key}"
        out["Content-Type"] = "application/json"
        return out

    def _upstream_attribution_headers(self, upstream_status: int | None) -> dict[str, str]:
        """Headers that let callers tell upstream errors from signet errors.

        Set on every forwarded response. ``X-Signet-Upstream`` carries
        either the configured label or the upstream URL host.
        ``X-Signet-Upstream-Status`` carries the upstream's HTTP status
        when known so a 500 the user sees can be unambiguously
        attributed to the upstream rather than to the gate.
        """
        from urllib.parse import urlparse

        label = self.config.upstream_label or urlparse(self.config.upstream_url).netloc
        out: dict[str, str] = {"X-Signet-Upstream": label}
        if upstream_status is not None:
            out["X-Signet-Upstream-Status"] = str(upstream_status)
        return out

    # ------------------------------------------------------------------
    # COMMITMENT on the HTTP path (F3)
    # ------------------------------------------------------------------
    #
    # Before F3, ``pipeline.inspect_tool_call`` had exactly one production
    # call site: :mod:`signet.server.realtime` (the Realtime WebSocket
    # path). The HTTP proxy never invoked it, so every COMMITMENT-stage
    # check -- including :class:`signet.checks.ToolCallInspectorCheck` and
    # its whole risk-tier registry -- was inert on ``/v1/chat/completions``.
    #
    # That is the path every OpenAI-compatible agent harness uses (Aider,
    # Goose, OpenHands, Cline, RigRun). An operator who configured
    # ``max_allowed_tier=MEDIUM`` and shipped it got a gate that recorded
    # the tool call in the audit chain and forwarded it anyway. Verified
    # against 0.1.10.1: a ``run_command`` call at HIGH tier passed through
    # with ``decision=allow``.
    #
    # The ``ToolCallContext`` docstring in realtime.py describes itself as
    # "shaped like the HTTP path's tool-call context", which suggests the
    # HTTP site was assumed to exist rather than deliberately omitted.

    @staticmethod
    def _extract_response_tool_calls(data: Any) -> list[tuple[str, dict[str, Any]]]:
        """Pull ``(tool_name, arguments)`` from a non-streaming response body.

        Walks ``choices[].message.tool_calls[]`` (current shape) and
        ``choices[].message.function_call`` (deprecated single-call shape
        still emitted by some OpenAI-compatible shims). Arguments arrive
        as a JSON-encoded string on the wire; they are parsed so checks
        see structured data, matching the Realtime path's contract. A
        non-dict or unparseable payload is wrapped as ``{"_raw": ...}``
        rather than dropped -- a check that gates on arguments must not
        silently receive ``{}`` for a malformed call.
        """

        def _parse_args(raw: Any) -> dict[str, Any]:
            if isinstance(raw, dict):
                return raw
            if isinstance(raw, str):
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    return {"_raw": raw}
                return parsed if isinstance(parsed, dict) else {"_raw": parsed}
            return {}

        calls: list[tuple[str, dict[str, Any]]] = []
        if not isinstance(data, dict):
            return calls
        choices = data.get("choices")
        if not isinstance(choices, list):
            return calls

        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if not isinstance(message, dict):
                continue

            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function")
                    if not isinstance(fn, dict):
                        continue
                    name = fn.get("name")
                    if isinstance(name, str) and name:
                        calls.append((name, _parse_args(fn.get("arguments"))))

            legacy = message.get("function_call")
            if isinstance(legacy, dict):
                name = legacy.get("name")
                if isinstance(name, str) and name:
                    calls.append((name, _parse_args(legacy.get("arguments"))))

        return calls

    async def _gate_tool_calls(
        self,
        ctx: RequestContext,
        rctx: ResponseContext,
        calls: list[tuple[str, dict[str, Any]]],
    ) -> Response | None:
        """Run COMMITMENT over proposed tool calls; return a refusal or ``None``.

        Returns ``None`` when every call is allowed (or when shadow mode
        converts a refusal into a pass-through). Returns a ready-to-send
        refusal :class:`Response` when a call is blocked or escalated and
        shadow mode is off.

        Fails closed: a crashing COMMITMENT check refuses the response
        rather than forwarding an ungated tool call, mirroring
        :meth:`signet.server.realtime._RealtimeBridge._handle_function_call`.
        """
        # Imported here rather than at module scope to match the existing
        # lazy-import convention in this module (see _record_exception).
        from signet.core.check import CheckResult

        for tool_name, arguments in calls:
            tcc = ToolCallContext(
                request=ctx,
                response=rctx,
                tool_name=tool_name,
                arguments=arguments,
                tool_metadata={},
            )

            try:
                result = await self.pipeline.inspect_tool_call(tcc)
            except Exception as exc:
                self._record_exception(ctx, exc, check_name="pipeline.commitment")
                logger.exception("HTTP COMMITMENT pipeline crashed")
                if self.config.shadow:
                    continue
                synthetic = CheckResult.block(
                    f"COMMITMENT pipeline raised {type(exc).__name__}",
                    _check_name="pipeline.commitment",
                    tool_name=tool_name,
                )
                entry = self._record_decision(
                    ctx, result=synthetic, check_name="pipeline.commitment"
                )
                return self._refusal(synthetic, entry)

            if result.is_allow:
                self._record_decision(
                    ctx,
                    result=result,
                    check_name="pipeline.commitment",
                    metadata={"tool_name": tool_name},
                )
                continue

            check_name = str(result.metadata.get("_check_name", "pipeline.commitment"))
            entry = self._record_decision(
                ctx,
                result=result,
                check_name=check_name,
                metadata={"tool_name": tool_name},
            )

            if self.config.shadow:
                # Shadow: the audit row already carries shadow=True via
                # _record_decision. Keep forwarding.
                continue

            return self._refusal(result, entry)

        return None

    def _refusal(self, result: Any, entry: AuditEntry | None) -> Response:
        """Translate a BLOCK CheckResult into the appropriate HTTP error.

        Body shape depends on :attr:`ServerConfig.strict_error_redaction`:

        * **Strict (default)**: ``{"error": "refused",
          "correlation_id": "<entry_id>"}``. The check name, reason,
          stage, and rule are intentionally absent -- full detail lives
          in the audit chain. Incident response uses the correlation
          ID to look up the row.
        * **Verbose** (``--no-strict-error-redaction`` / ``--dev``):
          full detail, the historical v0.1.4 shape -- useful when
          integrating with signet for the first time.
        """
        status = 403
        if "rate limit" in result.reason.lower():
            status = 429

        if self.config.strict_error_redaction:
            body: dict[str, Any] = {
                "error": "refused",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            # Retry-After is operational, not security-relevant -- keep
            # it in the strict body so well-behaved clients can back off.
            if "retry_after_seconds" in result.metadata:
                body["retry_after_seconds"] = result.metadata["retry_after_seconds"]
        else:
            body = {
                "error": "signet refused this request",
                "reason": result.reason,
                "check": result.metadata.get("_check_name"),
                "stage": result.metadata.get("_stage"),
                "correlation_id": entry.entry_id if entry is not None else None,
            }
            if "retry_after_seconds" in result.metadata:
                body["retry_after_seconds"] = result.metadata["retry_after_seconds"]

        # Refusals never reach the upstream, so X-Signet-Upstream-Status
        # is omitted; X-Signet-Upstream still fires so consumers can
        # confirm the gate-of-record.
        headers = self._upstream_attribution_headers(None)
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(status_code=status, content=body, headers=headers)

    def _escalation(self, result: Any, entry: AuditEntry | None) -> Response:
        """Translate an ESCALATE CheckResult into ``202 Accepted``.

        202 is the right status: the gate received the request, did not
        forward it, and is awaiting an out-of-band approval that signet
        does not orchestrate. The caller (or a higher-level system) is
        responsible for the approval workflow and resubmitting.

        Body shape obeys :attr:`ServerConfig.strict_error_redaction`,
        same as :meth:`_refusal`.
        """
        if self.config.strict_error_redaction:
            body: dict[str, Any] = {
                "status": "escalated",
                "correlation_id": entry.entry_id if entry is not None else None,
            }
        else:
            body = {
                "status": "escalated",
                "reason": result.reason,
                "check": result.metadata.get("_check_name"),
                "stage": result.metadata.get("_stage"),
                "audit_entry_id": entry.entry_id if entry is not None else None,
                "correlation_id": entry.entry_id if entry is not None else None,
            }
        headers = self._upstream_attribution_headers(None)
        if entry is not None and self._receipt_signer is not None:
            headers[self.config.receipt_header_name] = self._receipt_signer.sign(entry)
        return JSONResponse(status_code=202, content=body, headers=headers)

    def _stash_shadow_headers(
        self,
        ctx: RequestContext,
        result: Any,
        entry: AuditEntry | None,
        *,
        decision: str,
    ) -> None:
        """Build the ``X-Signet-Shadow-*`` header set and stash it on ctx.

        Called from the admit + inspection paths whenever a non-allow
        decision is neutralized by shadow mode. The forward path
        (:meth:`_forward_unary` / :meth:`_forward_stream`) merges the
        stashed headers into the eventual response.

        Headers emitted:

        * ``X-Signet-Shadow-Decision`` -- block / escalate / redact.
        * ``X-Signet-Shadow-Reason`` -- coarsened to ``"refused"`` when
          ``strict_error_redaction`` is on (matches the redaction rule
          that ``_refusal``/``_escalation`` apply to body content); the
          full reason otherwise.
        * ``X-Signet-Shadow-Stage`` -- admission / inspection /
          commitment / record (read from the result metadata).
        * ``X-Signet-Shadow-Check`` -- the firing check name
          (``_check_name`` from the result metadata, omitted in strict
          mode for the same reason ``_refusal`` redacts it from the
          body).
        * ``X-Signet-Correlation-Id`` -- the audit entry ID. Operators
          pivot from response → audit row via this ID.
        """
        headers: dict[str, str] = ctx.scratch.setdefault("_shadow_headers", {})
        headers["X-Signet-Shadow-Decision"] = decision
        if self.config.strict_error_redaction:
            headers["X-Signet-Shadow-Reason"] = "refused"
        else:
            headers["X-Signet-Shadow-Reason"] = result.reason
            check_name = result.metadata.get("_check_name")
            if check_name:
                headers["X-Signet-Shadow-Check"] = str(check_name)
        stage = result.metadata.get("_stage")
        if stage:
            headers["X-Signet-Shadow-Stage"] = str(stage)
        if entry is not None:
            headers["X-Signet-Correlation-Id"] = entry.entry_id

    def _record_upstream_failure(
        self,
        ctx: RequestContext,
        *,
        reason: str,
        refusal_kind: str,
        exception: BaseException | None = None,
        upstream_status: int | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> tuple[AuditEntry | None, dict[str, Any]]:
        """Shared writer for sync-path upstream failures (F1).

        Produces the pair (audit-entry, signet-shaped response body)
        that ``_forward_unary`` returns when the upstream errored before
        signet could parse a JSON response. The streaming path has its
        own equivalent in :meth:`_emit_upstream_error_abort` -- this
        helper keeps the unary path's contract aligned (same
        ``check_name='pipeline.upstream'``, same ``_refusal_kind``
        discriminator vocabulary as the abort frames).

        ``refusal_kind`` values:

        * ``upstream_protocol_violation`` -- httpx.HTTPError (connect
          failure, read error, protocol error, timeout).
        * ``upstream_exception`` -- non-httpx ``Exception`` raised by
          the client during the post call.
        * ``upstream_content_type_invalid`` -- 200 OK but Content-Type
          is not JSON on a JSON endpoint.
        * ``upstream_decode_error`` -- JSON-shaped Content-Type but
          the body did not parse.
        * ``upstream_redirect`` -- upstream returned a 3xx response.
          Forwarding the redirect would bypass signet (the client would
          re-issue the request to the Location target without going
          back through the gate). Handled by
          :meth:`_record_upstream_redirect` which builds a structured
          signet-shaped 502 body instead.

        Strict-error-redaction honored: under strict the response body
        is the minimal ``{"error": "upstream forward failed",
        "correlation_id": "..."}`` shape, mirroring the
        :meth:`_refusal` redaction rule. Verbose mode adds the
        ``refusal_kind``, the upstream status, and the exception class
        for SDK ergonomics.
        """
        from signet.core.check import CheckResult

        meta: dict[str, Any] = {
            "_refusal_kind": refusal_kind,
            "_pipeline_upstream_failure": True,
        }
        if upstream_status is not None:
            meta["upstream_status"] = upstream_status
        if exception is not None:
            meta["_exception_class"] = type(exception).__name__
            meta["_exception_message"] = str(exception)
        if extra_metadata:
            meta.update(extra_metadata)

        synthetic = CheckResult.block(
            reason,
            _check_name="pipeline.upstream",
            _stage="inspection",
        )
        entry = self._record_decision(
            ctx,
            result=synthetic,
            check_name="pipeline.upstream",
            metadata=meta,
        )

        correlation_id = entry.entry_id if entry is not None else None
        if self.config.strict_error_redaction:
            body: dict[str, Any] = {
                "error": "upstream forward failed",
                "correlation_id": correlation_id,
            }
        else:
            body = {
                "error": "upstream forward failed",
                "refusal_kind": refusal_kind,
                "correlation_id": correlation_id,
            }
            if upstream_status is not None:
                body["upstream_status"] = upstream_status
            if exception is not None:
                body["exception"] = type(exception).__name__
        return entry, body

    def _record_upstream_redirect(
        self,
        ctx: RequestContext,
        *,
        upstream_status: int,
        location_host: str | None,
    ) -> tuple[AuditEntry | None, dict[str, Any]]:
        """Shared writer for sync/stream upstream redirect refusals.

        Round 4 hunt finding: previously a 3xx upstream response was
        forwarded verbatim to the client. The client would then follow
        the redirect to whatever ``Location`` the upstream named, which
        is a signet bypass -- the followed request never re-enters the
        gate, so policy checks (rate limits, redaction, classification)
        do not apply to it. A hostile or misconfigured upstream could
        redirect the caller into an attacker-controlled host or into a
        loop. Block the redirect at the gate instead.

        Produces the (audit-entry, signet-shaped body) pair the caller
        returns as a 502. Body shape (intentionally distinct from the
        flat ``upstream forward failed`` shape so SDKs can branch on
        ``signet.error``):

        .. code-block:: json

            {
              "signet": {
                "error": "upstream_redirected",
                "upstream_status": 302,
                "upstream_location_host": "evil.example.com"
              }
            }

        ``upstream_location_host`` is the netloc only -- never the full
        URL (path / query / fragment / userinfo are dropped). A
        relative Location, missing Location, or unparseable Location
        surfaces as ``null`` so the body shape stays stable across
        upstreams.

        Strict-error-redaction adds the audit ``correlation_id`` to the
        ``signet`` object so incident response can pivot from response
        to chain row, but does NOT remove ``upstream_status`` /
        ``upstream_location_host``: those are operationally useful and
        not policy-revealing (they describe the upstream, not the
        gate's decision logic).
        """
        from signet.core.check import CheckResult

        meta: dict[str, Any] = {
            "_refusal_kind": "upstream_redirect",
            "_pipeline_upstream_failure": True,
            "upstream_status": upstream_status,
            "upstream_location_host": location_host,
        }
        synthetic = CheckResult.block(
            (
                f"upstream returned {upstream_status} redirect to "
                f"{location_host or '<unknown>'}; signet does not "
                "follow upstream redirects"
            ),
            _check_name="pipeline.upstream",
            _stage="inspection",
        )
        entry = self._record_decision(
            ctx,
            result=synthetic,
            check_name="pipeline.upstream",
            metadata=meta,
        )
        body: dict[str, Any] = {
            "signet": {
                "error": "upstream_redirected",
                "upstream_status": upstream_status,
                "upstream_location_host": location_host,
            }
        }
        if entry is not None:
            body["signet"]["correlation_id"] = entry.entry_id
        return entry, body

    def _record_decision(
        self,
        ctx: RequestContext,
        *,
        result: Any,
        check_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry | None:
        """Persist one audit row.

        Maps the four CheckResult outcomes to the four Decision values
        one-to-one -- earlier versions collapsed REDACT/ESCALATE into
        BLOCK, which lost information needed for incident review.

        Shadow mode: when ``self.config.shadow`` is True and
        ``result`` is a non-allow CheckResult, ``meta["shadow"] = True``
        is stamped on the audit row and the
        ``signet_shadow_would_have_blocked_total`` counter increments
        with the same {check, stage, decision} label set as
        ``signet_pipeline_decisions_total`` so dashboards can join the
        two. The decision recorded in the chain remains the original
        (block / escalate / redact) -- shadow only changes what the
        response layer does, never what the chain says.
        """
        decision = _result_to_decision(result)
        # Always tally pipeline decisions, even when no audit chain
        # is configured (developer mode, ephemeral runs). Stage label
        # is read from the result metadata when present so dashboards
        # can group by stage (admission/inspection/commitment/record);
        # an empty string means "stage not stamped" (e.g. synthetic
        # ``pipeline.complete`` rows that aren't tied to a single
        # stage).
        stage_label = ""
        if result is not None:
            try:
                stage_label = str(result.metadata.get("_stage", ""))
            except AttributeError:  # pragma: no cover -- defensive
                stage_label = ""
        self.metrics.inc(
            "signet_pipeline_decisions_total",
            {
                "check": check_name,
                "stage": stage_label,
                "decision": decision.value,
            },
        )
        is_shadowed = self.config.shadow and result is not None and not result.is_allow
        if is_shadowed:
            stage = ""
            try:
                stage = str(result.metadata.get("_stage", ""))
            except AttributeError:  # pragma: no cover -- defensive
                stage = ""
            self.metrics.inc(
                "signet_shadow_would_have_blocked_total",
                {
                    "check": check_name,
                    "stage": stage,
                    "decision": decision.value,
                },
            )
        if self._chain is None:
            return None
        reason = result.reason if result is not None else "request completed"
        meta = dict(metadata or {})
        if result is not None:
            meta.update(result.metadata)
        if is_shadowed:
            meta["shadow"] = True
        entry = AuditEntry(
            owner=ctx.owner,
            check_name=check_name,
            decision=decision,
            reason=reason,
            metadata=meta,
            request_fingerprint=ctx.scratch.get("_request_fingerprint", ""),
        )
        appended = self._chain.append(entry)
        self.metrics.inc("signet_audit_chain_appends_total")
        # If anchor backend is configured and reported a failure on
        # this entry, count it so operators can alert on anchor SLO.
        from signet.audit.anchor import ANCHOR_FIELD

        anchor_meta = appended.metadata.get(ANCHOR_FIELD, {})
        if isinstance(anchor_meta, dict) and anchor_meta.get("success") is False:
            self.metrics.inc(
                "signet_audit_anchor_failures_total",
                {"backend": str(anchor_meta.get("backend", "unknown"))},
            )
        return appended

    def _record_exception(
        self,
        ctx: RequestContext,
        exc: BaseException,
        *,
        check_name: str,
    ) -> AuditEntry | None:
        """Persist a synthetic audit row when the pipeline crashes.

        Audit consumers downstream rely on every request producing at
        least one row; an unhandled exception leaving the chain silent
        is itself a security-relevant gap.
        """
        if self._chain is None:
            return None
        entry = AuditEntry(
            owner=ctx.owner,
            check_name=check_name,
            decision=Decision.BLOCK,
            reason=f"pipeline raised {type(exc).__name__}: {exc}",
            metadata={
                "_exception_class": type(exc).__name__,
                "_exception_message": str(exc),
            },
            request_fingerprint=ctx.scratch.get("_request_fingerprint", ""),
        )
        return self._chain.append(entry)

    def _preflight_response(
        self,
        *,
        status_code: int,
        error: str,
        entry: AuditEntry | None,
        verbose_extras: dict[str, Any] | None = None,
    ) -> JSONResponse:
        """Build a complete preflight refusal response.

        Round 11 ``preflight-400-paths-omit-X-Signet-Upstream`` closure:
        pre-fix every preflight 400 returned a ``JSONResponse`` without
        the ``X-Signet-Upstream`` attribution header that 413 / 403 /
        429 / 502 all set. Operators routing through signet could not
        distinguish "signet refused" from "upstream refused" without
        parsing the body. This wrapper centralizes the body shape and
        the attribution-header merge so every preflight refusal -- 400
        and 413 alike -- carries the same operator-visible signal.
        """
        return JSONResponse(
            status_code=status_code,
            content=self._preflight_body(
                error=error,
                entry=entry,
                verbose_extras=verbose_extras,
            ),
            headers=self._upstream_attribution_headers(None),
        )

    def _outer_fallback_response(
        self,
        ctx: RequestContext,
        exc: BaseException,
        *,
        check_name: str,
    ) -> JSONResponse:
        """Build the safe outer-fallback 502 for ``_handle_*`` handlers.

        Round 11 ``outer-fallback-leaks-exception-classname-no-
        correlation_id-no-attribution`` closure: pre-fix every
        per-endpoint handler returned a bare ``{"error": "upstream
        forward failed", "exception": "<PythonClassName>"}`` from its
        catch-all ``except``, leaking the Python exception class name
        under ``strict_error_redaction=True`` (the docstring promises
        the public response does not name internals), omitting
        ``correlation_id`` so operators could not pivot to the
        ``_record_exception`` audit row, and omitting the
        ``X-Signet-Upstream`` attribution header. This helper records
        the exception via :meth:`_record_exception` (returning the
        entry so its ``entry_id`` becomes the response's
        ``correlation_id``), honors ``strict_error_redaction`` (no
        ``exception`` field under strict; verbose still surfaces the
        class name for SDK ergonomics), and attaches
        ``X-Signet-Upstream`` so every signet-emitted error response
        carries operator attribution.

        Round 13 INFO note: after R12 this helper is largely
        defense-in-depth. ``_forward_unary`` already catches
        ``httpx.HTTPError`` + generic ``Exception`` and converts to a
        structured 502 via :meth:`_record_upstream_failure`; the
        ``post_complete`` try/except inside ``_forward_unary``
        short-circuits the only path that could surface a check-side
        exception. Live probes against a dead upstream go through
        :meth:`_record_upstream_failure` rather than this helper. The
        helper still exists because the ``except Exception`` around
        ``_forward_unary`` is the last line of defense against a
        future regression that lets an exception leak out of the
        forward path; keeping it correct (and tested) means future
        refactors that touch ``_forward_unary`` are still safe.
        """
        entry = self._record_exception(ctx, exc, check_name=check_name)
        correlation_id = entry.entry_id if entry is not None else None
        body: dict[str, Any] = {
            "error": "upstream forward failed",
            "correlation_id": correlation_id,
        }
        if not self.config.strict_error_redaction:
            body["exception"] = type(exc).__name__
        return JSONResponse(
            status_code=502,
            content=body,
            headers=self._upstream_attribution_headers(None),
        )

    def _admission_fallback_response(
        self,
        ctx: RequestContext,
        exc: BaseException,
        *,
        check_name: str,
    ) -> JSONResponse:
        """Build the safe admission-fallback 500 for an ADMISSION-stage
        pipeline crash.

        Round 13 ``admission-pipeline-crash-leaks-classname`` closure:
        sibling of :meth:`_outer_fallback_response`. The admission-side
        catch in :meth:`_admit` (pre-fix) returned a bare
        ``{"error": "signet pipeline crashed during admission",
        "exception": "<ClassName>"}`` body even under
        ``strict_error_redaction=True``, omitted ``correlation_id`` so
        operators could not pivot to the ``_record_exception`` audit
        row, and omitted the ``X-Signet-Upstream`` attribution header.
        This helper has the same redaction / correlation / attribution
        semantics as ``_outer_fallback_response`` but emits a 500
        (admission-side crash before forwarding ever started) with the
        ADMISSION-shape error label so dashboards can split the two
        failure modes apart.
        """
        entry = self._record_exception(ctx, exc, check_name=check_name)
        correlation_id = entry.entry_id if entry is not None else None
        body: dict[str, Any] = {
            "error": "signet pipeline crashed during admission",
            "correlation_id": correlation_id,
        }
        if not self.config.strict_error_redaction:
            body["exception"] = type(exc).__name__
        return JSONResponse(
            status_code=500,
            content=body,
            headers=self._upstream_attribution_headers(None),
        )

    def _preflight_body(
        self,
        *,
        error: str,
        entry: AuditEntry | None,
        verbose_extras: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Shared response-body shape for the preflight 400 paths.

        Round 7 closure for the
        ``preflight-400-leaks-detail-and-omits-correlation-id`` finding:

        * Strict mode coarsens the body to ``{"error": "...",
          "correlation_id": "..."}`` -- a targeted prober can no longer
          map parser internals (column number, expected schema,
          ``got_type``) from these 4xx bodies.
        * Verbose mode keeps the historical hint fields so first-time
          integrators get an actionable error message.
        * Both modes now carry ``correlation_id`` so incident response
          can pivot from a preflight 400 to its audit row -- the link
          that the strict-redaction docstring already promised.

        ``entry`` is the row written by ``_record_preflight_refusal``;
        when the audit chain is unconfigured ``entry`` may be None and
        ``correlation_id`` is set to ``None`` (still present in the
        body so callers can unconditionally read the key).
        """
        body: dict[str, Any] = {
            "error": error,
            "correlation_id": entry.entry_id if entry is not None else None,
        }
        if not self.config.strict_error_redaction and verbose_extras:
            body.update(verbose_extras)
        return body

    def _record_preflight_refusal(
        self,
        *,
        request: Request,
        headers: dict[str, str],
        client_ip: str | None,
        session_id: str | None,
        path: str,
        fingerprint: str,
        reason: str,
        refusal_kind: str,
        extra_metadata: dict[str, Any],
    ) -> AuditEntry | None:
        """Persist a synthetic audit row for a 400 refused *before* the
        pipeline ran (empty body, malformed JSON, non-object body,
        non-finite floats).

        v0.1.7 charter promised every refused request leaves an audit
        row; v0.1.7 H1 wired the 400 response shape for non-object
        bodies but missed the audit-row half of that promise. NF1
        (v0.1.7.1) closes the gap by routing every pre-pipeline 400
        through this helper.

        The owner is :meth:`Owner.unresolved`: by definition admission
        never ran so we have no resolved identity. Metadata stamps a
        ``_pre_pipeline_refusal`` marker so downstream consumers can
        filter these rows out of policy-decision dashboards if they
        only care about pipeline-stage outcomes.
        """
        from signet.core.check import CheckResult

        ctx = RequestContext(
            owner=Owner.unresolved(),
            headers=headers,
            body={},
            path=path,
            method=request.method,
            client_ip=client_ip,
            session_id=session_id,
        )
        ctx.scratch["_request_fingerprint"] = fingerprint
        result_metadata: dict[str, Any] = {
            "_stage": "preflight",
            "_refusal_kind": refusal_kind,
        }
        result_metadata.update(extra_metadata)
        synthetic = CheckResult.block(reason, **result_metadata)
        return self._record_decision(
            ctx,
            result=synthetic,
            check_name="pipeline.preflight",
            metadata={"_pre_pipeline_refusal": True, "_refusal_kind": refusal_kind},
        )


class _BodyTooLarge(Exception):
    """Raised when the inbound request body exceeds the configured cap.

    ``limit`` is the configured ``max_request_body_bytes`` cap;
    ``bytes_seen`` is how many bytes the reader accumulated before
    tripping the cap. Round 9 closure surfaces ``bytes_seen`` into
    the 413 audit row so operators can see whether a request was
    only just over the cap or massively over.
    """

    def __init__(self, limit: int, bytes_seen: int = 0) -> None:
        super().__init__(f"request body exceeds {limit} bytes")
        self.limit = limit
        self.bytes_seen = bytes_seen


def _result_to_decision(result: Any) -> Decision:
    """Map a CheckResult-or-None to the corresponding Decision."""
    if result is None or result.is_allow:
        return Decision.ALLOW
    if result.is_block:
        return Decision.BLOCK
    if result.is_redact:
        return Decision.REDACT
    if result.is_escalate:
        return Decision.ESCALATE
    return Decision.BLOCK  # fail closed if a future Decision is added without a mapping


#: Recursion ceiling for :func:`_contains_non_finite_float`. JSON
#: documents that legitimately exceed this depth are exceptionally
#: rare; deeper inputs are treated as suspicious and refused (returning
#: ``True``) so we never recurse without bound on adversarial payloads.
#: ``json.loads`` itself defends against pathological depth via its own
#: recursion limit, so reaching this is effectively a no-op safety net.
_NON_FINITE_WALK_MAX_DEPTH: int = 256

#: Hard ceiling on JSON object/array nesting depth in inbound request
#: bodies. ``json.loads`` is recursive in CPython, so a sufficiently
#: nested payload trips Python's interpreter ``RecursionError`` (raised
#: as a bare ``RecursionError``, NOT a ``json.JSONDecodeError``) and the
#: error message ("invalid JSON body") gives operators no signal as to
#: the actual cause. A 64-level cap covers legitimate chat-completion
#: bodies (deeply-nested tool call args are still under ~10 levels in
#: practice) and refuses pathological depths up front with a structured
#: ``json_too_deeply_nested`` 400 instead of an opaque parser failure.
_MAX_JSON_DEPTH: int = 64

#: Hard ceiling on ``X-Signet-Session`` header value length, in bytes.
#: Round 7 closure for the ``unbounded-session-id-length`` finding: the
#: ``InMemorySessionStore`` LRU caps the number of sessions at 10 000,
#: but did not cap the *length* of each session ID -- a pathological
#: caller could exhaust ~10 GB by registering 10 000 distinct 1-MB
#: IDs. UUIDs (~36 bytes), hex hashes (32-64 bytes), and any reasonable
#: opaque token fit comfortably under 256.
_MAX_SESSION_ID_BYTES: int = 256

#: Allowed characters in ``X-Signet-Session``. Round 7 closure for the
#: ``null-bytes-in-session-id-accepted`` finding: ``get_header_ci``
#: stripped whitespace but not control characters, so a session ID
#: like ``"\x00abc"`` or ``"line1\nline2"`` was stored verbatim and
#: surfaced as embedded NULs / newlines in operator log tails. The
#: charset below covers UUIDs, hex hashes, base64url, opaque tokens,
#: and most reasonable session-ID shapes; anything else is rejected
#: with a preflight audit row.
_SESSION_ID_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_.:\-]+$")


def _header_value_is_safe(value: str) -> bool:
    """Return True when ``value`` is safe to forward as an HTTP header.

    Round 13 ``forwarded-header-crlf-injection`` closure: pre-fix the
    upstream-headers builder copied ``Authorization`` / ``OpenAI-Beta``
    / ``OpenAI-Organization`` straight from the inbound request without
    inspecting the values. h11 at the wire-send layer caught ``\\r\\n``
    sequences and raised ``LocalProtocolError``, which signet then
    funneled into a 502 ``upstream_protocol_violation`` -- the upstream
    got blamed for a client-side protocol violation, and dashboards
    alerting on upstream-failure-rate fired on a hostile client.

    Reject ``\\r``, ``\\n``, ``\\0``, and any other non-printable byte
    below 0x20 (except tab, 0x09) so the gate refuses the request with
    a structured 400 before the bytes ever touch the upstream HTTP
    client. Tab is allowed to permit folded header values; everything
    else in the C0 control range is wire-protocol-illegal in HTTP/1.1
    header values per RFC 7230 §3.2.6.

    Round 15 ``forwarded-header-non-ascii-mis-attributes-as-502``
    closure: extend the check to reject any byte in the ``0x80``-
    ``0xFF`` range. RFC 7230 §3.2.6 treats those as opaque ``obs-text``,
    but httpx (and most OpenAI-compatible upstreams) ASCII-encodes
    request header values at send time. Pre-fix a single ``0x85`` /
    ``0xA0`` / ``0xFF`` byte in ``Authorization`` survived the admit
    guard then raised ``UnicodeEncodeError`` deep inside the httpx
    client; signet's outer ``_outer_fallback_response`` catch then
    labelled the failure ``upstream_exception`` and returned a 502 with
    ``X-Signet-Upstream-Status`` attribution — the exact 502 mis-
    attribution shape R13 was built to retire. Refusing at admit time
    with ``header_invalid_charset`` + 400 + audit row keeps the
    failure mode attributed to the client.
    """
    for ch in value:
        cp = ord(ch)
        if cp == 0x09:  # tab is allowed
            continue
        if cp < 0x20 or cp >= 0x7F:
            # 0x7F (DEL) and the entire 0x80-0xFF obs-text range are
            # rejected. The strict ASCII-printable contract matches
            # what httpx will actually let through; admitting bytes
            # the downstream encoder cannot handle is the R15 mis-
            # attribution surface.
            return False
    return True


#: Set of registered ``/v1/*`` paths -- used by the 405 handler to
#: decide whether a method-mismatch request is on a real endpoint (in
#: which case 405 is correct) or on an unregistered path (in which case
#: 404 "endpoint not implemented" matches what POST to the same path
#: would return). Round 7 closure for the
#: ``get-on-v1-anything-returns-misleading-405`` finding.
_REGISTERED_V1_PATHS: frozenset[str] = frozenset(
    {
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/realtime",
    }
)


def _unsupported_v1_body(path: str) -> dict[str, Any]:
    """Build the ``unsupported_v1`` 404 body for ``path``.

    Pulled out as a module-level helper so the 405-fallback path and
    the catch-all POST route share the exact same shape. Mismatched
    bodies between those two paths is the root cause of the M8
    ergonomics class and Round 7's
    ``get-on-v1-anything-returns-misleading-405`` finding.
    """
    return {
        "error": f"endpoint not implemented in signet v{__version__}",
        "endpoint": path if path.startswith("/v1/") else f"/v1/{path.lstrip('/')}",
        "note": (
            f"signet v{__version__} gates /v1/chat/completions, "
            "/v1/completions, and /v1/embeddings. /v1/audio/* "
            "and /v1/images/* are roadmapped -- their non-JSON "
            "request shapes need their own check protocols "
            "and aren't a copy-paste addition."
        ),
    }


#: Hard ceiling on a single SSE chunk decoded into a Python string.
#: Round 7 closure for the ``sse-stream-chunk-no-size-bound`` finding:
#: ``ResponseContext.extend_text`` caps the accumulated text at 1 MiB
#: but the per-chunk ``chunk_text`` and the working buffers inside
#: ``_SSEBuffer`` were unbounded, so a hostile upstream could OOM the
#: proxy with a single 100-MB chunk. 1 MiB matches the accumulated
#: text cap and is comfortably above legitimate chunk sizes (most
#: upstreams ship ~16 KiB chunks).
_MAX_STREAM_CHUNK_BYTES: int = 1 * 1024 * 1024

#: Hard ceiling on the unterminated-event raw-byte buffer held by
#: ``_forward_stream`` while waiting for an SSE event terminator.
#: Round 9 closure for the ``sse-pending-raw-unbounded`` finding: an
#: upstream that never emits a ``\n\n`` (or ``\r\n\r\n`` / ``\r\r``)
#: terminator could grow this buffer indefinitely -- 500 x 500 KB
#: unterminated chunks observed at ~250 MB / 720 MB peak. 4 MiB is
#: well above any legitimate single SSE event (which are typically
#: under a kilobyte each) and aborts hostile / broken upstreams with
#: a structured ``upstream_sse_unterminated`` audit row instead of
#: silently OOMing the host.
_MAX_PENDING_RAW_SSE_BYTES: int = 4 * 1024 * 1024

#: WHATWG EventSource spec line-terminator regex. Per the spec a line
#: terminator is one of ``\r\n``, ``\r``, or ``\n``; an SSE event is
#: dispatched on **two** consecutive line terminators. Round 9 closure
#: for the ``sse-cr-line-terminator-bypass`` finding: the previous
#: outer-loop only recognized ``\n\n`` and ``\r\n\r\n`` — spec-valid
#: ``\r\r``, ``\n\r``, ``\r\n\r``, ``\r\r\n``, ``\r\n\n``, and
#: ``\n\r\n`` terminator pairs were missed, so events using those
#: combinations were held in ``_pending_raw_sse`` (then yielded raw
#: at end-of-stream) while ``_SSEBuffer.feed``'s return value was
#: discarded. The regex matches any spec-valid two-terminator
#: sequence so the outer loop now agrees with the buffer's internal
#: ``splitlines()``-driven line dispatch. Anchored so we find the
#: LAST terminator in the buffer (greedy ``.search()`` over the
#: accumulated bytes).
_SSE_EVENT_TERMINATOR_RE: re.Pattern[bytes] = re.compile(rb"(?:\r\n|\r|\n)(?:\r\n|\r|\n)")

#: Round 9 default-deny: structural keys at the TOP LEVEL of ``delta``
#: that ``_collect_inspectable_strings`` skips when, AND ONLY WHEN, the
#: top-level delta value conforms to its expected wire contract (see
#: :func:`_validate_top_level_structural_field`). Anything else — known
#: text-bearing fields like ``content`` / ``refusal`` / ``reasoning``,
#: AND any new field a future upstream adds (``thinking``,
#: ``audio.text``, ``private_reasoning``) — is inspected by default.
#: Closes the ``sse-delta-fields-default-allow`` bypass class so new
#: upstream features ship at signet's safe-by-default position rather
#: than waiting on an allowlist update.
#:
#: Round 11 ``sse-delta-structural-keys-denylist-content-bypass``
#: closure: the skip is now scoped to the TOP-LEVEL delta object only
#: AND gated on a structural-contract validator. Nested dicts/lists are
#: always inspected (a key named ``finish_reason`` or ``type`` inside
#: e.g. ``delta.tool_calls[0]`` is no longer a smuggle channel), AND a
#: top-level structural value that doesn't conform (e.g. ``delta.role``
#: with a non-enumerated string, or ``delta.type`` carrying a nested
#: dict) is reported as a protocol violation so the stream aborts
#: instead of skipping inspection.
_SSE_DELTA_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {
        # OpenAI delta structural fields — role label, index pointer,
        # message-id / type discriminator. Never text-bearing.
        "role",
        "index",
        "id",
        "type",
        # tool-call structural ids (NOT function.name or
        # function.arguments which are inspected by the recursive
        # walk in the same helper).
        "function_call_id",
        "tool_call_id",
        # Anthropic-shim / vendor structural fields that some
        # OpenAI-compatible proxies pass through verbatim. ``stop``
        # is a finish-reason token; ``object`` is the wire-shape
        # discriminator (``chat.completion.chunk``).
        "stop",
        "object",
        # ``finish_reason`` lives at the choice level rather than the
        # delta level but appears in nested dicts from some shims.
        "finish_reason",
    }
)


#: Enumerated values for ``delta.role`` per the OpenAI chat-completions
#: streaming spec. Any other value at the top level is treated as a
#: protocol violation so the stream aborts rather than letting a
#: hostile upstream smuggle classified text through ``delta.role``.
#:
#: Intent: this enum covers the OpenAI chat-completions wire shape
#: AND Anthropic-shim flows where an OpenAI-compatible proxy (LiteLLM,
#: Bedrock OpenAI-compat, etc.) forwards Anthropic role labels verbatim.
#: ``developer`` was added in OpenAI's December 2024 o1/o3 rollout --
#: Round 13 ``sse-delta-role-developer-aborts`` closure adds it so a
#: legitimate stream from those model families is not misclassified as
#: a protocol violation and aborted via ``upstream_sse_malformed``.
#: Anthropic raw streams flow through signet via shims that translate
#: to OpenAI shape before signet sees them; ``human`` (Anthropic) is
#: intentionally absent here -- a raw Anthropic stream would not parse
#: at the choices/delta layer at all, so adding ``human`` would only
#: bless a shape signet would otherwise refuse anyway.
_SSE_DELTA_ROLE_VALUES: frozenset[str] = frozenset(
    {"system", "user", "assistant", "tool", "function", "developer"}
)


#: Enumerated values for ``delta.finish_reason``. ``None`` (absent or
#: explicit JSON null) is also valid -- it appears as ``None`` in the
#: parsed dict and is handled separately in the validator.
#:
#: Intent: this enum covers BOTH the OpenAI chat-completions finish-
#: reason set (``stop``, ``length``, ``tool_calls``, ``content_filter``,
#: ``function_call``) AND the Anthropic-shim set (``end_turn``,
#: ``max_tokens``, ``stop_sequence``). Some OpenAI-compatible shims
#: (LiteLLM, AWS Bedrock OpenAI-compat) forward the Anthropic finish-
#: reason values verbatim rather than translating them. Round 13
#: ``sse-delta-finish-reason-anthropic-aborts`` closure adds those so
#: a legitimate OpenAI-shaped stream from an Anthropic upstream via a
#: leaky shim is not falsely aborted via ``upstream_sse_malformed``.
#: Round 15 ``sse-event-level-fields-bypass-inspection`` closure
#: (F-R15-2). Structural keys at the TOP LEVEL of an SSE event object
#: (one level up from ``delta``) whose values match an enumerated wire
#: contract and may therefore be skipped during inspection. Anything
#: else -- including string-valued event fields whose values are
#: attacker- or vendor-influenced (``id``, ``model``,
#: ``system_fingerprint``, ``error.message``, non-standard top-level
#: fields) -- is inspected by the recursive walker.
#:
#: The set is deliberately tight: only enum-shaped fields with closed
#: value sets are skipped. ``id`` and ``model`` and
#: ``system_fingerprint`` are string-valued but the upstream gets to
#: pick the value, so they're inspected like content. ``created`` and
#: ``usage.*`` are int-valued and skip via the walker's type filter
#: (the walker only collects strings / bytes), so they don't need
#: explicit entries here.
_SSE_EVENT_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {
        # Wire-shape discriminator: ``chat.completion.chunk``,
        # ``chat.completion``, ``text_completion``,
        # ``text_completion.chunk``. Any other value is a protocol
        # violation -- abort the stream rather than skip.
        "object",
    }
)


#: Enumerated values for ``event.object`` -- the OpenAI / OpenAI-compat
#: wire-shape discriminator at the top level of an SSE chunk. Round 15
#: ``sse-event-level-fields-bypass-inspection`` closure: an event whose
#: ``object`` is none of these is treated as a protocol violation and
#: the stream aborts via ``upstream_sse_malformed``. ``embedding`` and
#: ``list`` are unary-shape values (would not appear in a streaming
#: chunk) but are included for forward compatibility with shims that
#: pre-buffer non-streaming responses into a single SSE event.
_SSE_EVENT_OBJECT_VALUES: frozenset[str] = frozenset(
    {
        "chat.completion.chunk",
        "chat.completion",
        "text_completion",
        "text_completion.chunk",
        # Embeddings/list shapes for shims that emit them via SSE.
        "embedding",
        "list",
    }
)


#: Round 17 ``choices[i]-sibling-fields-uninspected`` closure (F-R17-1):
#: structural keys at the CHOICE level (one level below the event, one
#: level above ``delta``) that ``_collect_inspectable_strings`` may skip
#: when, AND ONLY WHEN, the choice-level value conforms to its
#: enumerated wire contract (see :func:`_validate_choice_structural_field`).
#: Anything else under a choice -- ``text`` (legacy ``/v1/completions``
#: streaming), ``message`` (chat.completion buffered-as-SSE), ``logprobs``
#: (token-level logprob payloads whose ``content[i].token`` and
#: ``top_logprobs[j].token`` are attacker-influenced strings), ``delta``
#: itself (handled separately by the delta-level walker), and any
#: future text-bearing field -- is inspected by the recursive walker.
#:
#: F-R15-2 stripped ``choices`` from the event-top walk to avoid double-
#: walking ``delta`` strings, but the matching choice-level loop in
#: ``_flush_event`` only re-included ``delta``. Sibling fields of
#: ``delta`` inside a choice (``text``, ``message``, ``logprobs``, the
#: choice-level ``finish_reason``) skipped inspection entirely. Closes
#: the same class of walker-scope bypass that F-R15-2 closed at the
#: event-top layer, one level deeper into the event tree.
_SSE_CHOICE_STRUCTURAL_KEYS: frozenset[str] = frozenset(
    {
        # Choice-level enum-shaped finish_reason (OpenAI ships it at
        # the choice level rather than under ``delta``).
        "finish_reason",
        # Per-choice index pointer -- int, never text-bearing.
        "index",
        # Some shims pre-buffer non-streaming responses into a single
        # SSE choice that carries its own ``object`` discriminator.
        "object",
    }
)


def _validate_choice_structural_field(key: str, value: Any) -> str:
    """Return an outcome token for a choice-level ``choice.<key>`` value.

    Round 17 ``choices[i]-sibling-fields-uninspected`` closure (F-R17-1):
    sibling of :func:`_validate_top_level_structural_field` (delta-level)
    and :func:`_validate_event_top_level_structural_field` (event-level)
    scoped to the choice-level structural set. The choice-level
    ``finish_reason`` shares the delta-level finish-reason enum
    (OpenAI / Anthropic-via-shim values) so a hostile upstream cannot
    bypass the enum check by relocating the marker from
    ``delta.finish_reason`` to ``choices[i].finish_reason`` (a
    documented asymmetry called out in F-R17-4 and subsumed by this
    fix). ``index`` is a non-negative int; a non-int / bool value
    is treated as a protocol violation. ``object`` shares the event-
    level object enum.
    """
    if key == "finish_reason":
        if value is None:
            return _STRUCTURAL_OK
        if not isinstance(value, str):
            return _STRUCTURAL_WALK
        if value in _SSE_DELTA_FINISH_REASON_VALUES:
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    if key == "index":
        if isinstance(value, bool):
            return _STRUCTURAL_ABORT
        if isinstance(value, int):
            return _STRUCTURAL_OK
        if value is None:
            return _STRUCTURAL_OK
        return _STRUCTURAL_WALK
    if key == "object":
        if value is None:
            return _STRUCTURAL_OK
        if not isinstance(value, str):
            return _STRUCTURAL_WALK
        if value in _SSE_EVENT_OBJECT_VALUES:
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    # Defense in depth: an unknown key shouldn't be in
    # _SSE_CHOICE_STRUCTURAL_KEYS in the first place; fall through to
    # WALK rather than silently skip if a future entry lands without
    # a matching branch.
    return _STRUCTURAL_WALK


def _validate_event_top_level_structural_field(key: str, value: Any) -> str:
    """Return an outcome token for an event-level ``event.<key>`` value.

    Round 15 sibling of :func:`_validate_top_level_structural_field`
    but scoped to event-level structural fields (one level up from the
    delta-level structural set). Currently the only event-level
    enum-shaped field is ``object``; ``id``, ``model``, and
    ``system_fingerprint`` are intentionally NOT structural here --
    they are open strings whose values reflect attacker- or vendor-
    influenced state, so they are inspected like content by the
    recursive walker.
    """
    if key == "object":
        if value is None:
            return _STRUCTURAL_OK
        if not isinstance(value, str):
            return _STRUCTURAL_WALK
        if value in _SSE_EVENT_OBJECT_VALUES:
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    # Defense-in-depth: an unknown key shouldn't be in
    # _SSE_EVENT_STRUCTURAL_KEYS in the first place, but if a future
    # entry lands without a matching branch, fall through to WALK
    # rather than silently skip.
    return _STRUCTURAL_WALK


_SSE_DELTA_FINISH_REASON_VALUES: frozenset[str] = frozenset(
    {
        # OpenAI chat-completions
        "stop",
        "length",
        "tool_calls",
        "content_filter",
        "function_call",
        # Anthropic-shim values forwarded verbatim by leaky proxies.
        # ``end_turn``, ``max_tokens``, ``stop_sequence`` are the
        # canonical Anthropic finish-reason set; ``pause_turn`` and
        # ``tool_use`` were added in Anthropic's late-2025 streaming
        # protocol (``tool_use`` overlaps semantically with OpenAI's
        # ``tool_calls`` -- some shims pick one and some pass both
        # through verbatim). Round 15 ``finish-reason-anthropic-2025-
        # additions`` closure: include both so a legitimate Anthropic-
        # via-shim stream does not abort with ``upstream_sse_malformed``.
        "end_turn",
        "max_tokens",
        "stop_sequence",
        "pause_turn",
        "tool_use",
    }
)


class _DepthSentinelList(list[str]):
    """List subclass used by :func:`_collect_inspectable_strings` to
    signal that the recursion-depth cap was tripped.

    Round 11 ``sse-delta-recursive-walk-depth-bypass`` closure: pre-fix
    the walker silently returned ``[]`` when ``depth > _max_depth`` so a
    7+-level nested ``delta`` payload bypassed inspection while the raw
    bytes still reached the client. The walker now returns this typed
    sentinel so the caller in :meth:`_SSEBuffer._flush_event` can flag
    ``malformed_event_seen`` and abort the stream via
    ``upstream_delta_too_deep`` instead of fail-open truncating.

    Carrying the signal as a typed subclass (rather than a side-channel
    attribute) keeps the walker's return-type checkable without an
    out-of-band exception path or a tuple return, and propagates
    cleanly through nested ``extend`` calls when the caller wraps a
    deep return in another result.
    """


# Outcome tokens for :func:`_validate_top_level_structural_field`:
# ``"ok"``     — value conforms; the walker may skip the field.
# ``"abort"``  — value is the right TYPE but a wrong VALUE for a closed-
#                set contract (e.g. ``delta.role`` is a string but not
#                in :data:`_SSE_DELTA_ROLE_VALUES`). Treated as a
#                protocol violation; the stream aborts via
#                ``upstream_sse_malformed``.
# ``"walk"``   — value is the wrong TYPE entirely (a nested dict / list
#                in place of a structural string). Don't skip and don't
#                abort: walk the value's strings through inspection so
#                any classification marker hidden inside the misshapen
#                value is caught by the inspection pipeline.
_STRUCTURAL_OK = "ok"
_STRUCTURAL_ABORT = "abort"
_STRUCTURAL_WALK = "walk"


def _validate_top_level_structural_field(key: str, value: Any) -> str:
    """Return an outcome token for a top-level ``delta.<key>`` value.

    Round 11 ``sse-delta-structural-keys-denylist-content-bypass``
    closure: the pre-fix skip was a fail-open content channel. Hostile
    upstreams set ``delta.role`` to an arbitrary string carrying a
    classification marker and the inspector skipped it entirely. The
    skip is now gated on a per-field contract:

    * ``role`` must be one of :data:`_SSE_DELTA_ROLE_VALUES`.
    * ``finish_reason`` must be ``None`` or one of
      :data:`_SSE_DELTA_FINISH_REASON_VALUES`.
    * ``index``, ``id``, ``type``, ``function_call_id``,
      ``tool_call_id``, ``stop``, ``object`` must be a non-empty
      string (or int for ``index``) with no control bytes
      (< 0x20 or 0x7f), or ``None``.

    Returns:
        ``_STRUCTURAL_OK`` if the value conforms; the walker skips
        the field.
        ``_STRUCTURAL_ABORT`` if the value is the right TYPE but a
        wrong VALUE for a closed-set contract (a hostile upstream
        with ``delta.role="(S//NF)"`` lands here); the stream
        aborts via the malformed-event path.
        ``_STRUCTURAL_WALK`` if the value is the wrong TYPE entirely
        (a nested dict / list); don't skip and don't abort -- walk
        the value's strings so any embedded marker is caught by the
        inspection pipeline (the test case
        ``delta.type={"nested":"(S//NF)"}`` lands here).
    """
    if key == "role":
        if not isinstance(value, str):
            return _STRUCTURAL_WALK
        if value in _SSE_DELTA_ROLE_VALUES:
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    if key == "finish_reason":
        if value is None:
            return _STRUCTURAL_OK
        if not isinstance(value, str):
            return _STRUCTURAL_WALK
        if value in _SSE_DELTA_FINISH_REASON_VALUES:
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    if key == "index":
        # OpenAI ships index as an int; some shims ship it as a string.
        # Both are acceptable as long as a string carries no control bytes.
        if isinstance(value, bool):
            return _STRUCTURAL_ABORT
        if isinstance(value, int):
            return _STRUCTURAL_OK
        if value is None:
            return _STRUCTURAL_OK
        if isinstance(value, str):
            if value and all(0x20 <= ord(c) < 0x7F for c in value):
                return _STRUCTURAL_OK
            return _STRUCTURAL_ABORT
        return _STRUCTURAL_WALK
    # id, type, function_call_id, tool_call_id, stop, object: non-empty
    # string with no control bytes, OR None. A nested dict/list value
    # is the wrong type entirely -- fall into walk so embedded markers
    # get inspected. A control-byte-laced string IS the right type but
    # fails the contract -- abort.
    if value is None:
        return _STRUCTURAL_OK
    if isinstance(value, str):
        if value and all(0x20 <= ord(c) < 0x7F for c in value):
            return _STRUCTURAL_OK
        return _STRUCTURAL_ABORT
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # ``stop`` is sometimes a numeric token-ID in legacy shims;
        # accept any non-bool number.
        return _STRUCTURAL_OK
    return _STRUCTURAL_WALK


def _collect_inspectable_strings(
    obj: Any,
    *,
    depth: int = 0,
    _max_depth: int | None = None,
    _top_level: bool = False,
    _event_top_level: bool = False,
    _choice_top_level: bool = False,
) -> list[str]:
    """Walk a nested JSON-shaped object, returning all inspectable strings.

    Round 9 ``sse-delta-fields-default-allow`` and
    ``sse-tool-call-function-description-uninspected`` closure: the
    pre-fix ``_flush_event`` allowlisted a fixed set of delta string
    fields (``content``, ``refusal``, ``reasoning``,
    ``reasoning_content``, ``audio.transcript``) and tool-call sub-
    fields (``function.name``, ``function.arguments``); every other
    string-valued field was silently bypassed (``delta.thinking``,
    ``delta.audio.text``, ``delta.private_reasoning``,
    ``tool_calls[*].function.description``, etc.). New OpenAI-
    compatible features ship faster than that allowlist updates.

    Post-fix: walk the dict / list recursively. Every string value
    not under a key in :data:`_SSE_DELTA_STRUCTURAL_KEYS` (at the top
    level only, per the Round 11 fix) is inspected. This converts the
    allowlist into a denylist of top-level structural fields, so new
    text-bearing fields ship safe-by-default.

    Round 11 ``sse-delta-recursive-walk-depth-bypass`` closure: the
    pre-fix ``_max_depth=6`` cap silently returned ``[]`` for content
    at depth 7+, while the raw SSE bytes carrying the deep-nested
    payload were already buffered and would be yielded to the client.
    The cap is raised to match :data:`_MAX_JSON_DEPTH` (so attackers
    can't exploit a smaller walker cap than the parser allows), and
    hitting the cap returns a result list with the ``_depth_exceeded``
    attribute set so the caller aborts the stream instead of fail-open
    truncating.

    Round 11 ``sse-delta-structural-keys-denylist-content-bypass``
    closure: structural-key skip is scoped to the TOP LEVEL only (the
    ``_top_level`` flag distinguishes the caller-provided delta from
    nested dicts) AND gated on
    :func:`_validate_top_level_structural_field` -- a misshapen
    structural value (e.g. ``delta.role = "(S//NF)"``) fails the
    contract, returns False from the validator, drops the skip, and
    inspects the string normally. Nested dicts are walked without any
    key-based skip: a key named ``finish_reason`` or ``type`` inside
    ``delta.tool_calls[0]`` is no longer a smuggle channel.

    Round 15 ``walker-ignores-bytes-bytearray-tuple`` closure
    (F-R15-9): JSON parses never produce ``bytes`` / ``bytearray`` /
    ``tuple`` types, but a subclass-override realtime live-bridge that
    constructs ``event`` dicts directly in Python from a non-JSON wire
    protocol (Cap'n Proto, MessagePack, a custom WS binary sub-
    protocol) could embed classified bytes in any of these value
    types and have them pass through inspection. ``bytes`` /
    ``bytearray`` values are utf-8 best-effort-decoded and the result
    (or a hex prefix for binary-only payloads) is appended for
    inspection; ``tuple`` values are walked as if they were ``list``.
    Tuples decoded from typed wire formats are the most common shape.
    """
    if _max_depth is None:
        _max_depth = _MAX_JSON_DEPTH
    if depth > _max_depth:
        # Return the typed sentinel so callers (``_flush_event``)
        # convert into ``malformed_event_seen=True`` and abort the
        # stream via ``upstream_delta_too_deep`` instead of silently
        # truncating inspection.
        return _DepthSentinelList()
    out: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            # Round 17 ``choices[i]-sibling-fields-uninspected`` (F-R17-1)
            # closure: when this walker is invoked on a choice dict with
            # ``_choice_top_level=True``, ``delta`` is intentionally
            # skipped here because the caller (``_flush_event``) walks it
            # separately with the delta-level structural contract. Other
            # siblings (``text``, ``message``, ``logprobs``, etc.) fall
            # through to the standard inspection / walk path below.
            if _choice_top_level and isinstance(key, str) and key == "delta":
                continue
            if _top_level and isinstance(key, str) and key in _SSE_DELTA_STRUCTURAL_KEYS:
                outcome = _validate_top_level_structural_field(key, value)
                if outcome == _STRUCTURAL_OK:
                    # Conformant structural value: skip the field. The
                    # value is a known structural token, not a text-
                    # bearing field, and the wire contract is upheld.
                    continue
                # _STRUCTURAL_ABORT and _STRUCTURAL_WALK both fall
                # through into the inspection / walk path below so the
                # value's strings reach the inspection pipeline. The
                # caller (``_flush_event``) additionally checks the
                # outcome and flags ``malformed_event_seen`` for
                # _STRUCTURAL_ABORT so the stream is aborted; we
                # intentionally inspect the strings too because the
                # _STRUCTURAL_WALK path is reached BEFORE the caller's
                # post-loop abort check and there is no harm in adding
                # the inspectable strings to ``out`` regardless.
            elif _event_top_level and isinstance(key, str) and key in _SSE_EVENT_STRUCTURAL_KEYS:
                # Round 15 ``sse-event-level-fields-bypass-inspection``
                # (F-R15-2) closure: event-level structural keys (e.g.
                # ``object``) get their own enum validator. Same
                # contract as delta-level: OK skips, ABORT/WALK fall
                # through. The caller (``_flush_event``) re-validates
                # the outcome separately so it can flag the malformed-
                # event abort path.
                outcome = _validate_event_top_level_structural_field(key, value)
                if outcome == _STRUCTURAL_OK:
                    continue
            elif _choice_top_level and isinstance(key, str) and key in _SSE_CHOICE_STRUCTURAL_KEYS:
                # Round 17 ``choices[i]-sibling-fields-uninspected``
                # (F-R17-1) closure: choice-level structural keys get
                # their own enum validator. Same contract as the delta-
                # and event-level paths above: OK skips, ABORT/WALK fall
                # through so the caller (``_flush_event``) can flag the
                # malformed-event abort path. Lifts the choice-level
                # ``finish_reason`` enum check that F-R17-4 documented
                # as missing.
                outcome = _validate_choice_structural_field(key, value)
                if outcome == _STRUCTURAL_OK:
                    continue
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, (bytes, bytearray)):
                # F-R15-9: best-effort utf-8 decode so bytes values
                # constructed by a live-bridge subclass from a typed
                # wire protocol still reach INSPECTION. Errors are
                # replaced rather than ignored so any partial-utf8
                # marker (e.g. a (S//NF) substring with one trailing
                # invalid byte) is still scannable. Defense in depth:
                # ``bytes()`` / decode shouldn't raise on bytes /
                # bytearray inputs, but a custom bytes-like subclass
                # with a hostile ``__bytes__`` could -- ``suppress``
                # drops the value rather than crashing the walker.
                with suppress(Exception):
                    out.append(bytes(value).decode("utf-8", errors="replace"))
            elif isinstance(value, (dict, list, tuple)):
                nested = _collect_inspectable_strings(value, depth=depth + 1, _max_depth=_max_depth)
                if isinstance(nested, _DepthSentinelList):
                    sentinel: list[str] = _DepthSentinelList()
                    sentinel.extend(out)
                    sentinel.extend(nested)
                    return sentinel
                out.extend(nested)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (bytes, bytearray)):
                # F-R15-9: matching defense-in-depth path for list /
                # tuple items. See the dict branch above for rationale.
                with suppress(Exception):
                    out.append(bytes(item).decode("utf-8", errors="replace"))
            elif isinstance(item, (dict, list, tuple)):
                nested = _collect_inspectable_strings(item, depth=depth + 1, _max_depth=_max_depth)
                if isinstance(nested, _DepthSentinelList):
                    sentinel = _DepthSentinelList()
                    sentinel.extend(out)
                    sentinel.extend(nested)
                    return sentinel
                out.extend(nested)
    return out


def _malformed_abort_tokens(buf: _SSEBuffer) -> tuple[str, str]:
    """Return the ``(reason_token, reason_detail)`` pair for a streaming
    abort triggered by a malformed SSE event.

    Round 11 ``sse-delta-recursive-walk-depth-bypass`` closure splits
    the abort token so dashboards can distinguish a JSON-parse-failure
    abort (``upstream_sse_malformed``) from a delta-too-deep abort
    (``upstream_delta_too_deep``). Both still route through
    :meth:`SignetApp._emit_upstream_error_abort` with the upstream
    status and land in the ``pipeline.upstream`` audit row.
    """
    if buf.delta_too_deep_seen:
        return (
            "upstream_delta_too_deep",
            (
                "upstream SSE delta exceeded the "
                f"{_MAX_JSON_DEPTH}-level nesting cap; aborting stream "
                "to prevent smuggled-content leak past the inspection "
                "walker"
            ),
        )
    return (
        "upstream_sse_malformed",
        (
            "upstream SSE event payload could not be parsed as JSON; "
            "aborting stream to prevent raw-byte leak"
        ),
    )


def _exceeds_json_depth(raw: bytes, *, limit: int = _MAX_JSON_DEPTH) -> bool:
    """Return True if the raw JSON bytes exceed ``limit`` nesting depth.

    Counts unescaped ``{``/``[`` openers vs ``}``/``]`` closers,
    respecting JSON string literals (so brackets inside strings don't
    bump the depth counter) and JSON's standard string escape rule
    (``\\"`` inside strings does not close the string). This is a
    structural scanner, not a parser -- it deliberately does not
    validate other JSON syntax. Callers run :func:`json.loads` after
    this check passes.

    The scanner is bounded by ``len(raw)`` so it cannot recurse and
    cannot OOM; it walks the bytes exactly once.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escape = False
    for byte in raw:
        if in_string:
            if escape:
                escape = False
                continue
            if byte == 0x5C:  # backslash
                escape = True
                continue
            if byte == 0x22:  # double quote
                in_string = False
            continue
        if byte == 0x22:  # double quote -- entering a string literal
            in_string = True
            continue
        if byte == 0x7B or byte == 0x5B:  # { or [
            depth += 1
            if depth > max_depth:
                max_depth = depth
                if max_depth > limit:
                    return True
        elif byte == 0x7D or byte == 0x5D:  # } or ]
            depth -= 1
    return max_depth > limit


def _contains_non_finite_float(obj: Any, _depth: int = 0) -> bool:
    """Recursively scan a JSON-decoded value for NaN / Infinity / -Infinity.

    Used by :meth:`SignetApp._admit` to refuse bodies that ``json.loads``
    happily parsed (Python permits the non-standard NaN/Infinity
    literals) but which httpx's strict JSON encoder would reject when
    forwarding to the upstream. Catching this here turns a confusing
    502 "upstream forward failed" into an honest 400 client error.

    Notes on safety:

    * ``json.loads`` produces tree-shaped structures (it never reuses a
      node), so we don't need an ``id(obj)`` visited-set for cycle
      detection on parsed bodies. The ``_depth`` ceiling is a belt-and-
      braces guard for callers who happen to feed in hand-built objects.
    * Booleans inherit from ``int``, not ``float``, so they don't trip
      the float branch. ``int`` values are always finite.
    """
    if _depth > _NON_FINITE_WALK_MAX_DEPTH:
        # Fail closed: deeper than we'll walk → treat as suspicious.
        return True
    if isinstance(obj, float):
        # ``math.isfinite`` is the canonical predicate; the literal
        # comparisons in the bug-report spec also work but are noisier.
        import math

        return not math.isfinite(obj)
    if isinstance(obj, dict):
        return any(_contains_non_finite_float(v, _depth + 1) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_non_finite_float(v, _depth + 1) for v in obj)
    return False


def _extract_redirect_host(location: str | None) -> str | None:
    """Extract just the host portion of a ``Location`` header value.

    Returns ``None`` when the location is missing, blank, or malformed.
    Deliberately drops the path, query, and fragment so the signet
    response never echoes raw redirect URLs back to the caller -- an
    attacker-controlled upstream could otherwise smuggle URL paths
    (PII, SSRF targets, etc.) into the response body through a 302
    redirect that signet trustfully reflected. The host alone is
    enough for operators to triage the misbehaving upstream.

    Both absolute (``https://evil.example.com/x``) and relative
    (``/login``) Location values are accepted: a relative redirect
    means the upstream is asking the client to go back to itself, so
    the host is unchanged. Returning ``None`` for that case lets the
    response body distinguish "redirect to <known host>" from
    "redirect to somewhere else entirely" without leaking the path.
    """
    if not location:
        return None
    location = location.strip()
    if not location:
        return None
    from urllib.parse import urlparse

    try:
        parsed = urlparse(location)
    except ValueError:
        return None
    host = parsed.netloc or None
    # Strip optional ``userinfo@`` prefix so a hostile Location of
    # ``http://user:pass@victim.example.com/...`` does not leak the
    # creds through ``X-Signet-Upstream``-style attribution.
    if host and "@" in host:
        host = host.rsplit("@", 1)[-1] or None
    return host


def _walk_path(data: Any, path: tuple[Any, ...]) -> Any:
    """Walk a (key, key, ...) path through nested dict/list, returning ``None``
    if any step is missing or the wrong type. Used by :meth:`_forward_unary`
    to extract the response text from upstreams of different shapes
    (chat → choices[0].message.content, completions → choices[0].text)."""
    cur = data
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        elif isinstance(cur, list) and isinstance(key, int) and 0 <= key < len(cur):
            cur = cur[key]
        else:
            return None
        if cur is None:
            return None
    return cur


#: SSE field-name prefixes that ``_SSEBuffer`` will scan when
#: ``inspect_all_sse_lines`` is enabled (S6). The bare ``:`` prefix is
#: the SSE comment shape; everything else is a per-spec field.
#: ``data:`` is always scanned regardless of the flag.
_SSE_NON_DATA_PREFIXES: tuple[str, ...] = ("event:", "id:", "retry:", ":")

#: Round 7 ``sse-non-content-fields-uninspected`` documented the
#: historical allowlist of OpenAI streaming delta fields that carry
#: inspectable text (``content``, ``refusal``, ``reasoning``,
#: ``reasoning_content``, ``audio.transcript``) plus
#: ``tool_calls[*].function.{name,arguments}``. Round 9
#: ``sse-delta-fields-default-allow`` superseded the allowlist with
#: the default-deny recursive walk in
#: :func:`_collect_inspectable_strings`, so this module no longer
#: carries the field list as a constant — the walk inspects every
#: string under ``delta.*`` unless its key is in
#: :data:`_SSE_DELTA_STRUCTURAL_KEYS`.


class _SSEBuffer:
    """Per-stream SSE re-assembler.

    Round 7 ``sse-chunk-boundary-bypass`` closure. Pre-fix
    ``_extract_sse_content`` was stateless across ``aiter_bytes()``
    chunks: a ``data:`` line split across raw byte chunks (TLS records,
    HTTP/2 frames, MTU-sized segments) left ``accumulated_text`` empty,
    so ``ScopeDriftCheck`` / ``RegexOutputCheck`` were blind while the
    raw bytes were still forwarded to the client.

    Post-fix: the buffer is allocated once per stream and fed every
    chunk in order. It holds any trailing partial line in
    ``_pending_line`` and any unfinished event's ``data:`` payloads in
    ``_pending_data`` until a real ``\\n``-or-``\\r\\n`` terminator
    arrives. Complete events are parsed exactly once and the resulting
    text is returned to the caller, who then calls
    ``ResponseContext.extend_text`` so INSPECTION sees the full content.

    Buffer caps:

    * ``_pending_line`` is bounded by ``_MAX_STREAM_CHUNK_BYTES`` so a
      hostile upstream cannot OOM the proxy by sending one infinite
      line with no terminator (otherwise the inner re-assembly would
      grow without bound).
    * ``_pending_data`` is similarly bounded; an event whose assembled
      payload exceeds the cap is dropped and counted as malformed.

    The buffer is inspection-only: the proxy still forwards
    ``raw_chunk`` verbatim to the client. The byte stream the client
    sees never differs from what the upstream sent (except when
    inspection decides to abort, in which case the offending chunk is
    never yielded).

    ``dropped_frame_count`` is incremented every time ``_flush_event``
    catches a ``JSONDecodeError`` or the per-buffer caps trip; the
    streaming forward path surfaces this in the ``pipeline.complete``
    audit metadata (Round 7
    ``sse-malformed-event-silently-dropped`` closure).
    """

    def __init__(self, *, inspect_all_lines: bool = False) -> None:
        self._pending_line: str = ""
        self._pending_data: list[str] = []
        self._pending_data_bytes: int = 0
        self._inspect_all_lines: bool = inspect_all_lines
        self.dropped_frame_count: int = 0
        # F3 (streaming COMMITMENT): tool calls arrive fragmented across
        # SSE events -- ``function.name`` lands in the first delta for a
        # given ``index``, ``function.arguments`` accumulates over many
        # subsequent ones. Reassemble per index so the forward path can
        # run COMMITMENT against a real tool name.
        #
        # ``pending_tool_calls`` is a drain-queue of indices whose name
        # has just become known. Gating on FIRST SIGHT of the name (not
        # at ``finish_reason == "tool_calls"``) is deliberate: the tier
        # decision only needs the name, and refusing early means the
        # arguments never stream to the client at all. Waiting for the
        # complete call would leak every argument byte before the abort.
        self.tool_calls: dict[int, dict[str, str]] = {}
        self.pending_tool_calls: list[int] = []
        # Round 9 ``sse-unparseable-json-event-leaks-raw-bytes``
        # closure: when an event's assembled ``data:`` payload fails
        # JSON parse, the raw bytes had already been buffered by the
        # outer ``_forward_stream`` loop, which would forward them
        # verbatim to the client (the joined ``data: ...\ndata:
        # garbage`` smuggle pattern). The forward path now polls this
        # flag after each ``feed()`` and aborts the stream via
        # ``upstream_sse_malformed`` instead of releasing the raw
        # buffered bytes.
        self.malformed_event_seen: bool = False
        # Round 11 ``sse-delta-recursive-walk-depth-bypass`` closure:
        # set to True when ``_collect_inspectable_strings`` returns the
        # depth-exceeded sentinel for an event's delta tree. The
        # forward path treats this as ``malformed_event_seen`` for the
        # abort path AND substitutes the dedicated
        # ``upstream_delta_too_deep`` abort-reason token so dashboards
        # can split walker-cap aborts from JSON-parse-failure aborts.
        self.delta_too_deep_seen: bool = False

    def feed(self, chunk_text: str) -> str:
        """Glue the chunk to any prior partial line, emit completed events.

        Returns the concatenated inspectable text from every event
        whose terminating blank line landed in this chunk (or in a
        previous chunk's tail combined with this one). A chunk that
        ends mid-event produces an empty string; the data is held in
        ``_pending_data`` and emitted when the terminator arrives.
        """
        buf = self._pending_line + chunk_text
        self._pending_line = ""

        # If after gluing we still have an absurdly long unterminated
        # line, drop it and reset. This is the cap that protects the
        # inner re-assembly from an upstream that never terminates a
        # line.
        out: list[str] = []
        lines = buf.splitlines(keepends=True)
        for raw_line in lines:
            if not raw_line.endswith(("\n", "\r", "\r\n")):
                # Tail of the chunk -- save for the next call.
                if len(raw_line) > _MAX_STREAM_CHUNK_BYTES:
                    # Pathological: a single line longer than the per-
                    # chunk cap. Drop it; the stream will re-sync on
                    # the next ``\n``. Increment the malformed counter
                    # so operators see the failure mode.
                    self.dropped_frame_count += 1
                    self._pending_line = ""
                    continue
                self._pending_line = raw_line
                continue
            line = raw_line.rstrip("\r\n")
            if line == "":
                self._flush_event(out)
                continue
            if line.startswith("data:"):
                payload = line[len("data:") :]
                if payload.startswith(" "):
                    payload = payload[1:]
                self._pending_data.append(payload)
                self._pending_data_bytes += len(payload)
                if self._pending_data_bytes > _MAX_STREAM_CHUNK_BYTES:
                    # An assembled event larger than the per-chunk cap
                    # is dropped: re-assembling it would exhaust memory
                    # and JSON parsing would explode the working set.
                    self.dropped_frame_count += 1
                    self._pending_data.clear()
                    self._pending_data_bytes = 0
                continue
            if self._inspect_all_lines:
                for prefix in _SSE_NON_DATA_PREFIXES:
                    if line.startswith(prefix):
                        extra = line[len(prefix) :]
                        if extra.startswith(" "):
                            extra = extra[1:]
                        if extra:
                            out.append(extra)
                        break
        # NOTE: deliberately do NOT call ``_flush_event`` at end-of-
        # chunk. A ``data:`` line whose JSON value happens to span this
        # chunk boundary has not been fully received yet; we wait for
        # the blank-line dispatch in a later chunk.
        return "".join(out)

    def finalize(self) -> str:
        """Flush any pending event at end-of-stream.

        Some upstreams omit the trailing blank line on the last event;
        the streaming forward path calls this once after
        ``aiter_bytes()`` exhausts so any tail event still gets seen.
        """
        out: list[str] = []
        if self._pending_line:
            # Treat a terminator-less tail as a complete line if it
            # happens to be a ``data:`` line. Otherwise discard.
            line = self._pending_line.rstrip("\r\n")
            self._pending_line = ""
            if line.startswith("data:"):
                payload = line[len("data:") :]
                if payload.startswith(" "):
                    payload = payload[1:]
                self._pending_data.append(payload)
        self._flush_event(out)
        return "".join(out)

    def _accumulate_tool_calls(self, obj: dict[str, Any]) -> None:
        """Reassemble fragmented ``delta.tool_calls[]`` across SSE events.

        Queues an index onto :attr:`pending_tool_calls` the first time a
        non-empty ``function.name`` is seen for it, so the forward path
        can gate before the arguments finish streaming.

        Defensive throughout: a hostile or merely sloppy upstream can
        send a non-list ``tool_calls``, a missing ``index``, or a name
        split across events. Anything unparseable is skipped rather than
        raised -- this runs inside the inspection path and must never be
        the reason a stream dies.
        """
        choices = obj.get("choices")
        if not isinstance(choices, list):
            return

        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            fragments = delta.get("tool_calls")
            if not isinstance(fragments, list):
                continue

            for frag in fragments:
                if not isinstance(frag, dict):
                    continue
                raw_index = frag.get("index", 0)
                # bool is an int subclass; reject it explicitly.
                if isinstance(raw_index, bool) or not isinstance(raw_index, int):
                    continue
                fn = frag.get("function")
                if not isinstance(fn, dict):
                    continue

                slot = self.tool_calls.setdefault(raw_index, {"name": "", "arguments": ""})

                name_frag = fn.get("name")
                if isinstance(name_frag, str) and name_frag:
                    had_name = bool(slot["name"])
                    # Some shims split the name across events; concatenate
                    # rather than overwrite so a two-part name resolves.
                    slot["name"] += name_frag
                    if not had_name:
                        self.pending_tool_calls.append(raw_index)

                args_frag = fn.get("arguments")
                if isinstance(args_frag, str):
                    slot["arguments"] += args_frag

    def _flush_event(self, out: list[str]) -> None:
        if not self._pending_data:
            return
        payload = "\n".join(self._pending_data)
        self._pending_data.clear()
        self._pending_data_bytes = 0
        if payload in ("[DONE]", ""):
            return
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            # Round 9 ``sse-unparseable-json-event-leaks-raw-bytes``
            # closure: pre-fix swallowed the parse error and counted
            # ``dropped_frame_count`` only, while the outer raw-byte
            # forward path released the event's raw bytes to the
            # client (the multi-``data:`` smuggle pattern). Flag the
            # malformed-event condition so the forward path can abort
            # via ``_emit_upstream_error_abort(reason="upstream_sse_
            # malformed")`` BEFORE the bytes leak.
            self.dropped_frame_count += 1
            self.malformed_event_seen = True
            return
        if not isinstance(obj, dict):
            self.dropped_frame_count += 1
            self.malformed_event_seen = True
            return

        self._accumulate_tool_calls(obj)

        # Round 15 ``sse-event-level-fields-bypass-inspection`` closure
        # (F-R15-2): pre-fix the HTTP SSE path inspected ONLY
        # ``choices[i].delta``. Event-level siblings -- ``id``,
        # ``system_fingerprint``, ``model``, ``error.message``,
        # ``usage`` (non-int leaf strings if a vendor adds them), and
        # any non-standard top-level field -- were forwarded verbatim
        # with their raw bytes already buffered in the outer chunk
        # buffer. The realtime/WS path (R14) walks the FULL event
        # dict; the asymmetry let a hostile upstream (or any upstream
        # populating these fields with classified content -- vendor
        # fingerprints, error bodies, multi-tenant model strings)
        # smuggle a marker past INSPECTION on the HTTP path.
        #
        # Post-fix: walk the whole event dict via
        # :func:`_collect_inspectable_strings` with the event-level
        # structural-key skip set. The ``choices`` array is excluded
        # from this walk because its contents are inspected with the
        # delta-level structural contract below; including it here
        # would either double-inspect every delta string (cheap but
        # noisy) or require the walker to know about choices internals.
        # Stripping ``choices`` at this layer is the minimal-coupling
        # split.
        event_for_inspection = {k: v for k, v in obj.items() if k != "choices"}
        # Validate event-level structural fields ahead of the walk so a
        # hostile upstream's wrong-VALUE in (e.g.) ``object`` -- a
        # closed-enum field that ought to be ``chat.completion.chunk``
        # / ``chat.completion`` / ``text_completion`` -- aborts the
        # stream rather than slipping through with the marker.
        saw_event_structural_abort = False
        for ek, ev in event_for_inspection.items():
            if (
                isinstance(ek, str)
                and ek in _SSE_EVENT_STRUCTURAL_KEYS
                and _validate_event_top_level_structural_field(ek, ev) == _STRUCTURAL_ABORT
            ):
                saw_event_structural_abort = True
                break
        event_strings = _collect_inspectable_strings(event_for_inspection, _event_top_level=True)
        if isinstance(event_strings, _DepthSentinelList):
            # Mirror the delta-level depth-sentinel behavior: the
            # outer raw bytes are already buffered, so abort via the
            # same ``upstream_delta_too_deep`` path rather than fail-
            # open truncating.
            out.extend(event_strings)
            self.dropped_frame_count += 1
            self.malformed_event_seen = True
            self.delta_too_deep_seen = True
            return
        out.extend(event_strings)
        if saw_event_structural_abort:
            self.dropped_frame_count += 1
            self.malformed_event_seen = True
            return

        choices = obj.get("choices")
        if not isinstance(choices, list):
            return
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            # Round 17 ``choices[i]-sibling-fields-uninspected`` (F-R17-1)
            # closure: walk the choice dict (minus ``delta``, which is
            # walked separately with the delta-level structural contract
            # below) so siblings of ``delta`` reach INSPECTION. Pre-fix
            # ``choices[i].text`` (``/v1/completions`` legacy streaming),
            # ``choices[i].message.content`` (chat.completion buffered-
            # as-SSE), ``choices[i].logprobs.content[].token``, and the
            # choice-level ``finish_reason`` were all skipped: F-R15-2
            # stripped ``choices`` from the event-top walk to avoid
            # double-walking ``delta``, but the matching choice-level
            # loop only re-included ``delta``. Same walker-scope class
            # as F-R15-2, one level deeper into the event tree.
            #
            # Validate choice-level structural fields ahead of the walk
            # so a wrong-VALUE in (e.g.) ``choices[i].finish_reason``
            # (right type, not in the enum -- a smuggle vector when the
            # marker is relocated from ``delta.finish_reason`` to the
            # choice-level field) aborts the stream via the malformed
            # event path rather than slipping through.
            saw_choice_structural_abort = False
            for ck, cv in choice.items():
                if (
                    isinstance(ck, str)
                    and ck in _SSE_CHOICE_STRUCTURAL_KEYS
                    and _validate_choice_structural_field(ck, cv) == _STRUCTURAL_ABORT
                ):
                    saw_choice_structural_abort = True
                    break
            choice_strings = _collect_inspectable_strings(choice, _choice_top_level=True)
            if isinstance(choice_strings, _DepthSentinelList):
                # Mirror the delta-level depth-sentinel behavior: the
                # outer raw bytes are already buffered, so abort via the
                # same ``upstream_delta_too_deep`` path rather than
                # fail-open truncating.
                out.extend(choice_strings)
                self.dropped_frame_count += 1
                self.malformed_event_seen = True
                self.delta_too_deep_seen = True
                return
            out.extend(choice_strings)
            if saw_choice_structural_abort:
                self.dropped_frame_count += 1
                self.malformed_event_seen = True
                return

            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            # Round 9 ``sse-delta-fields-default-allow`` /
            # ``sse-tool-call-function-description-uninspected``
            # closure: default-deny via recursive walk. Every string
            # value under ``delta`` (and nested dicts / lists) is
            # inspected unless the field's key is in
            # :data:`_SSE_DELTA_STRUCTURAL_KEYS` AND the structural
            # field's value matches its enumerated wire contract
            # (Round 11 ``sse-delta-structural-keys-denylist-content-
            # bypass`` closure -- the skip is now scoped to the
            # top-level delta only and is gated on a per-field
            # validator). Replaces the pre-fix fixed allowlist of
            # ``content`` / ``refusal`` / ``reasoning`` /
            # ``reasoning_content`` / ``audio.transcript`` +
            # ``tool_calls[*].function.{name, arguments}`` which
            # silently bypassed any new upstream text-bearing field
            # (``thinking``, ``audio.text``, ``private_reasoning``,
            # ``function.description``, etc.).
            #
            # Round 11 ``sse-delta-structural-keys-denylist-content-
            # bypass`` closure: also check the validator's outcome
            # for every top-level structural key. If any structural
            # key carries a wrong-VALUE (e.g. ``delta.role="(S//NF)"``
            # — right type, not in the enumerated set) flag the event
            # as malformed so the forward path aborts the stream.
            # ``_STRUCTURAL_WALK`` (wrong type entirely, e.g.
            # ``delta.type={"nested":"(S//NF)"}``) is not flagged
            # here — the walker inspects the nested strings via the
            # standard inspection pipeline so any embedded marker is
            # caught by the INSPECTION block path.
            saw_structural_abort = False
            for s_key, s_value in delta.items():
                if (
                    isinstance(s_key, str)
                    and s_key in _SSE_DELTA_STRUCTURAL_KEYS
                    and _validate_top_level_structural_field(s_key, s_value) == _STRUCTURAL_ABORT
                ):
                    saw_structural_abort = True
                    break
            collected = _collect_inspectable_strings(delta, _top_level=True)
            if isinstance(collected, _DepthSentinelList):
                # Round 11 ``sse-delta-recursive-walk-depth-bypass``
                # closure: the walker hit the recursion cap. The deep
                # bytes are already in the outer raw buffer and would
                # leak when the next terminator arrives; flag the
                # depth-exceeded condition so the forward path aborts
                # via ``upstream_delta_too_deep`` instead of fail-open
                # truncating inspection. Any strings the walker did
                # collect before tripping the cap are still added so
                # cross-chunk inspection accounting stays consistent.
                out.extend(collected)
                self.dropped_frame_count += 1
                self.malformed_event_seen = True
                self.delta_too_deep_seen = True
                return
            out.extend(collected)
            if saw_structural_abort:
                self.dropped_frame_count += 1
                self.malformed_event_seen = True
                return


def _extract_sse_content(chunk_text: str, *, inspect_all_lines: bool = False) -> str:
    """Single-shot SSE content extractor (legacy, no cross-chunk state).

    Round 7: the streaming forward path uses :class:`_SSEBuffer`
    directly so cross-chunk events survive. This thin wrapper preserves
    the historical function signature for callers that pass a whole
    SSE payload in one string (unit tests, the realtime handler's
    one-shot inspection path) -- it just builds a one-off buffer and
    finalizes it.

    Per the WHATWG EventSource spec, multiple consecutive ``data:``
    lines within a single event get joined with ``\\n`` before being
    delivered. OpenAI ships one event per data line so this almost
    never matters in practice, but other OpenAI-compatible upstreams
    (LiteLLM, vLLM with prompt-streaming) do emit multi-line events.
    Coalesce them so INSPECTION sees the full text.
    """
    buf = _SSEBuffer(inspect_all_lines=inspect_all_lines)
    out = buf.feed(chunk_text)
    out += buf.finalize()
    return out
