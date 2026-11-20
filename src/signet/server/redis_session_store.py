"""Redis-backed SessionStore -- multi-replica session state.

Drop-in replacement for :class:`signet.server.session.InMemorySessionStore`
when you run multiple signet replicas behind a load balancer and need
sessions to survive replica flips.

Requires ``pip install signet-sign[redis]``.

Usage::

    from signet.server.app import SignetApp
    from signet.server.redis_session_store import RedisSessionStore
    import redis

    store = RedisSessionStore(
        client=redis.Redis(host="redis.internal", decode_responses=True),
        prefix="signet:session:",
        ttl_seconds=3600,
    )
    app = SignetApp(config=cfg, pipeline=pipeline, session_store=store)

The ``ttl_seconds`` parameter sets each session's Redis TTL on every
write -- sessions inactive longer than that are evicted automatically
without any cleanup work in signet.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from signet.server.session import Session

if TYPE_CHECKING:
    import redis


class RedisSessionStore:
    """Session store backed by a Redis client.

    Stores each session as a JSON-encoded hash field at
    ``{prefix}{session_id}``. Session expiration is handled by Redis
    via per-key TTL; signet does not run a sweep loop.

    Args:
        client: A configured ``redis.Redis`` instance with
            ``decode_responses=True``. Caller owns the client's lifecycle
            (signet does not close it).
        prefix: Key prefix for all session entries. Allows multiple
            applications to share one Redis instance without colliding.
        ttl_seconds: TTL applied to each session on every write. After
            this many seconds of inactivity, Redis evicts the session.
            Default 1 hour. Set None to disable TTL (sessions persist
            forever, must be manually deleted).
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str = "signet:session:",
        ttl_seconds: int | None = 3600,
    ) -> None:
        self._client = client
        self._prefix = prefix
        self._ttl = ttl_seconds

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def _serialize(self, session: Session) -> str:
        return json.dumps(
            {
                "session_id": session.session_id,
                "created_at": session.created_at,
                "last_seen_at": session.last_seen_at,
                "request_count": session.request_count,
                "scratch": session.scratch,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def _deserialize(self, raw: str) -> Session:
        d: dict[str, Any] = json.loads(raw)
        return Session(
            session_id=d["session_id"],
            created_at=d["created_at"],
            last_seen_at=d["last_seen_at"],
            request_count=d["request_count"],
            scratch=d.get("scratch", {}),
        )

    def get(self, session_id: str) -> Session | None:
        # Sync redis-py returns str | None when decode_responses=True;
        # the type stubs leave the union open for the async client too.
        from typing import cast

        raw = cast("str | None", self._client.get(self._key(session_id)))
        if raw is None:
            return None
        return self._deserialize(raw)

    def get_or_create(self, session_id: str) -> Session:
        existing = self.get(session_id)
        if existing is not None:
            return existing
        now = time.time()
        new = Session(session_id=session_id, created_at=now, last_seen_at=now)
        key = self._key(session_id)
        payload = self._serialize(new)
        if self._ttl is not None:
            created = self._client.set(key, payload, ex=self._ttl, nx=True)
        else:
            created = self._client.set(key, payload, nx=True)
        if created:
            return new
        # Another replica created the session between our initial GET and SET NX.
        raced = self.get(session_id)
        return raced if raced is not None else new

    def save(self, session: Session) -> None:
        key = self._key(session.session_id)
        payload = self._serialize(session)
        if self._ttl is not None:
            self._client.set(key, payload, ex=self._ttl)
        else:
            self._client.set(key, payload)

    def delete(self, session_id: str) -> None:
        self._client.delete(self._key(session_id))


__all__ = ["RedisSessionStore"]
