"""Short-lived in-memory TTL cache for read-heavy API responses."""

from __future__ import annotations

import asyncio
from time import monotonic
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")

_store: dict[str, tuple[float, object]] = {}
_lock = asyncio.Lock()


async def get_or_set(
    key: str,
    ttl_seconds: float,
    factory: Callable[[], Awaitable[T]],
) -> T:
    now = monotonic()
    cached = _store.get(key)
    if cached is not None:
        expires_at, value = cached
        if now < expires_at:
            return value  # type: ignore[return-value]

    async with _lock:
        cached = _store.get(key)
        if cached is not None:
            expires_at, value = cached
            if monotonic() < expires_at:
                return value  # type: ignore[return-value]

        value = await factory()
        _store[key] = (monotonic() + ttl_seconds, value)
        return value


def invalidate_prefix(prefix: str) -> None:
    for key in list(_store):
        if key.startswith(prefix):
            del _store[key]
