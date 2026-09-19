"""Cross-platform subset of :mod:`fcntl` used by the engine for advisory file locks.

The engine originally targeted Linux only and used ``fcntl.flock`` directly. To run
the engine natively on Windows (see the Android-research port), this module provides a
drop-in ``flock`` plus the ``LOCK_*`` constants, backed by ``fcntl`` on POSIX and by
``msvcrt.locking`` on Windows. Call sites keep using ``fcntl.flock(handle, LOCK_EX)``
via ``from . import oslock as fcntl``.

Semantics match the engine's usage: an exclusive, blocking lock on an open lock-file
handle that is released when the handle is closed (every current call site relies on
``with open(...) as f`` for release rather than an explicit ``LOCK_UN``).
"""

from __future__ import annotations

import os
import time

try:  # POSIX
    import fcntl as _fcntl

    LOCK_EX = _fcntl.LOCK_EX
    LOCK_SH = _fcntl.LOCK_SH
    LOCK_UN = _fcntl.LOCK_UN
    LOCK_NB = _fcntl.LOCK_NB

    def flock(handle, operation: int) -> None:
        _fcntl.flock(handle, operation)

except ImportError:  # Windows
    import msvcrt

    # Values mirror POSIX so callers can OR flags; only the meaning below is used.
    LOCK_SH = 0x1
    LOCK_EX = 0x2
    LOCK_NB = 0x4
    LOCK_UN = 0x8

    _LOCK_BYTES = 1
    _BLOCKING_DEADLINE_SECONDS = 30.0

    def _fileno(handle) -> int:
        return handle if isinstance(handle, int) else handle.fileno()

    def _lock_region_start(handle, fd: int) -> int:
        # Contend on byte 0 so every locker of the same file collides. Rewind the
        # handle (dedicated lock files carry no meaningful content) so the lock
        # region is deterministic regardless of prior writes.
        try:
            if not isinstance(handle, int) and hasattr(handle, "seek"):
                handle.seek(0)
            else:
                os.lseek(fd, 0, os.SEEK_SET)
        except (OSError, ValueError):
            pass
        return 0

    def flock(handle, operation: int) -> None:
        fd = _fileno(handle)
        if operation & LOCK_UN:
            try:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_BYTES)
            except OSError:
                pass
            return
        _lock_region_start(handle, fd)
        nonblocking = bool(operation & LOCK_NB)
        deadline = time.monotonic() + _BLOCKING_DEADLINE_SECONDS
        while True:
            try:
                # msvcrt has no shared-lock concept; a shared request is satisfied
                # by an exclusive lock (safe, merely less concurrent).
                mode = msvcrt.LK_NBLCK if nonblocking else msvcrt.LK_LOCK
                msvcrt.locking(fd, mode, _LOCK_BYTES)
                return
            except OSError:
                # LK_LOCK already retries internally for ~10s before raising; extend
                # the effective blocking window, then give up like a failed flock.
                if nonblocking or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
