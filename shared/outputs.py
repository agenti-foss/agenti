#!/usr/bin/env python3
"""
outputs.py — copy a finished report into the permanent Outputs store.

Promotion COPIES, never moves: a run's own reports/ folder is aged out by
retention.py on its own schedule, independent of what was kept. A name
collision is resolved with a short unique suffix rather than overwriting an
earlier kept file or refusing — two runs of one agent plausibly both produce
a file with the same name.

The quota gate (iam.outputs_check) is the `approve` callback: it is called
with the size of the very descriptor that is then copied, exactly that many
bytes, under a lock on the outputs folder, so a run growing the file after
the check, or two keeps at once, cannot overrun the quota (audit run 2). The
filename is confined with tool_registry.safe_path(), so a crafted name can
never escape the source folder.
"""

from __future__ import annotations

import fcntl
import os
import uuid
from typing import Callable
from pathlib import Path

from tool_registry import safe_path


class OutputsError(Exception):
    """A file could not be kept; the message says why and is safe to show."""


def _open_source(src_dir: Path, filename: str):
    """The file to keep, opened without following a link anywhere under the
    run's folder (audit run 1, F16): a link planted in reports/ cannot make
    root copy /etc/shadow into someone's kept outputs, and a file swapped in
    between a check and the copy is never the one copied."""
    import run_files
    try:
        return run_files.open_in_slot(Path(src_dir).parent, Path(Path(src_dir).name) / filename)
    except run_files.FilesError:
        raise OutputsError(f"no such file in this run: {filename!r}")


def promote_output(src_dir: Path, filename: str, dest_dir: Path, *,
                   approve: Callable[[int], None]) -> tuple[Path, int]:
    """Copy one file from `src_dir` into `dest_dir`; return (new path, bytes).
    `approve(size)` raises OutputsError to refuse (the quota gate)."""
    if safe_path(src_dir, filename) is None:
        raise OutputsError(f"no such file in this run: {filename!r}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    lock = os.open(dest_dir.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        fh, size = _open_source(src_dir, filename)
        with fh:
            approve(size)
            name = Path(filename).name
            dest = dest_dir / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            try:
                fd = os.open(dest, flags, 0o640)
            except FileExistsError:
                dest = dest_dir / f"{Path(name).stem}-{uuid.uuid4().hex[:8]}{Path(name).suffix}"
                fd = os.open(dest, flags, 0o640)
            try:
                with os.fdopen(fd, "wb") as out:
                    left = size
                    while left:
                        chunk = fh.read(min(1 << 20, left))
                        if not chunk:
                            raise OutputsError(f"{filename!r} got shorter while it was being kept; "
                                               f"try again once the run has finished writing it.")
                        out.write(chunk)
                        left -= len(chunk)
                    if fh.read(1):
                        raise OutputsError(f"{filename!r} grew while it was being kept; try again "
                                           f"once the run has finished writing it.")
            except BaseException:
                dest.unlink(missing_ok=True)
                raise
        return dest, size
    finally:
        os.close(lock)
