#!/usr/bin/env python3
"""Read-only Linux inactive-path guard; stdout is emitted only for safe observations.

openat2 prohibits mount crossings (including same-device binds) and symlinks.
statx binds every retained descriptor to its mount and inode. No path-based
listing, syscall fallback, retry, or mutation is permitted. This is an admission
observation, not a lock or an atomic guarantee about subsequent operations.
"""

import ctypes
import errno
import json
import os
import platform
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass


class UnsafeObservation(RuntimeError):
    """Unsupported, unsafe, unstable, or incomplete observation."""


class OpenHow(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("flags", "mode", "resolve")]


class StatxTimestamp(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_int64), ("nsec", ctypes.c_uint32),
                ("reserved", ctypes.c_int32)]


class Statx(ctypes.Structure):
    # Linux UAPI struct statx: retain the fixed 256-byte ABI, ignoring newer fields.
    _fields_ = [
        ("mask", ctypes.c_uint32), ("blksize", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64), ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16), ("spare0", ctypes.c_uint16),
        ("ino", ctypes.c_uint64), ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
        ("atime", StatxTimestamp), ("btime", StatxTimestamp),
        ("ctime", StatxTimestamp), ("mtime", StatxTimestamp),
        ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32),
        ("mnt_id", ctypes.c_uint64), ("spare", ctypes.c_uint64 * 13),
    ]


@dataclass(frozen=True)
class Identity:
    mount: int
    device: tuple
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    ctime: tuple
    mtime: tuple

    def require_trusted_directory(self):
        if (not stat.S_ISDIR(self.mode) or self.uid != 0 or self.gid != 0
                or self.mode & 0o022 or self.links < 1 or self.mount <= 0
                or self.inode <= 0):
            raise UnsafeObservation("untrusted directory metadata")


class LinuxDescriptors:
    """Fixed x86_64 Linux ABI; the contracted Debian 6.12 kernel supports both APIs."""

    RESOLVE = 0x01 | 0x04  # NO_XDEV | NO_SYMLINKS (also forbids magic links)
    STATX_MASK = 0x07FF | 0x1000  # BASIC_STATS | MNT_ID (Linux >= 5.8)

    def __init__(self):
        if sys.platform != "linux" or platform.machine() != "x86_64":
            raise UnsafeObservation("requires Linux x86_64 openat2/statx")
        self.libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(self.libc, "statx") or ctypes.sizeof(Statx) != 256:
            raise UnsafeObservation("statx ABI unavailable")
        self.libc.syscall.restype = ctypes.c_long
        self.libc.statx.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                   ctypes.c_uint, ctypes.POINTER(Statx)]
        self.libc.statx.restype = ctypes.c_int

    def _open(self, parent, name, readable=False):
        flags = (os.O_RDONLY | os.O_NONBLOCK if readable else os.O_PATH)
        how = OpenHow(flags | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0, self.RESOLVE)
        result = self.libc.syscall(ctypes.c_long(437), ctypes.c_int(parent),
                                   ctypes.c_char_p(os.fsencode(name)),
                                   ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
        if result < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return result

    def root(self):
        return self._open(-100, "/")  # AT_FDCWD; only absolute lookup in the walk

    def child(self, parent, name, readable=False):
        return self._open(parent, name, readable)

    def identity(self, fd):
        value = Statx()
        # AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT; no pathname lookup.
        result = self.libc.statx(fd, b"", 0x1000 | 0x100 | 0x800,
                                 self.STATX_MASK, ctypes.byref(value))
        if result != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        if value.mask & self.STATX_MASK != self.STATX_MASK:
            raise UnsafeObservation("incomplete statx metadata or mount identity")
        return Identity(value.mnt_id, (value.dev_major, value.dev_minor), value.ino,
                        value.mode, value.uid, value.gid, value.nlink, value.size,
                        (value.ctime.sec, value.ctime.nsec),
                        (value.mtime.sec, value.mtime.nsec))

    @staticmethod
    def empty(fd):
        # Never stat/open any child, and bound enumeration to at most one entry.
        with os.scandir(fd) as entries:
            return next(entries, None) is None

    @staticmethod
    def close(fd):
        os.close(fd)


def observe(target, backend=None):
    if (not isinstance(target, str) or not target.startswith("/")
            or "\x00" in target or any(part in ("", ".", "..")
                                      for part in target.split("/")[1:])):
        raise UnsafeObservation("requires a canonical absolute non-root path")
    backend = LinuxDescriptors() if backend is None else backend
    parts = target.split("/")[1:]
    with ExitStack() as stack:
        def retain(fd):
            stack.callback(backend.close, fd)
            return fd

        root = retain(backend.root())
        first = backend.identity(root)
        first.require_trusted_directory()
        chain = [(root, first)]
        missing = None
        for name in parts:
            parent, parent_identity = chain[-1]
            try:
                child = retain(backend.child(parent, name))
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
                missing = name
                break
            identity = backend.identity(child)
            identity.require_trusted_directory()
            if identity.mount != parent_identity.mount:
                raise UnsafeObservation("mount crossing")
            chain.append((child, identity))

        def stable():
            # Reopen each edge relative to pinned ancestors; compare both the old
            # descriptor and current name. A renamed/unlinked/overmounted ancestor
            # must not turn a detached empty directory into admission evidence.
            with ExitStack() as checks:
                def temporary(fd):
                    checks.callback(backend.close, fd)
                    return fd

                current_root = temporary(backend.root())
                if backend.identity(current_root) != first:
                    raise UnsafeObservation("root identity changed")
                for index, (fd, identity) in enumerate(chain):
                    if backend.identity(fd) != identity:
                        raise UnsafeObservation("directory metadata changed")
                    if index:
                        current = temporary(backend.child(chain[index - 1][0], parts[index - 1]))
                        if backend.identity(current) != identity:
                            raise UnsafeObservation("directory name identity changed")
                if missing is not None:
                    try:
                        temporary(backend.child(chain[-1][0], missing))
                    except OSError as error:
                        if error.errno != errno.ENOENT:
                            raise
                    else:
                        raise UnsafeObservation("absent component appeared")
                    if backend.identity(chain[-1][0]) != chain[-1][1]:
                        raise UnsafeObservation("absent component parent changed")

        stable()
        if missing is None:
            target_fd, identity = chain[-1]
            readable = retain(backend.child(target_fd, ".", readable=True))
            if backend.identity(readable) != identity:
                raise UnsafeObservation("enumeration descriptor identity changed")
            if not backend.empty(readable):
                raise UnsafeObservation("inactive directory is nonempty")
            if backend.identity(readable) != identity:
                raise UnsafeObservation("directory changed during enumeration")
        stable()
        return {"exists": missing is None, "entry_count": 0 if missing is None else None}


def main(argv):
    try:
        if len(argv) != 1:
            raise UnsafeObservation("requires exactly one protected path")
        result = observe(argv[0])
    except (UnsafeObservation, OSError, ValueError, AttributeError) as error:
        print("inactive-path observation refused: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
