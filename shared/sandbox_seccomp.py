"""
sandbox_seccomp.py — the syscall filter loaded into the analysis sandbox.

WHAT IT IS FOR
--------------
shared/sandbox.py already confines a program that is parsing a hostile file:
no network, no vault, read-only input, no capabilities, hard limits. What it
did not do was narrow what the program may ASK THE KERNEL for. The usual way
out of a container-like sandbox is not through the program's own files but
through a kernel bug reached from a rarely used system call, so the practical
defence is to take those calls away from a process that has no use for them.

This filter does that. It is applied by bubblewrap (`--seccomp FD`) at the
last moment, after the sandbox's own mounts and namespaces exist and just
before the program starts, and it is inherited by everything the program runs.

WHY A DENY-LIST, AND WHY THAT IS A DECISION, NOT A SHORTCUT
-----------------------------------------------------------
An allow-list ("only these 150 calls") is the stronger shape, and the wrong
one to ship blind: tshark, capinfos and Suricata between them use hundreds of
calls across glibc versions and code paths, and a missed one fails as a
confusing crash far from its cause. A filter that breaks real work gets
switched off, which is worse than a narrower filter that stays on. So the
policy is "allow, except these", where "these" are the calls that
  * load or replace kernel code (modules, kexec, bpf),
  * reach deep, rarely audited kernel subsystems (io_uring, perf, userfaultfd,
    the key store, raw netlink and the exotic socket families),
  * act on the host rather than the process (mount, chroot, reboot, the clock,
    the hostname, swap, quotas),
  * let a process inspect or steer another (ptrace, process_vm_*),
  * or create new namespaces (unshare, setns, clone with CLONE_NEW*), which is
    the standard stepping stone for kernel privilege-escalation exploits.
Nothing a packet or document parser legitimately needs is on that list, and the
test suite runs the real programs under it to prove it.

TWO DETAILS THAT ARE EASY TO GET WRONG
  * clone3 passes its flags in a struct the filter cannot read, so it cannot be
    filtered by flag. It is answered ENOSYS instead; glibc (2.34+, Rust's
    std, Python) then retries with plain clone, whose flags CAN be checked.
  * Other architectures: only the host's own syscall table is allowed. A
    process that switches to a 32-bit or x32 table to dodge the deny-list is
    killed (libseccomp's default for a non-matching architecture).

WHAT THIS IS NOT
  Not a replacement for the rest of the sandbox, and not an allow-list. A
  program can still make any call not named here; the namespaces, the empty
  capability set and the missing filesystem are what limit those.

It uses libseccomp through ctypes (standard library only; libseccomp2 is a
dependency of bubblewrap's neighbours and is installed with Suricata). If the
library is missing the sandbox REFUSES to run rather than run unfiltered —
the same stance as a missing bubblewrap.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import functools
import os
import tempfile

__all__ = ["SeccompUnavailable", "available", "build", "policy", "AF_ALLOWED"]

SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_CMP_MASKED_EQ = 7          # enum scmp_compare
EPERM, ENOSYS = 1, 38


def _errno(e: int) -> int:
    return 0x00050000 | (e & 0xFFFF)            # SCMP_ACT_ERRNO(e)


# Socket families a sandboxed parser may open: local, IPv4, IPv6. The network
# namespace has only loopback, so these cannot reach anything, but they are
# what libraries expect to be able to create. Every other family is refused:
# netlink, packet, the crypto API, vsock, bluetooth, CAN, ... are all kernel
# attack surface with no use here.
AF_ALLOWED = (1, 2, 10)                          # AF_UNIX, AF_INET, AF_INET6
_AF_MAX = 64

# clone(2) flags that create a new namespace.
_CLONE_NEW_FLAGS = {
    "CLONE_NEWNS": 0x00020000, "CLONE_NEWCGROUP": 0x02000000, "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000, "CLONE_NEWTIME": 0x00000080,
}

# group -> (why it is refused, syscall names). A name that does not exist on
# this architecture is skipped: if it is not there, it cannot be called.
_DENY: dict[str, tuple[str, tuple[str, ...]]] = {
    "kernel code": (
        "loading or replacing kernel code",
        ("init_module", "finit_module", "delete_module", "create_module", "get_kernel_syms",
         "query_module", "kexec_load", "kexec_file_load", "reboot")),
    "host state": (
        "changing the host, not the process: swap, quotas, the clock, the hostname, hardware ports",
        ("swapon", "swapoff", "acct", "quotactl", "quotactl_fd", "settimeofday", "stime",
         "clock_settime", "clock_settime64", "clock_adjtime", "clock_adjtime64", "adjtimex",
         "sethostname", "setdomainname", "syslog", "vhangup", "iopl", "ioperm",
         "pciconfig_read", "pciconfig_write", "pciconfig_iobase", "sysfs", "_sysctl",
         "nfsservctl", "lookup_dcookie", "ustat", "uselib", "modify_ldt", "vm86", "vm86old")),
    "mounts": (
        "building or changing the filesystem tree (the sandbox's own is already set up)",
        ("mount", "umount", "umount2", "pivot_root", "chroot", "move_mount", "open_tree",
         "open_tree_attr", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr")),
    "namespaces": (
        "creating or entering namespaces — the usual stepping stone for kernel exploits",
        ("unshare", "setns")),
    "other processes": (
        "inspecting or steering another process",
        ("ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_getfd")),
    "kernel attack surface": (
        "rarely audited kernel subsystems a parser has no use for",
        ("bpf", "perf_event_open", "userfaultfd", "io_uring_setup", "io_uring_enter",
         "io_uring_register", "keyctl", "add_key", "request_key", "open_by_handle_at",
         "name_to_handle_at", "fanotify_init", "fanotify_mark", "mbind", "set_mempolicy",
         "set_mempolicy_home_node", "migrate_pages", "move_pages")),
}


class SeccompUnavailable(RuntimeError):
    """libseccomp cannot be used here (missing, or the filter would not build).
    Raised rather than running a sandbox with no filter."""


class _ArgCmp(ctypes.Structure):
    # struct scmp_arg_cmp { unsigned int arg; enum scmp_compare op;
    #                       scmp_datum_t datum_a, datum_b; }
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


@functools.lru_cache(maxsize=1)
def _lib():
    name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    try:
        lib = ctypes.CDLL(name)
    except OSError as e:
        raise SeccompUnavailable(
            f"libseccomp is not installed ({e}). The analysis sandbox needs it for its syscall "
            f"filter and will not run without one: sudo apt install libseccomp2") from e
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                           ctypes.c_uint, ctypes.POINTER(_ArgCmp)]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_export_bpf.restype = ctypes.c_int
    return lib


def available() -> bool:
    try:
        _lib()
        return True
    except SeccompUnavailable:
        return False


def _resolve(lib, name: str) -> int | None:
    n = lib.seccomp_syscall_resolve_name(name.encode())
    return n if n >= 0 else None          # negative: absent on this architecture


def policy() -> list[tuple[str, str, list[str]]]:
    """(group, why, syscall names) for every refusal — what the docs and the
    tests describe. Includes the socket-family and clone rules."""
    out = [(g, why, list(names)) for g, (why, names) in _DENY.items()]
    out.append(("sockets", "address families other than local, IPv4 and IPv6 "
                f"(allowed: {', '.join(str(a) for a in AF_ALLOWED)})", ["socket", "socketpair"]))
    out.append(("clone", "clone with any CLONE_NEW* flag; clone3 answers ENOSYS so libc falls back to clone",
                ["clone", "clone3"]))
    return out


@functools.lru_cache(maxsize=1)
def build() -> bytes:
    """The compiled BPF program (a multiple of 8 bytes: one sock_filter each).
    Cached: the policy is code, so it is the same for every run."""
    lib = _lib()
    ctx = lib.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise SeccompUnavailable("libseccomp could not create a filter context")
    try:
        def add(action: int, name: str, args: list[_ArgCmp] | None = None) -> None:
            nr = _resolve(lib, name)
            if nr is None:
                return
            arr = (_ArgCmp * len(args))(*args) if args else None
            rc = lib.seccomp_rule_add_array(ctx, action, nr, len(args or []), arr)
            if rc != 0:
                raise SeccompUnavailable(f"libseccomp refused the rule for {name} (error {rc})")

        for _, (_why, names) in _DENY.items():
            for name in names:
                add(_errno(EPERM), name)

        # Sockets: refuse every family that is not local/IPv4/IPv6. Compared on
        # the LOW 32 bits only: the kernel reads the family as an int, so a
        # plain 64-bit equality let 0x1_0000_0010 (netlink with a high bit set)
        # slip past the rule and still open a netlink socket (audit run 1, F38).
        for fam in range(0, _AF_MAX):
            if fam in AF_ALLOWED:
                continue
            eq = _ArgCmp(0, SCMP_CMP_MASKED_EQ, 0xFFFFFFFF, fam)
            add(_errno(EPERM), "socket", [eq])
            add(_errno(EPERM), "socketpair", [eq])

        # clone: refuse any call that asks for a new namespace. One rule per
        # flag, because "any bit set" is not a single comparison.
        for bit in _CLONE_NEW_FLAGS.values():
            add(_errno(EPERM), "clone", [_ArgCmp(0, SCMP_CMP_MASKED_EQ, bit, bit)])
        add(_errno(ENOSYS), "clone3")

        with tempfile.TemporaryFile() as fh:
            rc = lib.seccomp_export_bpf(ctx, fh.fileno())
            if rc != 0:
                raise SeccompUnavailable(f"libseccomp could not compile the filter (error {rc})")
            fh.seek(0)
            prog = fh.read()
    finally:
        lib.seccomp_release(ctx)
    if not prog or len(prog) % 8:
        raise SeccompUnavailable("libseccomp produced a malformed filter")
    return prog
