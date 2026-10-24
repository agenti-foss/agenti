#!/usr/bin/env python3
"""test_sandbox_seccomp.py — the syscall filter (shared/sandbox_seccomp.py).

    python3 shared/test_sandbox_seccomp.py

No root, no vault, no SDK. Two halves:

  1. POLICY, anywhere libseccomp exists: the compiled program is run through a
     small BPF interpreter written here, and the exact decision for each
     (architecture, syscall, arguments) is asserted. Needs no kernel support,
     so it runs on CI.
  2. LIVE, where bubblewrap works: real calls attempted from inside the
     sandbox. Every refusal is paired with a CONTROL — the same call with the
     filter switched off — whose result is DIFFERENT, so "it failed" cannot be
     mistaken for "the kernel would have refused anyway". Ordinary work (a
     thread, a fork, a child process, a socket) is also proven to still work,
     because a filter that breaks real programs gets turned off.

Skips loudly (never passes silently) when libseccomp or bubblewrap is absent.
"""
import dataclasses
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sandbox  # noqa: E402
import sandbox_seccomp as sc  # noqa: E402

PASS = FAIL = SKIP = 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(f"  [ OK ] {label}")
    else:
        FAIL += 1; print(f"  [FAIL] {label}\n         got  {got!r}\n         want {want!r}")


def skip(label, why):
    global SKIP
    SKIP += 1; print(f"  [SKIP] {label} — {why}")


def section(t): print(f"\n=== {t} ===")


# ---------------------------------------------------------------------------
# A BPF interpreter — just enough for the programs libseccomp emits.
# ---------------------------------------------------------------------------
RET_ALLOW = 0x7FFF0000


def errno_ret(e): return 0x00050000 | e


def bpf_run(prog: bytes, arch: int, nr: int, args=()) -> int:
    insns = [struct.unpack("<HBBI", prog[i:i + 8]) for i in range(0, len(prog), 8)]
    a = (list(args) + [0] * 6)[:6]
    data = struct.pack("<IIQ6Q", nr & 0xFFFFFFFF, arch, 0, *[x & 0xFFFFFFFFFFFFFFFF for x in a])
    A = X = 0
    mem = [0] * 16
    pc = 0
    for _ in range(100000):
        code, jt, jf, k = insns[pc]
        pc += 1
        cls = code & 7
        if cls == 0:                                    # LD
            mode = code & 0xE0
            if mode == 0x20:   A = struct.unpack_from("<I", data, k)[0]
            elif mode == 0x60: A = mem[k]
            elif mode == 0x00: A = k
            elif mode == 0x80: A = len(data)
            else: raise NotImplementedError(f"LD mode {mode:#x}")
        elif cls == 1:                                  # LDX
            mode = code & 0xE0
            if mode == 0x60:   X = mem[k]
            elif mode == 0x00: X = k
            else: raise NotImplementedError(f"LDX mode {mode:#x}")
        elif cls == 2: mem[k] = A                       # ST
        elif cls == 3: mem[k] = X                       # STX
        elif cls == 4:                                  # ALU
            op, src = code & 0xF0, (X if code & 0x08 else k)
            A = {0x00: A + src, 0x10: A - src, 0x20: A * src, 0x40: A | src, 0x50: A & src,
                 0x60: A << src, 0x70: A >> src, 0xA0: A ^ src}.get(op)
            if A is None: raise NotImplementedError(f"ALU op {op:#x}")
            A &= 0xFFFFFFFF
        elif cls == 5:                                  # JMP
            op, src = code & 0xF0, (X if code & 0x08 else k)
            if op == 0x00: pc += k
            else:
                hit = {0x10: A == src, 0x20: A > src, 0x30: A >= src, 0x40: bool(A & src)}[op]
                pc += jt if hit else jf
        elif cls == 6:                                  # RET
            return A if code & 0x10 else k
        else:
            raise NotImplementedError(f"class {cls}")
    raise RuntimeError("filter did not terminate")


# ---------------------------------------------------------------------------
section("the policy, decided by the compiled program itself")
if not sc.available():
    skip("policy checks", "libseccomp is not installed — THIS SUITE PROVED NOTHING (sudo apt install libseccomp2)")
    ARCH = prog = None
else:
    import ctypes
    lib = sc._lib()
    lib.seccomp_arch_native.restype = ctypes.c_uint32
    ARCH = lib.seccomp_arch_native()
    prog = sc.build()

    def nr(name):
        n = sc._resolve(lib, name)
        if n is None:
            raise KeyError(name)
        return n

    def decide(name, *args, arch=None):
        return bpf_run(prog, ARCH if arch is None else arch, nr(name), args)

    check("the program is whole instructions", len(prog) % 8, 0)
    check("building it twice gives the same bytes (it is cached policy, not state)", sc.build() is prog, True)

    ordinary = ("read", "write", "openat", "close", "mmap", "munmap", "mprotect", "futex", "execve",
                "exit_group", "getrandom", "statx", "rt_sigaction", "kill", "tgkill", "prctl", "memfd_create",
                "pipe2", "dup3", "epoll_create1", "eventfd2", "madvise", "ioctl", "fcntl", "pread64",
                "newfstatat", "clock_gettime", "nanosleep", "getpid", "set_tid_address", "rseq", "wait4")
    check("ordinary calls are allowed", [n for n in ordinary if decide(n) != RET_ALLOW], [])
    check("a plain fork/thread clone is allowed",
          decide("clone", 0x00010F00 | 17) == RET_ALLOW and decide("clone", 17) == RET_ALLOW, True)
    for fam, label in ((1, "AF_UNIX"), (2, "AF_INET"), (10, "AF_INET6")):
        check(f"socket({label}) is allowed", decide("socket", fam, 1, 0) == RET_ALLOW, True)
    check("socketpair(AF_UNIX) is allowed", decide("socketpair", 1, 1, 0) == RET_ALLOW, True)

    # Every named refusal that exists on this architecture is refused with EPERM.
    denied, missed = [], []
    for group, why, names in sc.policy():
        if group in ("sockets", "clone"):
            continue
        for n in names:
            try:
                got = decide(n)
            except KeyError:
                continue                              # not a call on this architecture
            denied.append(n)
            if got != errno_ret(1):
                missed.append((n, hex(got)))
    check("every named refusal answers EPERM", missed, [])
    check("...and the list is not empty (the policy resolved on this architecture)", len(denied) > 40, True)
    for n in ("init_module", "mount", "ptrace", "bpf", "unshare", "setns", "io_uring_setup", "keyctl",
              "perf_event_open", "userfaultfd", "reboot", "kexec_load", "chroot", "pivot_root",
              "process_vm_readv", "open_by_handle_at", "swapon", "settimeofday"):
        check(f"{n} is refused", decide(n) == errno_ret(1), True)

    for fam in (16, 17, 38, 40, 31, 29, 15, 21, 44):
        check(f"socket(family {fam}: netlink/packet/alg/vsock/...) is refused", decide("socket", fam, 3, 0) == errno_ret(1), True)
    check("socket(family 0) is refused", decide("socket", 0, 1, 0) == errno_ret(1), True)
    check("socketpair(AF_NETLINK) is refused", decide("socketpair", 16, 1, 0) == errno_ret(1), True)
    check("F38: netlink with a high bit set (0x1_0000_0010) is still refused",
          decide("socket", (1 << 32) | 16, 3, 0) == errno_ret(1), True)
    check("F38: ...and so is a packet socket with high bits set",
          decide("socket", (0xABCD << 32) | 17, 3, 0) == errno_ret(1), True)

    for flag, bit in sc._CLONE_NEW_FLAGS.items():
        check(f"clone with {flag} is refused", decide("clone", bit | 17) == errno_ret(1), True)
    check("clone with several namespace flags is refused",
          decide("clone", 0x10000000 | 0x40000000 | 17) == errno_ret(1), True)
    check("clone3 answers ENOSYS so libc falls back to plain clone", decide("clone3") == errno_ret(38), True)

    other_arch = 0x40000028                                   # AUDIT_ARCH_ARM: a 32-bit table
    other = bpf_run(prog, other_arch, 11, ())
    check("a call through another architecture's syscall table is killed, not allowed",
          other in (0x00000000, 0x80000000), True)

# ---------------------------------------------------------------------------
section("the same, attempted from inside the sandbox")
if prog is None:
    skip("live probes", "libseccomp is unavailable")
elif not sandbox.available() or not sandbox.run(["/bin/true"], "light").ok:
    skip("live probes", "bubblewrap is missing or this host refuses unprivileged user namespaces (as GitHub's "
                        "runners do). THIS HALF PROVED NOTHING HERE — it runs on the box.")
else:
    PYTHON = "/usr/bin/python3"
    # Each probe calls a syscall natively with arguments chosen to be harmless
    # and to fail in a DISTINCT way when nothing stops it.
    PROBES = {
        "ptrace":          ("ptrace", [9999, 0, 0, 0]),
        "unshare":         ("unshare", [0]),
        "setns":           ("setns", [-1, 0]),
        "bpf":             ("bpf", [-1, 0, 0]),
        "io_uring_setup":  ("io_uring_setup", [0, 0]),
        "perf_event_open": ("perf_event_open", [0, 0, -1, -1, 0]),
        "userfaultfd":     ("userfaultfd", [0xFFFFFFFF]),
        "keyctl":          ("keyctl", [-1]),
        "clone3":          ("clone3", [0, 0]),
    }
    spec = {k: [nr(n), a] for k, (n, a) in PROBES.items()}
    snippet = (
        "import ctypes, json, socket\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        f"spec = json.loads({json.dumps(json.dumps(spec))})\n"
        "out = {}\n"
        "for name, (nr, args) in spec.items():\n"
        "    ctypes.set_errno(0)\n"
        "    rc = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])\n"
        "    out[name] = [rc, ctypes.get_errno()]\n"
        "try:\n"
        "    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); out['netlink'] = ['ok', 0]; s.close()\n"
        "except OSError as e:\n"
        "    out['netlink'] = ['err', e.errno]\n"
        "try:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); out['inet'] = ['ok', 0]; s.close()\n"
        "except OSError as e:\n"
        "    out['inet'] = ['err', e.errno]\n"
        "print(json.dumps(out))\n")

    def probe(profile):
        r = sandbox.run([PYTHON, "-c", snippet], profile)
        assert r.ok, (r.exit_code, r.stderr[-300:])
        return json.loads(r.stdout.strip().splitlines()[-1])

    filtered = probe("light")
    control = probe(dataclasses.replace(sandbox.PROFILES["light"], seccomp=False))
    EPERM, ENOSYS = 1, 38
    for name in PROBES:
        want = ENOSYS if name == "clone3" else EPERM
        check(f"{name}: refused with {'ENOSYS' if want == ENOSYS else 'EPERM'} under the filter", filtered[name][1], want)
        check(f"{name}: ...but NOT with the filter off (control: errno {control[name][1]})", control[name][1] != want, True)
    check("a netlink socket is refused under the filter", filtered["netlink"], ["err", EPERM])
    check("...and could be created with the filter off (control)", control["netlink"][0], "ok")
    check("an ordinary IPv4 socket still works under the filter", filtered["inet"], ["ok", 0])

    work = (
        "import os, subprocess, threading, sys\n"
        "r = []\n"
        "t = threading.Thread(target=lambda: r.append('thread')); t.start(); t.join()\n"
        "pid = os.fork()\n"
        "if pid == 0: os._exit(7)\n"
        "r.append('fork%d' % (os.waitpid(pid, 0)[1] >> 8))\n"
        "r.append('child%d' % subprocess.run(['/usr/bin/true']).returncode)\n"
        "import socket\n"
        "a, b = socket.socketpair(); a.send(b'x'); r.append('pair' if b.recv(1) == b'x' else 'bad')\n"
        "print(','.join(r))\n")
    res = sandbox.run([PYTHON, "-c", work], "light")
    check("threads (clone3 -> clone fallback), fork, a child process and a socketpair all work under the filter",
          (res.ok, res.stdout.strip()), (True, "thread,fork7,child0,pair"))
    check("the filter is on the command line bubblewrap was given", "--seccomp" in res.argv, True)
    r_off = sandbox.run(["/bin/true"], dataclasses.replace(sandbox.PROFILES["light"], seccomp=False))
    check("...and absent when the profile turns it off (the control really is a control)", "--seccomp" in r_off.argv, False)
    check("every shipped profile has the filter on", [p.seccomp for p in sandbox.PROFILES.values()], [True] * len(sandbox.PROFILES))

    # Fail closed: no libseccomp, no sandbox.
    real = sc.build
    sc.build = lambda: (_ for _ in ()).throw(sc.SeccompUnavailable("libseccomp is not installed"))
    try:
        sandbox.run(["/bin/true"], "light")
        check("with no libseccomp the sandbox refuses to run", False, True)
    except sandbox.SandboxUnavailable as e:
        check("with no libseccomp the sandbox refuses to run, saying why", "libseccomp" in str(e), True)
    finally:
        sc.build = real

print(f"\n{PASS} passed, {FAIL} failed, {SKIP} skipped")
sys.exit(1 if FAIL else 0)
