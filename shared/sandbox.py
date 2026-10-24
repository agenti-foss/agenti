"""
sandbox.py — run ONE external program on an untrusted file, contained.

CLAUDE.md "Current plan", phase 2. Any program that parses a file an operator
attached (tshark and capinfos today) runs through here and nowhere else.

WHY IT EXISTS — the threat is the FILE, not the program
-------------------------------------------------------
Packet-capture, image, video and document parsers have a long, well-documented
history of remote code execution triggered by a *malformed input file*
(Wireshark's dissectors alone ship dozens of such CVEs a year). Vetting the
list of programs an agent may run protects against the agent reaching for
something dangerous; it does nothing about a perfectly legitimate program
being handed a hostile file.

The file is a capture someone else produced. If its parser is exploited, what
that attacker would reach on this box is the agent's API key, the encrypted
vault's contents, and every other user's runs. This module is what makes
"the file can only hurt itself" true.

WHAT IS ENFORCED, AND IT IS ALL PROVEN LIVE (shared/test_sandbox.py)
-------------------------------------------------------------------
Every property below is verified by ATTEMPTING it, not by reading config:

  * no network at all (default) — only loopback exists inside; an outbound
    connect fails with ENETUNREACH while the identical call succeeds on the
    host, which is the control that makes the result mean something;
  * the filesystem the program sees is a throwaway tmpfs root plus exactly:
    /usr /bin /lib (read-only, the program itself), the run's input
    directory (read-only), and its output directory (read-write).
    Agenti's data (/var/lib/agenti), the vault and /etc/shadow do not exist inside;
  * no capabilities at all (CapEff 0000000000000000) and NoNewPrivs=1, both
    set by bubblewrap's user namespace. The agent's own service unit cannot
    say that, because it must be able to sudo;
  * a private PID namespace, so the program sees only itself — and killing
    the sandbox reaps every process inside it, proven with a tree of
    children that all died;
  * a cleared environment. This matters more than it looks: the agent
    process holds ANTHROPIC_API_KEY, and without --clearenv every sandboxed
    program would inherit it;
  * CPU-seconds, address space and output-file-size ceilings via rlimits,
    plus a wall-clock deadline enforced here;
  * a seccomp syscall filter (sandbox_seccomp.py) that refuses the calls a
    parser has no use for, proven by attempting each class of them.

WHAT IS NOT ENFORCED, STATED PLAINLY
------------------------------------
  * **The syscall filter is a deny-list, not an allow-list.** It removes the
    calls a parser has no use for and that open kernel attack surface (modules,
    bpf, io_uring, perf, userfaultfd, mount, ptrace, new namespaces, netlink
    and the exotic socket families) — see shared/sandbox_seccomp.py for the
    list and for why it is not an allow-list. A program can still make any call
    not named there; the namespaces, the empty capability set and the missing
    filesystem are what limit those. Without libseccomp the sandbox refuses to
    run rather than run unfiltered.
  * **RLIMIT_CPU is per-process, not per-tree.** A program that forks gets a
    fresh CPU budget per child. The wall-clock deadline is the real backstop
    for a forking runaway, and `TasksMax` on the agent's own unit is the
    cgroup-level guard against a fork bomb (RLIMIT_NPROC is deliberately NOT
    used — it counts processes per-UID across the whole host, so a sensible
    value stops bubblewrap from even starting).
  * **A failed run's output is suspect.** Hitting the file-size ceiling
    leaves a truncated file behind, so the caller must treat output from a
    non-ok result as discardable rather than partial-but-usable.

Nothing here needs root: bubblewrap uses unprivileged user namespaces, which
is exactly right because the agent runs as an unprivileged service account
and could not create a systemd transient unit even if we wanted one. What it
DOES need from the agent's unit is a bounding-set CAP_SYS_ADMIN and two
relaxed hardening booleans (capability-dropin.sh, SANDBOX_CAP).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Sequence

import sandbox_seccomp

__all__ = ["SandboxProfile", "SandboxResult", "SandboxUnavailable", "run",
           "available", "build_argv", "PROFILES", "IN_DIR", "OUT_DIR", "MB"]

BWRAP = os.environ.get("AGENTI_BWRAP", "/usr/bin/bwrap")
PRLIMIT = os.environ.get("AGENTI_PRLIMIT", "/usr/bin/prlimit")

MB = 1024 * 1024
_STDERR_BYTES = 64 * 1024     # how much of a program's stderr (its tail) comes back in the result

# Where the run's files appear INSIDE the sandbox. The tool layer rewrites an
# attached file's name to IN_DIR/<name> before the program sees it.
IN_DIR = "/in"
OUT_DIR = "/out"

# Mounted read-only so the program itself (and its shared libraries) exist.
# Deliberately NOT /etc: binding the host's /etc would put /etc/shadow inside
# a sandbox built to run hostile input. A minimal passwd/group is synthesised
# instead, because some libraries call getpwuid() and handle its failure
# badly.
_SYSTEM_ROS = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32")

_PASSWD = "root:x:0:0:root:/:/usr/sbin/nologin\n{name}:x:{uid}:{gid}::/tmp:/usr/sbin/nologin\n"
_GROUP = "root:x:0:\n{name}:x:{gid}:\n"


class SandboxUnavailable(RuntimeError):
    """bubblewrap is missing or unusable. Raised rather than silently falling
    back to an unsandboxed run — a sandbox that quietly isn't one is worse
    than a clear failure."""


@dataclass(frozen=True)
class SandboxProfile:
    """The ceiling for one program invocation. The caps move up when the
    hardware does."""

    name: str
    wall_clock_s: int = 120
    cpu_seconds: int = 60
    memory_bytes: int = 512 * MB
    output_bytes: int = 256 * MB
    network: bool = False
    # Extra host paths this profile needs read-only.
    extra_ro: tuple[str, ...] = ()
    # The syscall filter (sandbox_seccomp.py). On for every profile; a profile
    # exists to set limits, not to opt out of containment. The field is here so
    # the test suite can run the same program with and without it as a control.
    seccomp: bool = True


# Starting points sized for the Raspberry Pi. They are parameters, not
# assumptions — raising them is how this moves to bigger hardware.
PROFILES: dict[str, SandboxProfile] = {
    # Quick, small work (and the test suite).
    "light": SandboxProfile("light", wall_clock_s=60, cpu_seconds=30,
                            memory_bytes=256 * MB, output_bytes=64 * MB),
    # Packet-capture analysis: tshark decoding up to a 100 MB capture (the
    # upload limit). Memory is address space, not resident size, and tshark
    # maps its plugins and dissectors, hence the headroom.
    "analysis": SandboxProfile("analysis", wall_clock_s=300, cpu_seconds=240,
                               memory_bytes=1536 * MB, output_bytes=128 * MB),
    # Suricata over a capture: loading a rule set (tens of thousands of rules
    # for the Emerging Threats set) dominates, and its event log can run to
    # several times the capture's size. Address space is generous because
    # Suricata maps large hash tables up front; resident use is far lower.
    "suricata": SandboxProfile("suricata", wall_clock_s=600, cpu_seconds=540,
                               memory_bytes=4096 * MB, output_bytes=512 * MB),
    # Hash cracking (john/hashcat): CPU-bound work over a wordlist. No network,
    # no GPU (the Pi has none accessible to an unprivileged process). Memory
    # usage is low (a wordlist is read line by line); wall clock is generous
    # because rockyou at CPU speed takes 5–30 min depending on the hash type.
    # The agent run's own timeout is the real ceiling; this is a per-invocation
    # safety backstop. output_bytes is small — cracked passwords fit in KiB.
    # Address space: hashcat's CPU OpenCL runtime (pocl) reserves a large
    # thread stack per core and failed at 1 GiB on the 4-core Pi ("Insufficient
    # memory available"); 2 GiB worked, 3 GiB leaves room for rockyou.
    # extra_ro: john's config (/etc/john/john.conf), the OpenCL driver list
    # hashcat loads, and the CPU topology pocl reads — all read-only, none
    # writable, nothing else from /etc or /sys.
    # CPU seconds are counted across every thread of a process, and john and
    # hashcat crack on every core: at 1800 a 4-thread john was killed after
    # ~8 of its 30 wall-clock minutes (run 78473136, 2026-10-18). One wall
    # clock's worth per core; the wall clock is the real ceiling.
    "cracker": SandboxProfile("cracker", wall_clock_s=1800, cpu_seconds=1800 * (os.cpu_count() or 1),
                              memory_bytes=3072 * MB, output_bytes=16 * MB,
                              extra_ro=("/etc/john", "/etc/OpenCL", "/sys/devices/system/cpu")),
}


@dataclass
class SandboxResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    # Which ceiling ended it, if any: wall_clock | cpu | memory | output_size.
    # None means the program simply exited (ok tells you whether it succeeded).
    limit_hit: str | None = None
    argv: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """One line for the run ledger / an operator-facing error."""
        if self.limit_hit == "wall_clock":
            return f"stopped: exceeded the {self.duration_s:.0f}s time limit"
        if self.limit_hit == "cpu":
            return "stopped: exceeded its CPU limit"
        if self.limit_hit == "memory":
            return "stopped: exceeded its memory limit"
        if self.limit_hit == "output_size":
            return "stopped: produced more output than its size limit allows"
        if self.ok:
            return f"completed in {self.duration_s:.1f}s"
        return f"failed (exit {self.exit_code})"


def available() -> bool:
    return bool(shutil.which(BWRAP) or Path(BWRAP).exists())


def _ro_binds() -> list[str]:
    args: list[str] = []
    for p in _SYSTEM_ROS:
        if Path(p).exists() and not Path(p).is_symlink():
            args += ["--ro-bind", p, p]
        elif Path(p).is_symlink():
            # /lib -> usr/lib on merged-/usr systems: recreate the symlink
            # rather than bind, or the target shadows it.
            args += ["--symlink", os.readlink(p), p]
    return args


def _bind_args(binds: Sequence[tuple[str, str]]) -> list[str]:
    """Read-only binds, where one may sit INSIDE another (the cracker's
    /wordlists with /wordlists/hashcat-rules in it).

    bwrap cannot create a mount point inside a read-only bind — that failed
    every john/hashcat run with "Can't create file /wordlists/hashcat-rules:
    Read-only file system" (run 183c7543fd9d, 2026-10-16). So a bind that has
    another inside it becomes a tmpfs holding its host directory's entries
    (each bound read-only, symlinks recreated as symlinks so they resolve
    inside the sandbox, never on the host), the inner binds are mounted on
    that tmpfs, and the whole thing is remounted read-only afterwards."""
    pairs = []
    for src, dest in binds:
        if not (os.path.isabs(src) and os.path.isabs(dest)):
            raise ValueError(f"sandbox bind needs absolute paths, got {src!r} -> {dest!r}")
        if not Path(src).exists():
            raise FileNotFoundError(f"cannot bind {src!r} into the sandbox: it does not exist")
        pairs.append((src, dest.rstrip("/") or "/"))
    # Outer before inner, so a parent's tmpfs exists before a child mounts on it.
    pairs.sort(key=lambda p: p[1].count("/"))
    args: list[str] = []
    remount: list[str] = []
    for src, dest in pairs:
        inner = {d[len(dest) + 1:].split("/", 1)[0] for _, d in pairs if d.startswith(dest + "/")}
        if not inner:
            args += ["--ro-bind", str(Path(src).resolve()), dest]
            continue
        if not Path(src).is_dir():
            raise ValueError(f"sandbox bind {src!r} -> {dest!r} has binds inside it, so it must be a directory")
        args += ["--tmpfs", dest]
        for entry in sorted(os.listdir(src)):
            if entry in inner:
                continue                       # the inner bind wins
            host = os.path.join(src, entry)
            if os.path.islink(host):
                args += ["--symlink", os.readlink(host), f"{dest}/{entry}"]
            else:
                args += ["--ro-bind", str(Path(host).resolve()), f"{dest}/{entry}"]
        remount.append(dest)
    # Innermost first: a remount-ro on the outer tmpfs does not touch inner mounts.
    for dest in reversed(remount):
        args += ["--remount-ro", dest]
    return args


def build_argv(command: list[str], profile: SandboxProfile, *,
               input_dir: Path | None = None,
               output_dir: Path | None = None,
               binds: Sequence[tuple[str, str]] = (),
               workdir: str = OUT_DIR) -> tuple[list[str], list[tuple[int, bytes]]]:
    """The full argv, plus the (fd-placeholder, data) pairs to inject.

    Separated from run() so the tests can assert on the exact flags without
    executing anything — the flags ARE the boundary, so they are worth
    asserting directly."""
    if not command:
        raise ValueError("sandbox.run needs a command to run")
    command = list(command)

    uid, gid = os.getuid(), os.getgid()
    name = "agent"
    argv: list[str] = [
        BWRAP,
        # A throwaway tmpfs root: anything the program writes outside the
        # bound directories lands here and is discarded with the sandbox.
        "--tmpfs", "/",
        *_ro_binds(),
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        # Every namespace. --share-net is the ONLY way network comes back,
        # and only when the profile asks for it.
        "--unshare-all",
        # Die with the parent, and detach from the controlling terminal so
        # the program cannot reach the operator's tty.
        "--die-with-parent",
        "--new-session",
        # No inherited environment: the agent holds API keys.
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "TMPDIR", "/tmp",
        "--setenv", "LC_ALL", "C.UTF-8",
        "--hostname", "sandbox",
    ]
    if profile.network:
        argv.append("--share-net")

    files: list[tuple[int, bytes]] = [
        (0, _PASSWD.format(name=name, uid=uid, gid=gid).encode()),
        (1, _GROUP.format(name=name, gid=gid).encode()),
    ]

    for host, dest, writable in ((input_dir, IN_DIR, False), (output_dir, OUT_DIR, True)):
        if host is None:
            continue
        argv += (["--bind"] if writable else ["--ro-bind"]) + [str(Path(host).resolve()), dest]

    for extra in profile.extra_ro:
        if Path(extra).exists():
            argv += ["--ro-bind", extra, extra]

    # Host files a program needs at a FIXED path of its own (Suricata's config
    # and rules), read-only. Chosen by code, never by the model. A missing
    # source is an error here rather than a silent omission: running the
    # program without its config would fail in a confusing way, or worse,
    # fall back to a different config.
    argv += _bind_args(binds)

    argv += ["--chdir", workdir if output_dir else "/tmp"]
    argv += ["--"] + list(command)
    return argv, files


def run(command: list[str], profile: SandboxProfile | str = "light", *,
        input_dir: Path | None = None,
        output_dir: Path | None = None,
        binds: Sequence[tuple[str, str]] = (),
        stdin_data: bytes | None = None,
        stdout_to: IO[bytes] | None = None) -> SandboxResult:
    """Run `command` inside the sandbox. Never raises for a program that
    merely failed or hit a ceiling — that is reported in the result, because
    a tool refusing a hostile file is a normal outcome, not an exception.

    Output never passes through a pipe. RLIMIT_FSIZE bounds what a program
    writes to a FILE (an inherited descriptor included) but not to a pipe, so
    a program that prints without end would fill this process's memory until
    the wall clock stopped it. Both streams therefore go to files: stderr to
    a private temp file (the last 64 KB come back in the result), stdout to
    `stdout_to` if given — an open binary file the caller keeps, in which case
    the result's stdout is empty — or else to a temp file read back into the
    result. Either way the profile's size ceiling applies."""
    if isinstance(profile, str):
        profile = PROFILES[profile]
    if not available():
        raise SandboxUnavailable(
            f"{BWRAP} not found. The sandbox is a prerequisite for any program "
            f"that opens an attached file — install bubblewrap (apt install "
            f"bubblewrap) rather than running such a program unconfined.")

    argv, files = build_argv(command, profile, input_dir=input_dir, output_dir=output_dir,
                              binds=binds)

    # Inject the synthetic passwd/group over pipes, so the host's /etc is
    # never bound into a sandbox built to run hostile input.
    pass_fds: list[int] = []
    # They go AFTER the tmpfs root: bwrap applies mounts in order, so placed
    # before it (as they were until 2026-10-16) the root tmpfs hid them and
    # the sandbox had no /etc/passwd at all — which crashed hashcat's OpenCL
    # runtime (pocl looks its user up) with a bare SIGSEGV.
    root_at = next(i for i in range(len(argv) - 1) if argv[i:i + 2] == ["--tmpfs", "/"]) + 2
    final: list[str] = argv[:root_at]
    for data, dest in ((files[0][1], "/etc/passwd"), (files[1][1], "/etc/group")):
        r, w = os.pipe()
        os.set_inheritable(r, True)
        with os.fdopen(w, "wb") as fh:
            fh.write(data)
        pass_fds.append(r)
        final += ["--ro-bind-data", str(r), dest]
    final += argv[root_at:]
    if profile.seccomp:
        # The filter, also over a pipe (a few KB, well under the pipe buffer).
        # Refuse to run without it rather than run a weaker sandbox than the
        # one every caller and every test believes in.
        try:
            prog = sandbox_seccomp.build()
        except sandbox_seccomp.SeccompUnavailable as e:
            for fd in pass_fds:
                os.close(fd)
            raise SandboxUnavailable(str(e)) from e
        r, w = os.pipe()
        os.set_inheritable(r, True)
        with os.fdopen(w, "wb") as fh:
            fh.write(prog)
        pass_fds.append(r)
        final[1:1] = ["--seccomp", str(r)]

    # rlimits are applied by prlimit on the OUTSIDE and inherited through
    # bubblewrap into the program. Lowering a limit never needs privilege.
    limited = [PRLIMIT,
               # Soft below hard: the kernel sends SIGXCPU (exit 152, which
               # only ever means this) at the ceiling, and SIGKILL only if the
               # program ignores it. With the two equal the only sign was a
               # bare SIGKILL — and the CPU used is invisible from out here
               # (bubblewrap's PID namespace does not pass the rusage back).
               f"--cpu={profile.cpu_seconds}:{profile.cpu_seconds + 5}",
               f"--as={profile.memory_bytes}",
               f"--fsize={profile.output_bytes}",
               "--"] + final if Path(PRLIMIT).exists() else final

    started = time.monotonic()
    limit_hit: str | None = None
    own_out = stdout_to is None
    out_f = tempfile.TemporaryFile() if own_out else stdout_to
    err_f = tempfile.TemporaryFile()
    try:
        try:
            proc = subprocess.run(limited, input=stdin_data, timeout=profile.wall_clock_s,
                                  close_fds=False, stdout=out_f, stderr=err_f)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            # Killing bubblewrap tears down the PID namespace, which reaps
            # every process inside it — verified live, not assumed.
            code, limit_hit = -1, "wall_clock"
        finally:
            for fd in pass_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
        duration = time.monotonic() - started
        # Which file filled up. A program whose stderr is full cannot print
        # "File too large", so the size, not the message, is the reliable sign.
        filled = any(os.fstat(f.fileno()).st_size >= profile.output_bytes for f in (out_f, err_f))
        out = b""
        if own_out:
            out_f.seek(0)
            out = out_f.read(profile.output_bytes)
        # The TAIL: a program's last words are its error, and a flood of
        # earlier output must not hide the "File too large" that ended it.
        err_f.seek(0, os.SEEK_END)
        err_f.seek(max(0, err_f.tell() - _STDERR_BYTES))
        err = err_f.read()
    finally:
        if own_out:
            out_f.close()
        err_f.close()

    text_err = err.decode("utf-8", "replace")
    if limit_hit is None and code != 0:
        # Map the usual signals/messages onto which ceiling was hit, so the
        # operator gets "it ran out of memory", not "exit -9".
        if filled:
            limit_hit = "output_size"
        elif code in (-9, 137) and duration * (os.cpu_count() or 1) >= profile.cpu_seconds * 0.9:
            # A program that ignored SIGXCPU and ran on to the hard limit. A
            # multithreaded one gets there in a fraction of cpu_seconds of
            # wall time, so the floor is per core, not per program.
            limit_hit = "cpu"
        elif code in (-24, 152):            # SIGXCPU
            limit_hit = "cpu"
        elif code in (-25, 153):            # SIGXFSZ
            limit_hit = "output_size"
        elif "MemoryError" in text_err or "Cannot allocate memory" in text_err \
                or "std::bad_alloc" in text_err:
            limit_hit = "memory"
        elif "File size limit exceeded" in text_err or "File too large" in text_err:
            # SIGXFSZ kills a default-handling program (tshark: code 153); a
            # runtime that ignores the signal (Python) gets EFBIG instead.
            limit_hit = "output_size"

    return SandboxResult(
        ok=(code == 0 and limit_hit is None),
        exit_code=code,
        stdout=out.decode("utf-8", "replace"),
        stderr=text_err,
        duration_s=duration,
        limit_hit=limit_hit,
        argv=limited,
    )
