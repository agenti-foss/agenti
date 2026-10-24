#!/usr/bin/env python3
"""
egress_relay.py — the one way out of an IP-scoped run that is not a target.

Since audit run 1 (fix 1b) every run of an IP-scoped agent (enum, exploit,
trafficmon) is fenced by the kernel: systemd's IPAddressDeny=any plus
IPAddressAllow=<the run's approved networks> localhost. Nothing in the run —
the harness, a scanner, Metasploit — can send a packet anywhere else, whatever
Agenti's own checks say. The model still has to reach Anthropic, so the Claude
CLI (and only it: the harness hands it HTTPS_PROXY, not the scanners) goes
through this relay on localhost.

The relay accepts HTTP CONNECT for the allowed endpoints only — by default
api.anthropic.com:443 — and refuses everything else with 403. It never sees the
traffic: TLS runs end to end between the CLI and Anthropic, with the CLI
verifying Anthropic's certificate. It resolves the name itself, outside the
run's fence. It is not a general proxy and keeps no logs of content.

    egress_relay.py [--listen 127.0.0.1:8429 | --fd 3] [--allow api.anthropic.com:443 ...]

Its port is held by systemd from boot (agenti-relay.socket, operator decision
2026-10-23: a free port could be taken by any local user); the relay itself
starts on a run's first connection and takes the socket as fd 3. The allowed list can be widened only by root:
/etc/agenti/relay.conf, ALLOW=host:port host:port.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import re
import socket
import sys

DEFAULT_LISTEN = "127.0.0.1:8429"
DEFAULT_ALLOW = ("api.anthropic.com:443",)
CONF = "/etc/agenti/relay.conf"
MAX_HEADER = 8192
IDLE_TIMEOUT_S = 900
CONNECT_RE = re.compile(rb"^CONNECT ([A-Za-z0-9.-]{1,253}):([0-9]{1,5}) HTTP/1\.[01]\r$")


def _conf_allow(path: str = CONF) -> tuple[str, ...]:
    try:
        for line in open(path, encoding="utf-8"):
            if line.startswith("ALLOW="):
                return tuple(x.lower() for x in line[6:].split() if x)
    except OSError:
        pass
    return ()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT_S)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _refuse(writer: asyncio.StreamWriter, code: int, why: str) -> None:
    body = why.encode() + b"\n"
    writer.write(b"HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                 % (code, b"Forbidden" if code == 403 else b"Bad Request", len(body), body))
    try:
        await writer.drain()
    finally:
        writer.close()


def make_handler(allowed: set[str]):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
            writer.close()
            return
        if len(head) > MAX_HEADER:
            return await _refuse(writer, 400, "request too large")
        m = CONNECT_RE.match(head.split(b"\n", 1)[0])
        if not m:
            return await _refuse(writer, 400, "only CONNECT host:port is accepted here")
        target = f"{m.group(1).decode().lower()}:{int(m.group(2))}"
        if target not in allowed:
            print(f"REFUSED CONNECT {target}", file=sys.stderr, flush=True)
            return await _refuse(writer, 403, f"{target} is not an allowed destination")
        host, port = target.rsplit(":", 1)
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 20)
        except (OSError, asyncio.TimeoutError) as e:
            return await _refuse(writer, 403, f"cannot reach {target}: {e}")
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))
    return handle


async def serve(listen: str, allowed: set[str], fd: int | None = None) -> None:
    if fd is not None:
        # systemd's agenti-relay.socket holds the port from boot and hands it
        # over here, so it is never free for another program (audit run 2).
        sock = socket.socket(fileno=fd)
        server = await asyncio.start_server(make_handler(allowed), sock=sock, limit=MAX_HEADER)
        listen = "%s:%s" % sock.getsockname()[:2]
    else:
        host, port = listen.rsplit(":", 1)
        server = await asyncio.start_server(make_handler(allowed), host, int(port), limit=MAX_HEADER)
    print(f"agenti relay on {listen}, allowing: {', '.join(sorted(allowed))}", flush=True)
    async with server:
        await server.serve_forever()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description="Agenti's egress relay: CONNECT to the allowed endpoints only.")
    ap.add_argument("--listen", default=os.environ.get("AGENTI_RELAY_ADDR", DEFAULT_LISTEN))
    ap.add_argument("--allow", action="append", default=[], metavar="HOST:PORT")
    ap.add_argument("--fd", type=int, default=None,
                    help="serve on this inherited listening socket (systemd socket activation: 3)")
    a = ap.parse_args(argv)
    allowed = {x.lower() for x in (a.allow or _conf_allow() or DEFAULT_ALLOW)}
    asyncio.run(serve(a.listen, allowed, a.fd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
