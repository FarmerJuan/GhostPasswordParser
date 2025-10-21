#!/usr/bin/env python3
"""
GhostPasswordParser.py

Parse default-http-login-hunter output, clean noise, group credentials per host
into a single CSV cell, print a Ghost Energy–themed banner on start, clone &
run default-http-login-hunter, extract web servers from a Nessus file (built-in),
run the hunter on the extracted list (from inside the hunter repo), stream output
with a progress bar, then parse and write grouped CSV/JSON results.

Usage:
    python3 GhostPasswordParser.py hunter_output.txt
    python3 GhostPasswordParser.py -n scan.nessus
    python3 GhostPasswordParser.py -n scan.nessus --outdir results --no-progress

Flags:
    --redact            : redact passwords in the CSV output (replace with 'REDACTED')
    --sep SEP           : separator used to join creds in CSV (default: '; ')
    --no-color          : disable ANSI color output
    --width N           : banner total width (default: 72)
    --clone / --no-clone: clone the default-http-login-hunter repo (default: clone)
    --repo DIR          : directory to clone repo into (default: ./default-http-login-hunter)
    -n, --nessus FILE   : path to a Nessus XML file to extract web servers from
    --webservers FILE   : path to produced web servers list (default: web_servers.txt)
    --hunter-out FILE   : raw hunter output path (default: hunter_raw.txt)
    --no-run-hunter     : skip running the hunter even if repo exists
    --outdir DIR        : output directory for CSV/JSON files (default: .)
    --stdout            : also print one-line summary per host to stdout
    --no-progress       : disable live progress bar while hunter runs
"""
from __future__ import annotations
import sys
import re
import csv
import json
import argparse
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

__version__ = "1.6"
__author__ = "GhostPasswordParser (adapted for you)"

ANSI = {
    "bold": "\033[1m",
    "reset": "\033[0m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "white": "\033[97m",
}

def colorize(s: str, code: str, use_color: bool = True) -> str:
    if not use_color:
        return s
    return f"{ANSI.get(code, '')}{s}{ANSI['reset']}"

BANNER_LINES = [
    r"     .-.",
    r"    (o o)   GHOST",
    r"   |  O  |  PASSWORD",
    r"    \   /   PARSER",
    r"    __) (__",
    r"   /  `-'  \   Ghost Energy™ style",
    r"  / /| . |\ \  Clean • Group • Export",
    r" /_/ |_| |_\\_\ ",
]

def print_banner(use_color: bool = True, total_width: int = 72):
    total_width = max(48, min(120, total_width))
    art_width = max(len(ln) for ln in BANNER_LINES) + 2
    meta_width = total_width - art_width - 6
    if meta_width < 20:
        meta_width = 20
    meta_lines = [
        f" GhostPasswordParser v{__version__}",
        f" by {__author__}",
        f" {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        " Clean • Group • Export",
    ]
    top = colorize("╔" + "═" * (total_width - 2) + "╗", "magenta", use_color)
    bottom = colorize("╚" + "═" * (total_width - 2) + "╝", "magenta", use_color)
    print(top)
    for i in range(max(len(BANNER_LINES), len(meta_lines))):
        art_ln = BANNER_LINES[i] if i < len(BANNER_LINES) else ""
        art_col = art_ln.ljust(art_width)
        meta_ln = meta_lines[i] if i < len(meta_lines) else ""
        if len(meta_ln) > meta_width:
            meta_ln = meta_ln[: max(0, meta_width - 3)] + "..."
        art_col_colored = colorize(art_col, "cyan", use_color)
        meta_colored = colorize(meta_ln.ljust(meta_width), "magenta", use_color)
        line = colorize("║ ", "magenta", use_color) + art_col_colored + " " + meta_colored + colorize(" ║", "magenta", use_color)
        print(line)
    print(bottom)
    print()

# ---------------- Parsing helpers ----------------

def extract_ip_port(header: str) -> tuple[str | None, int | None]:
    ip_port_re = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[:\.](?P<port>\d{1,5})")
    m = ip_port_re.search(header)
    if m:
        return m.group("ip"), int(m.group("port"))
    ip_re = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})")
    ipm = ip_re.search(header)
    if ipm:
        ip = ipm.group(1)
        after = header[ipm.end() :]
        portm = re.search(r"[:\.\s](\d{1,5})", after)
        if portm:
            try:
                return ip, int(portm.group(1))
            except ValueError:
                return ip, None
        return ip, None
    return None, None

def is_useless_timestamp_line(line: str) -> bool:
    if not line:
        return False
    if "trying default http logins on" in line.lower():
        return True
    return False

def is_junk_header(hdr: str) -> bool:
    if not hdr or not hdr.strip():
        return True
    if "error: http request table is empty" in hdr.lower():
        return True
    if "trying default http logins on" in hdr.lower():
        return True
    if re.fullmatch(r"[_\|\s\-]+", hdr.strip()):
        return True
    if hdr.strip().startswith("_") and len(hdr.strip()) < 80:
        if not re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hdr):
            return True
    return False

def is_junk_cred(u: str | None, p: str | None) -> bool:
    if not u or not p:
        return True
    u = u.strip()
    p = p.strip()
    if not u or not p:
        return True
    if re.fullmatch(r"[_\|\-]{1,10}", u) or re.fullmatch(r"[_\|\-]{1,10}", p):
        return True
    return False

def parse(text: str) -> list[dict]:
    results: list[dict] = []
    lines = text.splitlines()
    header_re = re.compile(r"^\|\s*(?P<header>.+)$")
    bracket_re = re.compile(r"\[([^\]]+)\]")
    cred_re = re.compile(r"([A-Za-z0-9_.+\-]{1,64}):([^\s:]{1,128})")
    cur = None
    for ln in lines:
        s = ln.rstrip("\n")
        if is_useless_timestamp_line(s):
            continue
        m = header_re.match(s.strip())
        if m and ("http" in s.lower() or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s)):
            if cur is not None and cur.get("creds"):
                results.append(cur)
            header = m.group("header").strip()
            ip, port = extract_ip_port(header)
            cur = {"host_header": header, "ip": ip, "port": port, "display_name": None, "creds": [], "raw_block": [s.strip()]}
            continue
        if cur is not None:
            cur["raw_block"].append(s.strip())
            b = bracket_re.search(s)
            if b:
                cur["display_name"] = b.group(1).strip()
            if is_useless_timestamp_line(s):
                continue
            for user, pw in cred_re.findall(s):
                if user.lower().startswith("http") or user.lower().endswith("http"):
                    continue
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", user):
                    continue
                if user in ("at", "www", "http", "https"):
                    continue
                cur["creds"].append({"username": user.strip(), "password": pw.strip(), "raw_line": s.strip()})
    if cur is not None and cur.get("creds"):
        results.append(cur)
    return results

def clean_parsed(parsed: list[dict]) -> list[dict]:
    cleaned: list[dict] = []
    for block in parsed:
        hdr = (block.get("host_header") or "").strip()
        if is_junk_header(hdr):
            continue
        good_creds = []
        for c in block.get("creds", []):
            u = (c.get("username") or "").strip()
            p = (c.get("password") or "").strip()
            raw = (c.get("raw_line") or "")
            if is_useless_timestamp_line(raw):
                continue
            if is_junk_cred(u, p):
                continue
            good_creds.append({"username": u, "password": p, "raw_line": raw})
        if not good_creds:
            continue
        nb = {
            "host_header": hdr,
            "ip": block.get("ip"),
            "port": block.get("port"),
            "display_name": block.get("display_name"),
            "creds": good_creds,
            "raw_block": block.get("raw_block", []),
        }
        cleaned.append(nb)
    return cleaned

def write_outputs_grouped(parsed: list[dict], outdir: Path, redact: bool = False, sep: str = "; ", also_stdout: bool = False):
    outdir.mkdir(parents=True, exist_ok=True)
    csv_out = outdir / "hunter_parsed_grouped.csv"
    json_out = outdir / "hunter_parsed_grouped.json"
    with csv_out.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["host_header", "ip", "port", "display_name", "all_creds", "raw_block"])
        writer.writeheader()
        for block in parsed:
            creds_joined = []
            for c in block.get("creds", []):
                user = c["username"]
                pw = "REDACTED" if redact else c["password"]
                creds_joined.append(f"{user}:{pw}")
            creds_joined_str = sep.join(creds_joined)
            writer.writerow(
                {
                    "host_header": block.get("host_header", ""),
                    "ip": block.get("ip", "") or "",
                    "port": block.get("port", "") or "",
                    "display_name": block.get("display_name", "") or "",
                    "all_creds": creds_joined_str,
                    "raw_block": "\\n".join(block.get("raw_block", [])),
                }
            )
    with json_out.open("w") as f:
        json.dump(parsed, f, indent=2)
    total_creds = sum(len(b.get("creds", [])) for b in parsed)
    print(f"Parsed {total_creds} credential entries across {len(parsed)} host blocks.")
    print(f"CSV -> {csv_out.resolve()}")
    print(f"JSON -> {json_out.resolve()}")
    if also_stdout:
        for block in parsed:
            host = block.get("host_header", "")
            creds = "; ".join(f"{c['username']}:{('REDACTED' if redact else c['password'])}" for c in block.get("creds", []))
            print(f"{host}  ->  {creds}")

# ---------------- Command helpers ----------------

def run_cmd(cmd: list[str], cwd: Path | None = None, capture: bool = False, check: bool = False):
    try:
        if capture:
            res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
            return res.stdout, res.stderr, res.returncode
        else:
            res = subprocess.run(cmd, cwd=cwd, check=check)
            return None, None, res.returncode
    except subprocess.CalledProcessError as e:
        return getattr(e, "stdout", ""), getattr(e, "stderr", ""), getattr(e, "returncode", 1)
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", 127

def find_hunter_script(repo_dir: Path) -> Path | None:
    repo = Path(repo_dir)
    if not repo.exists():
        return None
    # Prefer explicit-named runners near root
    patterns = [
        "default-http-login-hunter.sh",
        "*default*login*hunter*.sh",
        "*default*login*hunter*",
    ]
    for pat in patterns:
        for p in repo.glob(pat):
            if p.is_file():
                return p
    # prefer .sh near root
    for p in repo.rglob("*.sh"):
        rel = p.relative_to(repo)
        if len(rel.parts) <= 3:
            return p
    # any .sh anywhere
    for p in repo.rglob("*.sh"):
        return p
    # any file with 'hunter' in name
    for p in repo.rglob("*hunter*"):
        if p.is_file():
            return p
    return None

def clone_repo(repo_url: str, target: Path, use_color: bool):
    if target.exists():
        print(colorize(f"[i] repo directory exists: {target}", "yellow", use_color))
        return True
    git_path = shutil.which("git")
    if not git_path:
        print(colorize("[!] git not found on PATH; cannot clone repository.", "yellow", use_color))
        return False
    print(colorize(f"[i] Cloning {repo_url} -> {target}", "green", use_color))
    out, err, rc = run_cmd(["git", "clone", repo_url, str(target)], capture=True)
    if rc != 0:
        print(colorize(f"[!] git clone failed: {err or out}", "yellow", use_color))
        return False
    return True

# ---------------- Nessus extractor (built-in) ----------------

COMMON_SSL_PORTS = {"443", "8443", "9443", "10443"}

def extract_web_servers_from_nessus_builtin(nessus_file: Path, output_file: Path, use_color: bool) -> bool:
    try:
        tree = ET.parse(str(nessus_file))
        root = tree.getroot()
    except Exception as e:
        print(colorize(f"[!] failed to parse nessus file: {e}", "yellow", use_color))
        return False
    web_servers = set()
    for report_host in root.iter("ReportHost"):
        host_ip = report_host.attrib.get("name", "").strip()
        for item in report_host.iter("ReportItem"):
            svc_name = (item.attrib.get("svc_name", "") or "").lower()
            port = item.attrib.get("port", "").strip()
            if "http" in svc_name or "www" in svc_name:
                if "ssl" in svc_name or port in COMMON_SSL_PORTS:
                    protocol = "https"
                else:
                    protocol = "http"
                if host_ip:
                    web_servers.add(f"{protocol}://{host_ip}:{port}")
    try:
        with output_file.open("w") as fh:
            for server in sorted(web_servers):
                fh.write(server + "\n")
    except Exception as e:
        print(colorize(f"[!] failed to write web servers file: {e}", "yellow", use_color))
        return False
    print(colorize(f"[i] extracted {len(web_servers)} web servers to '{output_file}'", "green", use_color))
    return True

# ---------------- hunter-run helpers ----------------

def count_webservers(webservers_path: Path) -> int:
    if not webservers_path.exists():
        return 0
    cnt = 0
    for line in webservers_path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cnt += 1
    return cnt

def print_progress(cur: int, total: int, width: int = 30):
    if total <= 0:
        return
    frac = min(1.0, max(0.0, cur / total))
    filled = int(frac * width)
    bar = "#" * filled + "." * (width - filled)
    print(f"\rProgress: [{bar}] {cur}/{total}", end="", flush=True)

def _copy_webservers_into_repo(webservers: Path, repo_dir: Path, use_color: bool) -> Path | None:
    try:
        repo_dir.mkdir(parents=True, exist_ok=True)
        dest = repo_dir / webservers.name
        # if already same file, return it
        try:
            if webservers.resolve().samefile(dest):
                return webservers
        except Exception:
            pass
        shutil.copy2(str(webservers), str(dest))
        return dest
    except Exception as e:
        try:
            dest = repo_dir / webservers.name
            if dest.exists():
                dest.unlink()
            dest.symlink_to(webservers.resolve())
            return dest
        except Exception as e2:
            print(colorize(f"[!] failed to copy or link webservers into repo: {e} / {e2}", "yellow", use_color))
            return None

def run_hunter(hunter_script: Path, webservers: Path, hunter_out: Path, use_color: bool, show_progress: bool = True):
    """
    Robust runner that:
     - copies/symlinks webservers file into repo_dir
     - runs: (cd repo_dir && bash runner_basename web_servers_name)
     - if method1 fails, falls back to: bash /abs/path/to/runner /abs/path/to/webservers (no cwd)
     - streams output to console and hunter_out; updates progress heuristically
    """
    if not hunter_script or not hunter_script.exists():
        print(colorize(f"[!] hunter script not found: {hunter_script}", "yellow", use_color))
        return False

    repo_dir = hunter_script.parent
    if not webservers.exists():
        print(colorize(f"[!] web servers list not found: {webservers}", "yellow", use_color))
        return False

    local_ws = _copy_webservers_into_repo(webservers, repo_dir, use_color)
    if not local_ws:
        print(colorize("[!] unable to make webservers available inside hunter repo; aborting run.", "yellow", use_color))
        return False

    total_targets = count_webservers(local_ws)
    runner_basename = hunter_script.name
    abs_runner = str(hunter_script.resolve())
    abs_ws = str(local_ws.resolve())

    # Attempt 1: invoke inside repo using runner basename (preferred)
    cmd1 = ["bash", runner_basename, local_ws.name]
    print(colorize(f"[i] running hunter (method1): cd {repo_dir} && {' '.join(cmd1)} -> {hunter_out}", "green", use_color))
    try:
        with hunter_out.open("w") as fh:
            proc = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=repo_dir, text=True, bufsize=1)
            cur_count = 0
            header_re = re.compile(r"^\|\s*.*http", re.I)
            try:
                for raw_line in proc.stdout:
                    if raw_line is None:
                        break
                    line = raw_line.rstrip("\n")
                    fh.write(line + "\n")
                    fh.flush()
                    print(line)
                    if show_progress and total_targets > 0:
                        low = line.lower()
                        if "trying default http logins on" in low or header_re.match(line.strip()):
                            cur_count += 1
                            print_progress(cur_count, total_targets)
                rc = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()
                print("\n[!] Hunter run interrupted by user.")
                return False

            if rc == 0:
                if show_progress and total_targets > 0:
                    if cur_count < total_targets:
                        cur_count = total_targets
                        print_progress(cur_count, total_targets)
                    print()
                return True

            print(colorize(f"[debug] method1 returned rc {rc}; trying fallback", "yellow", use_color))
    except Exception as e:
        print(colorize(f"[debug] method1 exception: {e}", "yellow", use_color))

    # Attempt 2: fallback to absolute paths (no cwd)
    cmd2 = ["bash", abs_runner, abs_ws]
    print(colorize(f"[i] running hunter (fallback): {' '.join(cmd2)} -> {hunter_out} (appending)", "green", use_color))
    try:
        with hunter_out.open("a") as fh:
            proc = subprocess.Popen(cmd2, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            cur_count = 0
            header_re = re.compile(r"^\|\s*.*http", re.I)
            try:
                for raw_line in proc.stdout:
                    if raw_line is None:
                        break
                    line = raw_line.rstrip("\n")
                    fh.write(line + "\n")
                    fh.flush()
                    print(line)
                    if show_progress and total_targets > 0:
                        low = line.lower()
                        if "trying default http logins on" in low or header_re.match(line.strip()):
                            cur_count += 1
                            print_progress(cur_count, total_targets)
                rc = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()
                print("\n[!] Hunter run interrupted by user.")
                return False

            if rc != 0:
                print(colorize(f"[!] hunter returned rc {rc} on fallback", "yellow", use_color))
                return False

            if show_progress and total_targets > 0:
                if cur_count < total_targets:
                    cur_count = total_targets
                    print_progress(cur_count, total_targets)
                print()
            return True
    except Exception as e:
        print(colorize(f"[!] fallback failed: {e}", "yellow", use_color))
        return False

# ---------------- Arg parsing ----------------

def build_argparser():
    p = argparse.ArgumentParser(prog="GhostPasswordParser", description="Parse and group default-http-login-hunter output")
    p.add_argument("infile", metavar="INFILE", type=Path, nargs="?", help="hunter output text file (or '-' for stdin)")
    p.add_argument("--redact", action="store_true", help="redact passwords in CSV output")
    p.add_argument("--sep", default="; ", help="separator to join multiple credentials in CSV (default: '; ')")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    p.add_argument("--width", type=int, default=72, help="banner total width (default 72)")
    p.add_argument("--clone", dest="clone", action="store_true", help="clone the default-http-login-hunter repo", default=True)
    p.add_argument("--no-clone", dest="clone", action="store_false", help="do not clone repo")
    p.add_argument("--repo", default="default-http-login-hunter", help="repo directory (default ./default-http-login-hunter)")
    p.add_argument("-n", "--nessus", help="Nessus XML file to extract web servers from (optional)")
    p.add_argument("--webservers", default="web_servers.txt", help="web servers list file (default web_servers.txt)")
    p.add_argument("--hunter-out", default="hunter_raw.txt", help="raw hunter output file (default hunter_raw.txt)")
    p.add_argument("--no-run-hunter", action="store_true", help="skip running the hunter even if repo exists")
    p.add_argument("--outdir", default=".", help="output directory for CSV/JSON files")
    p.add_argument("--stdout", action="store_true", help="also print one-line summary per host to stdout")
    p.add_argument("--no-progress", action="store_true", help="disable live progress bar while hunter runs")
    return p

# ---------------- Main ----------------

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = build_argparser()
    args = ap.parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty()
    print_banner(use_color=use_color, total_width=args.width)
    outdir = Path(args.outdir)

    repo_dir = Path(args.repo)
    if args.clone:
        ok = clone_repo("https://github.com/InfosecMatter/default-http-login-hunter.git", repo_dir, use_color)
        if not ok:
            print(colorize("[!] clone failed (or skipped). If you already have the repo, set --no-clone.", "yellow", use_color))

    hunter_script = None
    if not args.no_run_hunter and repo_dir.exists():
        hunter_script = find_hunter_script(repo_dir)
        if not hunter_script:
            print(colorize(f"[!] could not find a hunter script in {repo_dir}; you may need to run the hunter manually.", "yellow", use_color))

    webservers_path = Path(args.webservers)
    if args.nessus:
        nessus_path = Path(args.nessus)
        if not nessus_path.exists():
            print(colorize(f"[!] Nessus file not found: {nessus_path}", "yellow", use_color))
            sys.exit(2)
        ok = extract_web_servers_from_nessus_builtin(nessus_path, webservers_path, use_color)
        if not ok:
            print(colorize("[!] extraction failed; aborting.", "yellow", use_color))
            sys.exit(1)

    # If hunter should run and we found a runner
    if not args.no_run_hunter and hunter_script:
        ok = run_hunter(hunter_script, webservers_path, Path(args.hunter_out), use_color, show_progress=not args.no_progress)
        if not ok:
            print(colorize("[!] hunter run failed; if you already have hunter output, specify its path as INFILE.", "yellow", use_color))

    # Determine input text for parsing
    if args.infile:
        if args.infile == Path("-"):
            text = sys.stdin.read()
        else:
            infile_path = args.infile
            if not infile_path.exists():
                print(colorize(f"[!] input file not found: {infile_path}", "yellow", use_color))
                sys.exit(2)
            text = infile_path.read_text(errors="ignore")
    else:
        hunter_out = Path(args.hunter_out)
        if hunter_out.exists():
            text = hunter_out.read_text(errors="ignore")
        else:
            print(colorize("[!] No input file provided and hunter output not found. Use INFILE or run with -n/--nessus to auto-generate.", "yellow", use_color))
            sys.exit(2)

    parsed = parse(text)
    cleaned = clean_parsed(parsed)
    write_outputs_grouped(cleaned, outdir=Path(args.outdir), redact=args.redact, sep=args.sep, also_stdout=args.stdout)

if __name__ == "__main__":
    main()
