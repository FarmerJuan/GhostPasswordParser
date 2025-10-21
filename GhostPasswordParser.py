#!/usr/bin/env python3
"""
GhostPasswordParser.py

Parse default-http-login-hunter output, clean noise, group credentials per host
into a single CSV cell, and print a Ghost Energy–themed banner on start.

Usage:
    python3 GhostPasswordParser.py hunter_output.txt
    python3 GhostPasswordParser.py hunter_output.txt --redact --sep " | " --width 80

Flags:
    --redact            : redact passwords in the CSV output (replace with 'REDACTED')
    --sep SEP           : separator used to join creds in CSV (default: '; ')
    --no-color          : disable ANSI color output
    --width N           : banner total width (default: 72)
    --clone             : clone https://github.com/InfosecMatter/default-http-login-hunter.git (default: true)
    --repo DIR          : directory to clone repo into (default: ./default-http-login-hunter)
    --extractor PATH    : path to your Nessus->webservers extractor script (optional)
    -n/--nessus FILE    : path to a Nessus XML file to extract webserver URLs from (optional)
    --webservers FILE   : path to webservers list file (default: webservers.txt)
    --hunter-out FILE   : raw hunter output path (default: hunter_raw.txt)
    --no-run-hunter     : skip running the hunter even if repo exists
    --outdir DIR        : output directory for CSV/JSON files (default: .)
    --stdout            : also print one-line summary per host to stdout
    --no-progress       : disable live progress bar while hunter runs
"""
from __future__ import annotations
import sys, re, csv, json, argparse, subprocess, shutil, time
from pathlib import Path
from datetime import datetime, timezone

__version__ = "1.3"
__author__ = "GhostPasswordParser (adapted for you)"

ANSI = {"bold":"\033[1m","reset":"\033[0m","cyan":"\033[96m","magenta":"\033[95m","green":"\033[92m","yellow":"\033[93m","white":"\033[97m"}

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
        " Clean • Group • Export"
    ]
    top = colorize("╔" + "═" * (total_width - 2) + "╗", "magenta", use_color)
    bottom = colorize("╚" + "═" * (total_width - 2) + "╝", "magenta", use_color)
    print(top)
    for i in range(max(len(BANNER_LINES), len(meta_lines))):
        art_ln = BANNER_LINES[i] if i < len(BANNER_LINES) else ""
        art_col = art_ln.ljust(art_width)
        meta_ln = meta_lines[i] if i < len(meta_lines) else ""
        if len(meta_ln) > meta_width:
            meta_ln = meta_ln[:max(0, meta_width - 3)] + "..."
        art_col_colored = colorize(art_col, "cyan", use_color)
        meta_colored = colorize(meta_ln.ljust(meta_width), "magenta", use_color)
        line = colorize("║ ", "magenta", use_color) + art_col_colored + " " + meta_colored + colorize(" ║", "magenta", use_color)
        print(line)
    print(bottom)
    print()

def extract_ip_port(header: str) -> tuple[str | None, int | None]:
    ip_port_re = re.compile(r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})[:\.](?P<port>\d{1,5})')
    m = ip_port_re.search(header)
    if m:
        return m.group('ip'), int(m.group('port'))
    ip_re = re.compile(r'((?:\d{1,3}\.){3}\d{1,3})')
    ipm = ip_re.search(header)
    if ipm:
        ip = ipm.group(1)
        after = header[ipm.end():]
        portm = re.search(r'[:\.\s](\d{1,5})', after)
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
    if 'trying default http logins on' in line.lower():
        return True
    return False

def is_junk_header(hdr: str) -> bool:
    if not hdr or not hdr.strip():
        return True
    if 'error: http request table is empty' in hdr.lower():
        return True
    if 'trying default http logins on' in hdr.lower():
        return True
    if re.fullmatch(r'[_\|\s\-]+', hdr.strip()):
        return True
    if hdr.strip().startswith('_') and len(hdr.strip()) < 80:
        if not re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hdr):
            return True
    return False

def is_junk_cred(u: str | None, p: str | None) -> bool:
    if not u or not p:
        return True
    u = u.strip(); p = p.strip()
    if not u or not p:
        return True
    if re.fullmatch(r'[_\|\-]{1,10}', u) or re.fullmatch(r'[_\|\-]{1,10}', p):
        return True
    return False

def parse(text: str) -> list[dict]:
    results: list[dict] = []
    lines = text.splitlines()
    header_re = re.compile(r'^\|\s*(?P<header>.+)$')
    bracket_re = re.compile(r'\[([^\]]+)\]')
    cred_re = re.compile(r'([A-Za-z0-9_.+\-]{1,64}):([^\s:]{1,128})')
    cur = None
    for ln in lines:
        s = ln.rstrip('\n')
        if is_useless_timestamp_line(s):
            continue
        m = header_re.match(s.strip())
        if m and ('http' in s.lower() or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)):
            if cur is not None and cur.get('creds'):
                results.append(cur)
            header = m.group('header').strip()
            ip, port = extract_ip_port(header)
            cur = {'host_header': header, 'ip': ip, 'port': port, 'display_name': None, 'creds': [], 'raw_block': [s.strip()]}
            continue
        if cur is not None:
            cur['raw_block'].append(s.strip())
            b = bracket_re.search(s)
            if b:
                cur['display_name'] = b.group(1).strip()
            if is_useless_timestamp_line(s):
                continue
            for user, pw in cred_re.findall(s):
                if user.lower().startswith('http') or user.lower().endswith('http'):
                    continue
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', user):
                    continue
                if user in ('at', 'www', 'http', 'https'):
                    continue
                cur['creds'].append({'username': user.strip(), 'password': pw.strip(), 'raw_line': s.strip()})
    if cur is not None and cur.get('creds'):
        results.append(cur)
    return results

def clean_parsed(parsed: list[dict]) -> list[dict]:
    cleaned: list[dict] = []
    for block in parsed:
        hdr = (block.get('host_header') or '').strip()
        if is_junk_header(hdr):
            continue
        good_creds = []
        for c in block.get('creds', []):
            u = (c.get('username') or '').strip()
            p = (c.get('password') or '').strip()
            raw = (c.get('raw_line') or '')
            if is_useless_timestamp_line(raw):
                continue
            if is_junk_cred(u, p):
                continue
            good_creds.append({'username': u, 'password': p, 'raw_line': raw})
        if not good_creds:
            continue
        nb = {'host_header': hdr, 'ip': block.get('ip'), 'port': block.get('port'), 'display_name': block.get('display_name'), 'creds': good_creds, 'raw_block': block.get('raw_block', [])}
        cleaned.append(nb)
    return cleaned

def write_outputs_grouped(parsed: list[dict], outdir: Path, redact: bool = False, sep: str = '; ', also_stdout: bool = False):
    outdir.mkdir(parents=True, exist_ok=True)
    csv_out = outdir / 'hunter_parsed_grouped.csv'
    json_out = outdir / 'hunter_parsed_grouped.json'
    with csv_out.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['host_header','ip','port','display_name','all_creds','raw_block'])
        writer.writeheader()
        for block in parsed:
            creds_joined = []
            for c in block.get('creds', []):
                user = c['username']
                pw = 'REDACTED' if redact else c['password']
                creds_joined.append(f"{user}:{pw}")
            creds_joined_str = sep.join(creds_joined)
            writer.writerow({'host_header': block.get('host_header',''),'ip': block.get('ip','') or '','port': block.get('port','') or '','display_name': block.get('display_name','') or '','all_creds': creds_joined_str,'raw_block': "\\n".join(block.get('raw_block', []))})
    with json_out.open('w') as f:
        json.dump(parsed, f, indent=2)
    total_creds = sum(len(b.get('creds', [])) for b in parsed)
    print(f"Parsed {total_creds} credential entries across {len(parsed)} host blocks.")
    print(f"CSV -> {csv_out.resolve()}")
    print(f"JSON -> {json_out.resolve()}")
    if also_stdout:
        for block in parsed:
            host = block.get('host_header','')
            creds = '; '.join(f"{c['username']}:{('REDACTED' if redact else c['password'])}" for c in block.get('creds', []))
            print(f"{host}  ->  {creds}")

def run_cmd(cmd: list[str], cwd: Path | None = None, capture: bool = False, check: bool = False):
    try:
        if capture:
            res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check)
            return res.stdout, res.stderr, res.returncode
        else:
            res = subprocess.run(cmd, cwd=cwd, check=check)
            return None, None, res.returncode
    except subprocess.CalledProcessError as e:
        return getattr(e, 'stdout', ''), getattr(e, 'stderr', ''), getattr(e, 'returncode', 1)
    except FileNotFoundError:
        return '', f'command not found: {cmd[0]}', 127

def find_hunter_script(repo_dir: Path) -> Path | None:
    candidates = []
    for p in repo_dir.rglob('*'):
        if p.is_file() and p.stat().st_mode & 0o111:
            name = p.name.lower()
            if 'default' in name and 'login' in name and 'hunter' in name:
                candidates.append(p)
    if not candidates:
        for p in repo_dir.glob('*.sh'):
            candidates.append(p)
    return candidates[0] if candidates else None

def clone_repo(repo_url: str, target: Path, use_color: bool):
    if target.exists():
        print(colorize(f"[i] repo directory exists: {target}", "yellow", use_color))
        return True
    git_path = shutil.which('git')
    if not git_path:
        print(colorize("[!] git not found on PATH; cannot clone repository.", "yellow", use_color))
        return False
    print(colorize(f"[i] Cloning {repo_url} -> {target}", "green", use_color))
    out, err, rc = run_cmd(['git','clone',repo_url,str(target)], capture=True)
    if rc != 0:
        print(colorize(f"[!] git clone failed: {err or out}", "yellow", use_color))
        return False
    return True

def count_webservers(webservers_path: Path) -> int:
    if not webservers_path.exists():
        return 0
    cnt = 0
    for line in webservers_path.read_text(errors='ignore').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        cnt += 1
    return cnt

def print_progress(cur: int, total: int, width: int = 30):
    if total <= 0:
        return
    frac = min(1.0, max(0.0, cur / total))
    filled = int(frac * width)
    bar = '#' * filled + '.' * (width - filled)
    print(f"\rProgress: [{bar}] {cur}/{total}", end='', flush=True)

def run_hunter(hunter_script: Path, webservers: Path, hunter_out: Path, use_color: bool, show_progress: bool = True):
    if not hunter_script or not hunter_script.exists():
        print(colorize(f"[!] hunter script not found: {hunter_script}", "yellow", use_color)); return False
    if not webservers.exists():
        print(colorize(f"[!] webservers list not found: {webservers}", "yellow", use_color)); return False
    total_targets = count_webservers(webservers)
    print(colorize(f"[i] running hunter: {hunter_script} {webservers} -> {hunter_out}", "green", use_color))
    try:
        # Run hunter and stream stdout+stderr
        with hunter_out.open('w') as fh:
            proc = subprocess.Popen([str(hunter_script), str(webservers)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=hunter_script.parent, text=True, bufsize=1)
            cur_count = 0
            header_re = re.compile(r'^\|\s*.*http', re.I)
            try:
                for raw_line in proc.stdout:
                    if raw_line is None:
                        break
                    line = raw_line.rstrip('\n')
                    # write output to file
                    fh.write(line + '\n')
                    fh.flush()
                    # print live to terminal
                    print(line)
                    # progress heuristics: increment on timestamp/status or header-like line
                    if show_progress and total_targets > 0:
                        low = line.lower()
                        if 'trying default http logins on' in low:
                            cur_count += 1
                            print_progress(cur_count, total_targets)
                        else:
                            # header line like "| ip:80.http....:"
                            if header_re.match(line.strip()):
                                cur_count += 1
                                print_progress(cur_count, total_targets)
                rc = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                proc.wait()
                print("\n[!] Hunter run interrupted by user.")
                return False
            # finalize progress display
            if show_progress and total_targets > 0:
                if cur_count < total_targets:
                    cur_count = total_targets
                    print_progress(cur_count, total_targets)
                print()  # newline after progress bar
            if rc != 0:
                print(colorize(f"[!] hunter returned rc {rc}", "yellow", use_color))
                return False
    except Exception as e:
        print(colorize(f"[!] failed to run hunter: {e}", "yellow", use_color))
        return False
    return True

def run_extractor(extractor: Path, nessus: Path, webservers: Path, use_color: bool):
    if not extractor.exists():
        print(colorize(f"[!] extractor not found: {extractor}", "yellow", use_color)); return False
    print(colorize(f"[i] running extractor: {extractor} {nessus}", "green", use_color))
    out, err, rc = run_cmd(['python3', str(extractor), str(nessus)], capture=True)
    if rc != 0:
        print(colorize(f"[!] extractor failed (rc {rc}): {err or out}", "yellow", use_color)); return False
    if webservers.exists():
        print(colorize(f"[i] webservers list produced: {webservers}", "green", use_color)); return True
    return True

def build_argparser():
    p = argparse.ArgumentParser(prog="GhostPasswordParser", description="Parse and group default-http-login-hunter output")
    p.add_argument("infile", metavar="INFILE", type=Path, nargs='?', help="hunter output text file (or '-' for stdin)")
    p.add_argument("--redact", action="store_true", help="redact passwords in CSV output")
    p.add_argument("--sep", default="; ", help="separator to join multiple credentials in CSV (default: '; ')")
    p.add_argument("--no-color", action="store_true", help="disable colored banner output")
    p.add_argument("--width", type=int, default=72, help="banner total width (default 72)")
    p.add_argument("--clone", dest="clone", action="store_true", help="clone the default-http-login-hunter repo", default=True)
    p.add_argument("--no-clone", dest="clone", action="store_false", help="do not clone repo")
    p.add_argument("--repo", default="default-http-login-hunter", help="repo directory (default ./default-http-login-hunter)")
    p.add_argument("--extractor", help="path to Nessus->webservers extractor script (optional)")
    p.add_argument("-n","--nessus", help="Nessus XML file to extract webservers from (optional)")
    p.add_argument("--webservers", default="webservers.txt", help="webservers list file (default webservers.txt)")
    p.add_argument("--hunter-out", default="hunter_raw.txt", help="raw hunter output file (default hunter_raw.txt)")
    p.add_argument("--no-run-hunter", action="store_true", help="skip running the hunter even if repo exists")
    p.add_argument("--outdir", default=".", help="output directory for CSV/JSON files")
    p.add_argument("--stdout", action="store_true", help="also print one-line summary per host to stdout")
    p.add_argument("--no-progress", action="store_true", help="disable live progress bar while hunter runs")
    return p

def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = build_argparser()
    args = ap.parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty()
    print_banner(use_color=use_color, total_width=args.width)
    outdir = Path(args.outdir)
    if args.nessus and args.extractor:
        nessus = Path(args.nessus)
        extractor = Path(args.extractor)
        webservers = Path(args.webservers)
        if not nessus.exists():
            print(colorize(f"[!] Nessus file not found: {nessus}", "yellow", use_color)); sys.exit(2)
        ok = run_extractor(extractor, nessus, webservers, use_color)
        if not ok:
            print(colorize("[!] extractor failed; aborting.", "yellow", use_color)); sys.exit(1)
    if args.clone:
        repo_dir = Path(args.repo)
        ok = clone_repo("https://github.com/InfosecMatter/default-http-login-hunter.git", repo_dir, use_color)
        if not ok:
            print(colorize("[!] clone failed (or skipped). If you already have the repo, set --no-clone.", "yellow", use_color))
    repo_dir = Path(args.repo)
    hunter_script = None
    if not args.no_run_hunter and repo_dir.exists():
        hunter_script = find_hunter_script(repo_dir)
        if not hunter_script:
            print(colorize(f"[!] could not find a hunter script in {repo_dir}; you may need to run the hunter manually.", "yellow", use_color))
        else:
            webservers = Path(args.webservers)
            hunter_out = Path(args.hunter_out)
            ok = run_hunter(hunter_script, webservers, hunter_out, use_color, show_progress=not args.no_progress)
            if not ok:
                print(colorize("[!] hunter run failed; if you already have hunter output, specify its path as INFILE.", "yellow", use_color))
    infile_path = None
    if args.infile:
        if args.infile == Path('-'):
            text = sys.stdin.read()
            infile_path = None
        else:
            infile_path = args.infile
            if not infile_path.exists():
                print(colorize(f"[!] input file not found: {infile_path}", "yellow", use_color)); sys.exit(2)
            text = infile_path.read_text(errors='ignore')
    else:
        hunter_out = Path(args.hunter_out)
        if hunter_out.exists():
            text = hunter_out.read_text(errors='ignore')
        else:
            print(colorize("[!] No input file provided and hunter output not found. Use INFILE or run with -n/--nessus to auto-generate.", "yellow", use_color))
            sys.exit(2)
    parsed = parse(text)
    cleaned = clean_parsed(parsed)
    write_outputs_grouped(cleaned, outdir=Path(args.outdir), redact=args.redact, sep=args.sep, also_stdout=args.stdout)

if __name__ == "__main__":
    main()
