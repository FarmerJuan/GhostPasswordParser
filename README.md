# GhostParser

**GhostParser** is an all-in-one pentesting helper that:
1. Extracts web servers from a Nessus export into `web_servers.txt`
2. Runs an **OOS SSRF check** against those targets (inlined — no second script needed)
3. Clones and runs **default-http-login-hunter** against the same targets
4. Parses, cleans, and groups discovered credentials into **CSV** and **JSON**
5. Writes SSRF results to a colour-coded **Excel workbook** (`ssrf_results.xlsx`)

---

## Requirements

- **Linux / Kali recommended** — the hunter needs `bash` + `git`
- Python 3.8+
- `git` in `$PATH` (for cloning the hunter repo)

```bash
sudo apt update && sudo apt install -y python3 python3-pip git
pip3 install requests urllib3 openpyxl
```

> **Windows users:** The SSRF check runs fine on Windows. The hunter step requires Kali/Linux (or WSL with git + bash).

---

## Quick install

Drop `GhostParser.py` anywhere and run it. No companion scripts required.

---

## Usage

```
python3 GhostParser.py [INFILE] [flags]
```

### Common workflows

**Full pipeline — Nessus file → SSRF → hunter → CSV/JSON**
```bash
python3 GhostParser.py -n scan.nessus --outdir results
```

**Existing web server list → SSRF → hunter → CSV/JSON**
```bash
python3 GhostParser.py --webservers webs.txt --outdir results
```

**SSRF only (no hunter)**
```bash
python3 GhostParser.py --webservers webs.txt --no-run-hunter
```

**Parse existing hunter output (skip SSRF + hunter)**
```bash
python3 GhostParser.py hunter_raw.txt --outdir results --no-ssrf-check
```

**Redact passwords in CSV output**
```bash
python3 GhostParser.py -n scan.nessus --outdir results --redact
```

**Reuse existing webhook.site token (avoid rate-limits)**
```bash
python3 GhostParser.py --webservers webs.txt --ssrf-webhook <token>
```

---

## Pipeline flow

```
  -n nessusfile.nessus
        │
        ▼
  Extract web_servers.txt
        │
        ▼  (or start here with --webservers webs.txt)
  OOS SSRF Check  ──► ssrf_results.xlsx
        │
        ▼
  default-http-login-hunter  ──► hunter_raw.txt
        │
        ▼
  Parse & group credentials
        │
        ├──► hunter_parsed_grouped.csv
        └──► hunter_parsed_grouped.json
```

---

## Flags

### Core

| Flag | Default | Description |
|---|---|---|
| `INFILE` | — | Hunter output to parse directly |
| `-n, --nessus FILE` | — | Nessus XML to extract web servers from |
| `--webservers FILE` | `web_servers.txt` | Web servers list |
| `--hunter-out FILE` | `hunter_raw.txt` | Raw hunter output path |
| `--no-clone` | — | Skip cloning the hunter repo |
| `--repo DIR` | `./default-http-login-hunter` | Hunter repo directory |
| `--no-run-hunter` | — | Skip running the hunter |
| `--outdir DIR` | `.` | Output directory for CSV/JSON |
| `--redact` | — | Replace passwords with `REDACTED` in CSV |
| `--sep SEP` | `; ` | Separator for multiple creds in CSV cell |
| `--stdout` | — | Print one-line summary per host to stdout |

### OOS SSRF Check

| Flag | Default | Description |
|---|---|---|
| `--ssrf-check` / `--no-ssrf-check` | on | Toggle the SSRF scan |
| `--ssrf-threads N` | `10` | Concurrent scan threads |
| `--ssrf-timeout SEC` | `15` | Max wait for OOB callback |
| `--ssrf-webhook TOKEN` | — | Reuse an existing webhook.site token |
| `--ssrf-output FILE` | `ssrf_results.xlsx` | Excel output file |

---

## Output files

| File | Description |
|---|---|
| `web_servers.txt` | Extracted targets — one URL per line |
| `ssrf_results.xlsx` | Colour-coded Excel: Target, WOPI Endpoint, SSRF, OOS Version, Callback IP |
| `hunter_raw.txt` | Raw stdout from the hunter |
| `hunter_parsed_grouped.csv` | One row per host; creds grouped in one cell |
| `hunter_parsed_grouped.json` | Full parsed structure |

### Excel colour key

| Colour | Meaning |
|---|---|
| 🟢 Green | Confirmed SSRF vulnerable |
| 🟡 Yellow | OOS + WOPI detected, no SSRF callback |
| 🔴 Red | OOS detected, not vulnerable |
| ⬜ Grey | Not an OOS server |

> If `openpyxl` is not installed, a plain `.csv` is written instead.

---

## Troubleshooting

- **git not found** — install git or run on Kali (hunter requires it; SSRF check does not)
- **`requests`/`urllib3` missing** — run `pip3 install requests urllib3`
- **`openpyxl` missing** — run `pip3 install openpyxl` (falls back to CSV)
- **No hunter output to parse** — if hunter didn't run, GhostParser exits cleanly after the SSRF scan with no error
- **Malformed `web_servers.txt`** — inspect a few lines; your Nessus exporter may need tuning

---

## Security & Legal

Only use against systems you **own** or have **explicit written permission** to test. Credential spraying and SSRF probing against unauthorised systems is illegal. Use `--redact` when storing results in less-secure locations.

---

## Contributing

PRs welcome. Ideas:
- `--hunter-args` passthrough for verbose hunter output
- Additional Nessus `svc_name` shapes
- SIEM-compatible JSON schema
- Unit tests with sample hunter output
