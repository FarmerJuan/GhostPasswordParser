```markdown
# GhostPasswordParser

GhostPasswordParser is a lightweight helper for pentesters: it extracts web targets from Nessus exports, runs default-http-login-hunter (optionally), streams and saves raw hunter output, then parses, cleans, and groups discovered credentials into tidy CSV and JSON exports.

Think of it as “glue + cleanup” to make credential exports ready for reporting or ingestion.

---

Table of Contents
- Quick overview
- Badges & Requirements
- Quick install
- Usage & examples
- Important flags
- Output files
- Troubleshooting
- Security & legal
- Contributing
- License
- FAQ

---

## Quick overview

What it does (TL;DR)
- Optionally extract web servers from a Nessus `.nessus` file into `web_servers.txt`.
- Optionally clone and run default-http-login-hunter against those targets.
- Stream and save raw hunter output to `hunter_raw.txt`.
- Parse that output, remove noise, group multiple credentials per host into a single CSV cell, and export:
  - `hunter_parsed_grouped.csv`
  - `hunter_parsed_grouped.json`

---

## Requirements

- Linux (Kali or Debian-based recommended)
- Python 3.8+
- git in $PATH
- Optional: jq, csvkit for nicer inspection

Install basics:

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

---

## Quick install

1. Clone your repo (or create one) and add `GhostPasswordParser.py`.
2. Run from repo root.

Full run (clone hunter, extract from Nessus, run hunter, parse results):

```bash
python3 GhostPasswordParser.py -n scan.nessus --outdir results
```

Parse only (hunter output already exists):

```bash
python3 GhostPasswordParser.py hunter_raw.txt --outdir results
```

---

## Usage & examples

Usage: `GhostPasswordParser.py [INFILE] [flags]`

Examples:

1) Full pipeline using a Nessus file

```bash
python3 GhostPasswordParser.py -n example_scan.nessus --outdir ./results
```

2) Parse existing hunter output and redact passwords

```bash
python3 GhostPasswordParser.py hunter_raw.txt --outdir ./results --redact
```

3) Skip cloning (you already have the hunter repo locally)

```bash
python3 GhostPasswordParser.py -n example_scan.nessus --no-clone
```

4) Save outputs to a custom folder

```bash
python3 GhostPasswordParser.py -n example_scan.nessus --outdir /tmp/ghost_results
```

---

## Important flags

- `-n, --nessus FILE` — Nessus XML to extract web servers from
- `--no-clone` — don't clone default-http-login-hunter
- `--no-run-hunter` — skip running hunter (parse-only)
- `--hunter-out FILE` — path for raw hunter output (default `hunter_raw.txt`)
- `--outdir DIR` — directory for CSV/JSON outputs (default `.`)
- `--redact` — replace passwords with `REDACTED` in CSV
- `--sep SEP` — separator for multiple creds in CSV (default `;`)

Tip: a `--hunter-args` flag to forward arguments to the hunter would be handy (suggested contribution).

---

## Output files

- `web_servers.txt` — extracted targets (one URL per line)
- `hunter_raw.txt` — raw stdout/stderr captured from the hunter run
- `hunter_parsed_grouped.csv` — one row per host; multiple credentials grouped in one cell
- `hunter_parsed_grouped.json` — full parsed structure for programmatic use

---

## Troubleshooting & tips

- No creds found: verify targets are reachable (try `curl -I http://IP:PORT/`).
- Malformed `web_servers.txt`: open it and inspect a few lines — your Nessus exporter might need adjustment. Paste examples if you want me to tune the extractor.
- Hunter script failing with "No such file or directory": the wrapper runs hunter from inside the hunter repo; do not pass the repo path as the runner argument. Use `--no-clone` if you maintain the hunter repo yourself.
- Want verbose hunter output: run the hunter manually with `-vvv` or ask to add a `--hunter-args` passthrough.
- Large runs: use a beefy VM and ensure you have written permission to test targets.

---

## Security & Legal (read this)

Do not run this tool against systems you are not authorized to test. Attempting logins against third-party hosts without explicit permission is illegal in many jurisdictions. Use only against:

- assets you own, or
- assets you have explicit permission to test (scope in a signed engagement).

Handle credential exports securely. Use `--redact` if storing results in less-secure places.

---

## Contributing

PRs welcome. Suggested contributions:
- Add `--hunter-args` passthrough to tune hunter verbosity
- Improve Nessus parsing (support more shapes of `svc_name`)
- Add unit tests for the parser (sample hunter outputs)
- Improve CSV/JSON schema for SIEM ingestion

When opening a PR:
- keep changes small and focused
- add a short explanation of "why"
- include sample input/output where relevant

---

## License

Suggested: MIT. Add a `LICENSE` file with the MIT text if you want this to be public under MIT terms. If you prefer a different license, replace accordingly.

---

## FAQ

Q: Can I make the repo private?
A: Yes — host it in a private GitHub repo and add collaborators or a team. GitHub manages access via account permissions and tokens.

Q: How do I run only parsing on a saved hunter output?
A: `python3 GhostPasswordParser.py hunter_raw.txt --outdir results`

---

If you'd like, I can:
- Add a short example of the expected `hunter_raw.txt` input and the exact parser output,
- Convert this README into a template with badges filled in automatically,
- Or open a small PR updating the repo README directly.
```
