GhostPasswordParser

Ghost Energy–style parser for default-http-login-hunter output — extract web targets from Nessus, run the hunter, stream raw output, and produce cleaned, grouped credential exports (CSV + JSON).
Fast, practical, and made for pentesters who want tidy results.

🔥 What it does (TL;DR)

Optionally extracts web servers from a Nessus .nessus file into web_servers.txt.

Optionally clones default-http-login-hunter and runs it against the extracted target list.

Streams all raw hunter output to your console and saves it to hunter_raw.txt.

Parses that output, removes noise, groups multiple credentials per host into a single CSV cell, and exports:

hunter_parsed_grouped.csv

hunter_parsed_grouped.json

Think of GhostPasswordParser as “glue + cleanup” so your creds are export-ready.

📦 Badges (drop-in)

You can paste these into the top of your repo README.md:

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)]
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)]
[![GitHub Release](https://img.shields.io/github/v/release/<youruser>/<repo>?label=release)]


Replace <youruser>/<repo> with your GitHub repo path.

✅ Requirements

Linux (Kali or Debian-based recommended)

Python 3.8+

git in $PATH

Optional: jq, csvkit for nice inspection

Install basics:

sudo apt update
sudo apt install -y python3 python3-pip git

🚀 Quick install

Clone your repo (or create one) and add GhostPasswordParser.py.

Run from repo root:

# full run: clone hunter, extract from Nessus, run hunter, parse results
python3 GhostPasswordParser.py -n scan.nessus --outdir results

# run parser only on existing output
python3 GhostPasswordParser.py hunter_raw.txt --outdir results

🧭 Usage & examples
usage: GhostPasswordParser.py [INFILE] [flags]

Examples:
# 1) Full automated pipeline using a Nessus file
python3 GhostPasswordParser.py -n example_scan.nessus --outdir ./results

# 2) Hunter output already exists; parse only
python3 GhostPasswordParser.py hunter_raw.txt --outdir ./results --redact

# 3) Skip cloning (you already have hunter)
python3 GhostPasswordParser.py -n example_scan.nessus --no-clone

# 4) Write outputs to a specific folder
python3 GhostPasswordParser.py -n example_scan.nessus --outdir /tmp/ghost_results


Important flags:

-n, --nessus FILE — Nessus XML to extract web servers from

--no-clone — don't clone default-http-login-hunter

--no-run-hunter — skip running hunter (parse-only)

--hunter-out FILE — path for raw hunter output (default hunter_raw.txt)

--outdir DIR — where CSV/JSON are saved (default .)

--redact — replace passwords with REDACTED in CSV

--sep SEP — separator for multiple creds in CSV (default ; )

🗂 Output files

web_servers.txt — extracted targets (one URL per line)

hunter_raw.txt — raw stdout/stderr captured from the hunter run

hunter_parsed_grouped.csv — one row per host; multiple creds grouped in one cell

hunter_parsed_grouped.json — full parsed structure for programmatic use

🔎 Troubleshooting & tips

No creds found: verify targets are reachable (try curl -I http://IP:PORT/).

Malformed web_servers.txt: open the file; your Nessus extractor might need adjustment. Paste a few lines if you want me to tune it.

Hunter script failing with No such file or directory: script runs hunter from inside the hunter repo; don't pass the repo path as the runner argument. Use --no-clone if you maintain the repo yourself.

Want verbose hunter output: run the hunter manually with -vvv or ask me to add a --hunter-args flag.

Large runs: consider running on a beefy VM and ensure you have permission to test the targets.

🔐 Security & Legal (read this)

Do not run this tool against systems you are not authorized to test. Running login attempts against third-party hosts without explicit permission is illegal in many jurisdictions. Use only against:

assets you own, or

assets you have written permission to test (explicit scope in a signed engagement).

Handle all credential exports securely. Use --redact if you need to store results in less-secure locations.

✍️ Contributing

PRs welcome. Suggested contributions:

Add --hunter-args to tune hunter verbosity.

Improve Nessus parsing (support more shapes of svc_name).

Add unit tests for the parser (sample hunter outputs).

Improve CSV/JSON schema for SIEM ingestion.

When opening a PR:

keep changes small and focused,

add a short note explaining why,

include sample input/output where relevant.

🧾 License

Suggested: MIT (simple, permissive). Add a LICENSE file with the MIT text if you want to make it public.
If you prefer a different license, choose one that matches how you want others to reuse the project.

📌 FAQ (short)

Q: Can I make the repo private so only some people can clone with a special link?
A: Yes — host it in a private GitHub repo and add those people as collaborators or a team. There is no special clone link per-user; GitHub manages access via account permissions and tokens.

Q: How do I run only parsing on a saved hunter output?
A: python3 GhostPasswordParser.py hunter_raw.txt --outdir results
