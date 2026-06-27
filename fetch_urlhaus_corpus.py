#!/usr/bin/env python3
"""
fetch_urlhaus_corpus.py

Pulls recent malware-distribution URLs from the URLhaus Community API
and builds a defanged hostname corpus for stress-testing the HASS
Aho-Corasick engine (aho_corasick.v / build_ac_table.py).

This is a SEPARATE stress-test corpus, not a replacement for the
curated 22-pattern "No-Fly List" table. The curated table stays as
the known-good baseline; this script gives you a larger, real-world
sample to validate matching at scale (state count, false-positive
rate, build_ac_table.py performance on bigger inputs).

-----------------------------------------------------------------------
SAFETY / OUTPUT POLICY
-----------------------------------------------------------------------
- This script never prints or writes a clickable/working URL.
- Every hostname written to disk or stdout has '.' replaced with '[.]'
  (the standard "defanging" convention used across threat-intel
  tooling) so nothing here is copy-paste-live.
- The script does NOT fetch payloads, does NOT visit the URLs, and
  does NOT include the URL path/query, only the registered hostname.
- Output files are local artifacts for your test bench only -- don't
  publish the corpus file somewhere with copy-paste-and-go convenience
  unless you re-derive that's intentional (e.g. for a research paper
  appendix, hashing is preferable to defanging).

-----------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------
1. Get/rotate your Auth-Key at https://auth.abuse.ch/
2. Set it as an environment variable (NEVER hardcode it in source):
     export URLHAUS_AUTH_KEY="your-key-here"          (Linux/macOS)
     setx URLHAUS_AUTH_KEY "your-key-here"             (Windows, new shell)
3. Run:
     python3 fetch_urlhaus_corpus.py --limit 150

Output files (written to ./urlhaus_corpus/):
  - hostnames_defanged.txt   one defanged hostname per line (for humans/review)
  - hostnames_raw.txt        one REAL hostname per line (for build_ac_table.py)
  - metadata.csv             id, hostname(defanged), family tags, first_seen, url_status
  - fetch_summary.txt        run stats for your ISEF methodology writeup

NOTE on hostnames_raw.txt: this contains real hostnames (no scheme,
no path -- e.g. "evil-example[.]com" becomes "evil-example.com" only
in this one file). It is the ONLY non-defanged artifact, it is local,
and it exists because build_ac_table.py needs literal bytes to compile
the DFA. It is never printed to stdout and the script does not upload
or transmit it anywhere.
"""

import argparse
import csv
import os
import ssl
import sys
import time
from urllib import request, error
from urllib.parse import urlparse

try:
    import certifi
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    # Fall back to system default if certifi isn't installed.
    # (Run `pip install certifi` if you hit CERTIFICATE_VERIFY_FAILED.)
    SSL_CONTEXT = ssl.create_default_context()

API_BASE = "https://urlhaus-api.abuse.ch/v1"
RECENT_ENDPOINT = "{base}/urls/recent/limit/{limit}/"

OUTPUT_DIR = "urlhaus_corpus"


def defang(hostname: str) -> str:
    """Replace '.' with '[.]' so the string can't be clicked/resolved by accident."""
    return hostname.replace(".", "[.]")


def fetch_recent_urls(auth_key: str, limit: int, timeout: int = 15) -> dict:
    """Call URLhaus 'recent URLs' endpoint. Returns parsed JSON dict."""
    url = RECENT_ENDPOINT.format(base=API_BASE, limit=limit)
    req = request.Request(url, headers={"Auth-Key": auth_key})
    try:
        with request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
            raw = resp.read()
    except error.HTTPError as e:
        sys.exit(f"[fatal] HTTP {e.code} from URLhaus API: {e.reason}\n"
                  f"        Check that your Auth-Key is valid and not rate-limited.")
    except error.URLError as e:
        sys.exit(f"[fatal] Network error reaching URLhaus API: {e.reason}")

    import json
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        sys.exit("[fatal] URLhaus API did not return valid JSON. Response may have "
                  "changed format -- check https://urlhaus.abuse.ch/api/ for updates.")


def extract_hostname(full_url: str) -> str:
    """Pull just the registered hostname out of a full URL, no scheme/path/port."""
    parsed = urlparse(full_url)
    host = parsed.hostname or ""
    return host.lower()


def is_ip_literal(host: str) -> bool:
    """Skip bare-IP entries -- the AC engine matches domain-name byte patterns,
    not IPs, so IP-literal hosts aren't useful test vectors for this engine."""
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=150,
                     help="Number of recent URLhaus entries to fetch (API max: 1000, default: 150)")
    ap.add_argument("--auth-key", default=None,
                     help="Auth-Key (prefer env var URLHAUS_AUTH_KEY instead)")
    args = ap.parse_args()

    auth_key = args.auth_key or os.environ.get("URLHAUS_AUTH_KEY")
    if not auth_key:
        sys.exit(
            "[fatal] No Auth-Key provided.\n"
            "        Set it via:  export URLHAUS_AUTH_KEY=\"your-key\"\n"
            "        Get/rotate a key at https://auth.abuse.ch/\n"
            "        (Do not pass keys on the command line in shared terminals/scripts.)"
        )

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"[*] Requesting {args.limit} recent entries from URLhaus...")
    data = fetch_recent_urls(auth_key, args.limit)

    if data.get("query_status") != "ok":
        sys.exit(f"[fatal] URLhaus query_status = {data.get('query_status')!r}")

    entries = data.get("urls", [])
    print(f"[*] Received {len(entries)} entries.")

    seen_hosts = set()
    rows = []  # for metadata.csv

    for entry in entries:
        full_url = entry.get("url", "")
        host = extract_hostname(full_url)
        if not host:
            continue
        if is_ip_literal(host):
            continue
        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        rows.append({
            "id": entry.get("id", ""),
            "hostname_defanged": defang(host),
            "tags": ";".join(entry.get("tags") or []),
            "threat": entry.get("threat", ""),
            "date_added": entry.get("date_added", ""),
            "url_status": entry.get("url_status", ""),
        })

    if not rows:
        sys.exit("[fatal] No usable hostnames extracted from response -- "
                  "check API response format hasn't changed.")

    # --- Write outputs ---
    raw_path = os.path.join(OUTPUT_DIR, "hostnames_raw.txt")
    defanged_path = os.path.join(OUTPUT_DIR, "hostnames_defanged.txt")
    meta_path = os.path.join(OUTPUT_DIR, "metadata.csv")
    summary_path = os.path.join(OUTPUT_DIR, "fetch_summary.txt")

    with open(raw_path, "w") as f:
        for r in rows:
            f.write(r["hostname_defanged"].replace("[.]", ".") + "\n")

    with open(defanged_path, "w") as f:
        for r in rows:
            f.write(r["hostname_defanged"] + "\n")

    with open(meta_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "id", "hostname_defanged", "tags", "threat", "date_added", "url_status"
        ])
        writer.writeheader()
        writer.writerows(rows)

    family_counts = {}
    for r in rows:
        for tag in r["tags"].split(";"):
            if tag:
                family_counts[tag] = family_counts.get(tag, 0) + 1

    with open(summary_path, "w") as f:
        f.write(f"URLhaus stress-test corpus -- fetched {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"Requested limit: {args.limit}\n")
        f.write(f"Raw entries returned: {len(entries)}\n")
        f.write(f"Unique non-IP hostnames extracted: {len(rows)}\n")
        f.write(f"\nTop malware family tags in this sample:\n")
        for tag, count in sorted(family_counts.items(), key=lambda x: -x[1])[:15]:
            f.write(f"  {tag:20s} {count}\n")
        f.write(f"\nFor build_ac_table.py: feed it {raw_path}\n")
        f.write(f"For human review (safe to view/share): {defanged_path}\n")

    print(f"[*] Unique hostnames extracted: {len(rows)}")
    print(f"[*] Wrote: {defanged_path}  (defanged, safe to view)")
    print(f"[*] Wrote: {raw_path}  (real hostnames -- input for build_ac_table.py)")
    print(f"[*] Wrote: {meta_path}")
    print(f"[*] Wrote: {summary_path}")
    print(f"[*] Top families: {sorted(family_counts.items(), key=lambda x: -x[1])[:5]}")


if __name__ == "__main__":
    main()