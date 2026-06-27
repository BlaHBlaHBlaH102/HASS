#!/usr/bin/env python3
"""
build_ac_table.py (v3 - corpus-loading + corrected state ceiling)

Builds a completed (failure-merged) Aho-Corasick DFA from a list of patterns,
matching the table format expected by aho_corasick.v:

    goto_bram[state][byte]   -> next_state   (10 bits, hardware array sized 256 states)
    output_table[state]      -> 1 if state is an accepting state
    output_id[state]         -> pattern ID (10 bits) matched at that state

IMPORTANT -- STATE CEILING NOTE:
aho_corasick.v declares NUM_STATES=1024 as a module parameter, but the actual
goto_bram / fail_table / output_table arrays in the current RTL are hardcoded
to [0:255] (256 states) -- see the "reduced to 256 states fits in BRAM"
comment in aho_corasick.v. The 1024 parameter is NOT yet wired to any real
memory array. MAX_STATES below checks against the REAL 256-state hardware
limit, not the unused 1024 parameter. If you widen goto_bram/fail_table/
output_table in the RTL to actually use 1024 states, update MAX_STATES here
to match.

Usage:
    # Build from the curated 22-pattern "No-Fly List" (default, unchanged):
    python build_ac_table.py

    # Build from an external corpus file instead (one hostname per line),
    # e.g. the output of fetch_urlhaus_corpus.py:
    python build_ac_table.py --corpus urlhaus_corpus/hostnames_raw.txt
    python build_ac_table.py --corpus C:\\hass\\urlhaus_corpus\\hostnames_raw.txt

    Corpus path may be absolute, or relative to the directory you RUN this
    script FROM (not relative to where build_ac_table.py itself is saved).

Outputs (written to the current working directory):
    goto_table.hex     -- $readmemh-compatible flat file, one value per line
                          256 lines per state (one per byte value 0-255),
                          states in order 0, 1, 2, ...
    output_table.hex   -- one bit per state, 1 = accepting
    output_id.hex       -- one 10-bit pattern ID per state (only valid where
                          output_table bit is 1)
    summary.txt          -- human-readable state/pattern map for debugging
"""

import argparse
import os
from collections import deque

# ---------------------------------------------------------------------------
# STEP 1: Curated pattern set (default; used when --corpus is not given).
#
# Modeled on the *shape* of real URLhaus / PhishTank / Emerging Threats
# indicators per HASS's threat table:
#   - tech support scam domain fragments
#   - brand-impersonation phishing fragments (PayPal, Microsoft, banks)
#   - generic malware/C2-shaped tokens
#   - deliberate overlaps and near-misses to exercise failure links
#
# These are SYNTHETIC fragments shaped like real indicators, not actual
# malicious domains.
# ---------------------------------------------------------------------------
PATTERNS = [
    # --- tech support scam family ---
    "scam",
    "scammer",
    "scam-alert",
    "tech-support-scam",
    "windows-defender-alert",
    "virus-detected",

    # --- brand impersonation / phishing family ---
    "paypal-secure",
    "paypal-secure-login",
    "secure-login",
    "account-verify",
    "verify-account-now",
    "microsoft-support",
    "apple-id-locked",
    "bank-alert-update",

    # --- generic malware / C2-shaped tokens ---
    "evil",
    "malware",
    "trojan",
    "c2-beacon",
    "backdoor",

    # --- deliberate near-miss / overlap stress cases ---
    "scammed",        # shares "scam" prefix but diverges at 5th char
    "bad",
    "badge",          # shares "bad" prefix but diverges at 4th char
]


def load_corpus_patterns(corpus_path):
    """
    Load hostnames from a corpus file (e.g. hostnames_raw.txt produced by
    fetch_urlhaus_corpus.py) as the pattern list, instead of the curated
    PATTERNS above.

    Accepts either an absolute path or a path relative to the CURRENT
    WORKING DIRECTORY (not relative to this script's location).
    """
    if not os.path.isfile(corpus_path):
        raise SystemExit(
            f"ERROR: corpus file not found: {corpus_path}\n"
            f"        (Current working directory: {os.getcwd()})\n"
            f"        Use an absolute path, or a path relative to the directory\n"
            f"        you are RUNNING this script from -- not relative to where\n"
            f"        build_ac_table.py itself is saved."
        )

    patterns = []
    with open(corpus_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                line.encode("ascii")
            except UnicodeEncodeError:
                print(f"  [skip] non-ASCII hostname, can't encode for goto_table: {line!r}")
                continue
            patterns.append(line)

    if not patterns:
        raise SystemExit(f"ERROR: no usable patterns found in {corpus_path}")

    return patterns


ALPHABET_SIZE = 256

# CRITICAL: aho_corasick.v declares NUM_STATES=1024 as a parameter, but the
# actual goto_bram/fail_table/output_table arrays are hardcoded to [0:255]
# (256 states) in the current RTL -- see the "reduced to 256 states fits in
# BRAM" comment in aho_corasick.v. The 1024 parameter is currently unused
# by the real memory arrays. This guard checks the REAL hardware limit.
MAX_STATES = 256  # must match aho_corasick.v goto_bram/fail_table/output_table array bound, NOT the NUM_STATES parameter


class TrieNode:
    def __init__(self):
        self.children = {}      # byte_value -> TrieNode
        self.fail = 0            # failure state index
        self.output = []         # list of pattern IDs ending here
        self.state_id = None


def build_trie(patterns):
    """Step 1: build raw trie. Root is state 0."""
    root = TrieNode()
    root.state_id = 0
    states = [root]

    for pattern_id, pattern in enumerate(patterns):
        node = root
        for ch in pattern.encode('ascii'):
            if ch not in node.children:
                new_node = TrieNode()
                new_node.state_id = len(states)
                states.append(new_node)
                node.children[ch] = new_node
            node = node.children[ch]
        node.output.append(pattern_id)

    return root, states


def build_failure_links_and_complete_goto(root, states):
    """
    Step 2: BFS to compute failure links, then build the completed
    (dense) goto function: goto[state][byte] for ALL 256 byte values,
    not just the ones that exist as trie edges.
    """
    num_states = len(states)
    goto_table = [[-1] * ALPHABET_SIZE for _ in range(num_states)]

    root.fail = 0

    for b in range(ALPHABET_SIZE):
        if b in root.children:
            goto_table[0][b] = root.children[b].state_id
        else:
            goto_table[0][b] = 0  # stay at root

    queue = deque()
    for b, child in root.children.items():
        child.fail = 0  # depth-1 nodes always fail to root
        queue.append(child)

    while queue:
        current = queue.popleft()
        current_id = current.state_id

        for b in range(ALPHABET_SIZE):
            if b in current.children:
                child = current.children[b]
                child_id = child.state_id

                goto_table[current_id][b] = child_id

                child.fail = goto_table[current.fail][b]

                fail_node = states[child.fail]
                child.output = list(set(child.output) | set(fail_node.output))

                queue.append(child)
            else:
                goto_table[current_id][b] = goto_table[current.fail][b]

    return goto_table


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus", default=None,
        help="Path to a corpus file (one hostname per line) to use INSTEAD of "
             "the curated PATTERNS list above. E.g. urlhaus_corpus/hostnames_raw.txt"
    )
    args = parser.parse_args()

    if args.corpus:
        patterns = load_corpus_patterns(args.corpus)
        print(f"[*] Loaded {len(patterns)} patterns from corpus file: {args.corpus}")
        print(f"[*] (Curated {len(PATTERNS)}-pattern table is NOT used in this run.)")
    else:
        patterns = PATTERNS
        print(f"[*] Using curated {len(patterns)}-pattern table (no --corpus flag given).")

    root, states = build_trie(patterns)
    goto_table = build_failure_links_and_complete_goto(root, states)
    num_states = len(states)

    if num_states > MAX_STATES:
        raise SystemExit(
            f"ERROR: {num_states} states exceeds MAX_STATES={MAX_STATES}\n"
            f"        (this is the real aho_corasick.v goto_bram/fail_table/\n"
            f"        output_table array bound, not the unused NUM_STATES=1024\n"
            f"        parameter). Either trim the pattern/corpus set, or widen\n"
            f"        the hardcoded [0:255] arrays in aho_corasick.v to actually\n"
            f"        use the full 1024-state width the module already declares."
        )

    with open("goto_table.hex", "w") as f:
        for state_id in range(num_states):
            for b in range(ALPHABET_SIZE):
                f.write(f"{goto_table[state_id][b]:03x}\n")

    with open("output_table.hex", "w") as f_out, \
         open("output_id.hex", "w") as f_id:
        for state in states:
            if state.output:
                f_out.write("1\n")
                f_id.write(f"{min(state.output):03x}\n")
            else:
                f_out.write("0\n")
                f_id.write("000\n")

    with open("summary.txt", "w") as f:
        f.write(f"Total states: {num_states}\n")
        f.write(f"Pattern source: {args.corpus if args.corpus else 'curated PATTERNS list'}\n")
        f.write(f"Patterns:\n")
        for i, p in enumerate(patterns):
            f.write(f"  ID {i}: \"{p}\"\n")
        f.write("\nAccepting states:\n")
        for state in states:
            if state.output:
                f.write(
                    f"  state {state.state_id}: "
                    f"pattern IDs {sorted(state.output)} "
                    f"({[patterns[i] for i in sorted(state.output)]})\n"
                )
        f.write("\nFailure links (non-trivial only, i.e. fail != 0):\n")
        for state in states:
            if state.fail != 0:
                f.write(f"  state {state.state_id} -> fail {state.fail}\n")

    print(f"Built DFA with {num_states} states for {len(patterns)} patterns.")
    print("Wrote: goto_table.hex, output_table.hex, output_id.hex, summary.txt")
    print("\nPattern -> ID map:")
    for i, p in enumerate(patterns):
        print(f"  {i}: \"{p}\"")


if __name__ == "__main__":
    main()