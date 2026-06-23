#!/usr/bin/env python3
"""
build_ac_table.py (v2 - expanded realistic pattern set)

Builds a completed (failure-merged) Aho-Corasick DFA from a list of patterns,
matching the table format expected by aho_corasick.v:

    goto_bram[state][byte]   -> next_state   (10 bits, NUM_STATES=1024 max)
    output_table[state]      -> 1 if state is an accepting state
    output_id[state]         -> pattern ID (10 bits) matched at that state

Usage:
    python build_ac_table.py

Outputs:
    goto_table.hex     -- $readmemh-compatible flat file, one value per line
                          256 lines per state (one per byte value 0-255),
                          states in order 0, 1, 2, ...
    output_table.hex   -- one bit per state, 1 = accepting
    output_id.hex       -- one 10-bit pattern ID per state (only valid where
                          output_table bit is 1)
    summary.txt          -- human-readable state/pattern map for debugging
"""

from collections import deque

# ---------------------------------------------------------------------------
# STEP 1: Define a larger, realistic pattern set.
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

ALPHABET_SIZE = 256
MAX_STATES = 1024  # must match aho_corasick.v NUM_STATES parameter


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
    root, states = build_trie(PATTERNS)
    goto_table = build_failure_links_and_complete_goto(root, states)
    num_states = len(states)

    if num_states > MAX_STATES:
        raise SystemExit(
            f"ERROR: {num_states} states exceeds MAX_STATES={MAX_STATES}"
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
        f.write(f"Patterns:\n")
        for i, p in enumerate(PATTERNS):
            f.write(f"  ID {i}: \"{p}\"\n")
        f.write("\nAccepting states:\n")
        for state in states:
            if state.output:
                f.write(
                    f"  state {state.state_id}: "
                    f"pattern IDs {sorted(state.output)} "
                    f"({[PATTERNS[i] for i in sorted(state.output)]})\n"
                )
        f.write("\nFailure links (non-trivial only, i.e. fail != 0):\n")
        for state in states:
            if state.fail != 0:
                f.write(f"  state {state.state_id} -> fail {state.fail}\n")

    print(f"Built DFA with {num_states} states for {len(PATTERNS)} patterns.")
    print("Wrote: goto_table.hex, output_table.hex, output_id.hex, summary.txt")
    print("\nPattern -> ID map:")
    for i, p in enumerate(PATTERNS):
        print(f"  {i}: \"{p}\"")


if __name__ == "__main__":
    main()