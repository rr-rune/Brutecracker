#!/usr/bin/env python3
"""
ctf_cracker.py - a CTF password/hash cracking helper that wraps john and hashcat.

Meant for CTF challenges you're authorized to solve: cracking hashes you dumped,
password-protected zip/7z/rar/pdf archives, SSH keys, etc. It does not attack
live services or anything over a network.

Pipeline:
  1. Figure out what kind of file you handed it (raw hash list, zip/7z/rar/pdf,
     SSH key) and convert it into a john-compatible hash file with the right
     *2john helper.
  2. Phase A - wordlist attack: rockyou (or whatever you point it at) plus a
     generated wordlist of your challenge-specific keywords (challenge name,
     flag prefix, hints, etc.), both run through mangling rules (case toggles,
     leetspeak, common CTF suffixes).
  3. Phase B - hybrid attack (hashcat only): keyword list + a brute-forced
     mask, e.g. "keyword" + "?d?d?d?d" or "keyword" + "!?d?d". This is the
     phase aimed at your case: a real word with extra special characters or
     numbers tacked on that rockyou alone won't contain.
  4. Phase C - pure brute force / mask / incremental, bounded by a length you
     set, as a last resort.

Needs john and/or hashcat installed on the machine you run this on - see
README.md for install notes. This script does not install them.

Usage examples:
  ./ctf_cracker.py target.zip --keywords "flag,ctfname,2026" --backend hashcat
  ./ctf_cracker.py hashes.txt --wordlist rockyou.txt --hash-type sha256
  ./ctf_cracker.py id_rsa --keywords ctf2026,admin --mask "?d?d?d?d"
  ./ctf_cracker.py hashes.txt --bruteforce --min-len 4 --max-len 6 --charset loweralpha
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Hash-type detection
# ---------------------------------------------------------------------------

# magic-byte / prefix -> (label, john format hint, hashcat mode, *2john helper)
FILE_SIGNATURES = [
    (b"PK\x03\x04", "zip", "zip2john"),
    (b"PK\x05\x06", "zip", "zip2john"),
    (b"Rar!\x1a\x07", "rar", "rar2john"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7z2john"),
    (b"%PDF", "pdf", "pdf2john"),
]

# john hash-string prefix -> (john format name, hashcat mode)
JOHN_PREFIX_MAP = {
    "$zip2$": ("ZIP", 13600),
    "$zip$": ("PKZIP", 17200),
    "$pkzip2$": ("PKZIP", 17200),
    "$7z$": ("7z", 11600),
    "$RAR3$": ("rar", 12500),
    "$rar5$": ("RAR5", 13000),
    "$sshng$": ("SSH", 22921),
    "$krb5tgs$": ("krb5tgs", 13100),
    "$krb5asrep$": ("krb5asrep", 18200),
    "$office$": ("office", 9600),
    "$pdf$": ("PDF", 10500),
}

# plain-hash heuristics by hex length, for raw hash lists with no prefix
PLAIN_HEX_LEN_MAP = {
    32: [("raw-md5", 0), ("ntlm", 1000)],
    40: [("raw-sha1", 100)],
    56: [("raw-sha224", 1300)],
    64: [("raw-sha256", 1400)],
    96: [("raw-sha384", 10800)],
    128: [("raw-sha512", 1700)],
}


def sniff_container(path: Path) -> str | None:
    """Return 'zip' / 'rar' / '7z' / 'pdf' / 'ssh' / None based on file content."""
    try:
        head = path.open("rb").read(64)
    except OSError:
        return None

    if head.startswith(b"-----BEGIN") and b"PRIVATE KEY" in head:
        return "ssh"
    for magic, label, _helper in FILE_SIGNATURES:
        if head.startswith(magic):
            return label
    return None


def guess_hash_type(hash_line: str) -> tuple[str | None, int | None]:
    """Best-effort (john_format, hashcat_mode) guess from a hash string."""
    for prefix, (jformat, hmode) in JOHN_PREFIX_MAP.items():
        if hash_line.startswith(prefix):
            return jformat, hmode

    candidate = hash_line.split(":")[-1].strip()
    if candidate.startswith("$2a$") or candidate.startswith("$2b$") or candidate.startswith("$2y$"):
        return "bcrypt", 3200
    if candidate.startswith("$1$"):
        return "md5crypt", 500
    if candidate.startswith("$6$"):
        return "sha512crypt", 1800
    if candidate.startswith("$5$"):
        return "sha256crypt", 7400

    hexpart = candidate.strip()
    if all(c in "0123456789abcdefABCDEF" for c in hexpart) and len(hexpart) in PLAIN_HEX_LEN_MAP:
        return PLAIN_HEX_LEN_MAP[len(hexpart)][0]  # (john_format, hashcat_mode) of first guess

    return None, None


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

@dataclass
class Tools:
    john: str | None
    hashcat: str | None
    helpers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def discover(cls) -> "Tools":
        helpers = {}
        for name in ["zip2john", "rar2john", "7z2john", "pdf2john", "ssh2john",
                      "7z2john.pl", "pdf2john.pl", "ssh2john.py"]:
            found = shutil.which(name)
            if found:
                key = name.replace(".pl", "").replace(".py", "")
                helpers.setdefault(key, found)
        return cls(
            john=shutil.which("john"),
            hashcat=shutil.which("hashcat"),
            helpers=helpers,
        )

    def require_helper(self, name: str) -> str:
        path = self.helpers.get(name)
        if not path:
            raise RuntimeError(
                f"Need '{name}' to process this file type but it isn't on PATH. "
                f"It usually ships with john (john-the-ripper-jumbo)."
            )
        return path


# ---------------------------------------------------------------------------
# Wordlist / keyword mangling for the "keyword rockyou won't have" case
# ---------------------------------------------------------------------------

LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
COMMON_SUFFIXES = ["", "1", "12", "123", "!", "!!", "#", "2024", "2025", "2026", "_"]
COMMON_PREFIXES = ["", "!", "#"]


def leetspeak(word: str) -> str:
    return "".join(LEET_MAP.get(c.lower(), c) for c in word)


def case_variants(word: str) -> set[str]:
    return {word, word.lower(), word.upper(), word.capitalize(), word.swapcase()}


def build_keyword_wordlist(keywords: list[str], out_path: Path, max_lines: int = 20000) -> int:
    """
    Expand a short list of challenge-specific keywords into a bounded wordlist
    using case toggles, leetspeak, and common CTF-style prefixes/suffixes.
    This is the list rockyou won't have but is cheap to build from what you
    already know about the challenge (its name, theme, hint words, flag tag).
    """
    seen: set[str] = set()
    with out_path.open("w", encoding="utf-8", errors="ignore") as fh:
        for kw in keywords:
            kw = kw.strip()
            if not kw:
                continue
            bases = case_variants(kw) | {leetspeak(kw), leetspeak(kw.capitalize())}
            for base in bases:
                for pre in COMMON_PREFIXES:
                    for suf in COMMON_SUFFIXES:
                        candidate = f"{pre}{base}{suf}"
                        if candidate and candidate not in seen:
                            seen.add(candidate)
                            fh.write(candidate + "\n")
                            if len(seen) >= max_lines:
                                return len(seen)
    return len(seen)


def default_rule_lines() -> list[str]:
    """A small rule set covering case toggles, leet, and digit/symbol
    suffixes/prefixes - used when the user hasn't pointed us at a bigger
    rule file like OneRuleToRuleThemAll / best64. Uses only the common
    subset of rule syntax both john and hashcat understand (no JtR-only
    preprocessor syntax like Az"...")."""
    lines = [":", "l", "u", "c", "C", "t", "sa4 se3 si1 so0 ss5"]
    for suffix in ["1", "12", "123", "0", "!", "@", "#", "2025", "2026"]:
        lines.append(" ".join(f"${ch}" for ch in suffix))
    for prefix in ["!", "#"]:
        lines.append(" ".join(f"^{ch}" for ch in prefix))
    return lines


def write_default_rules_john(rule_path: Path) -> None:
    """John rules need an ini-style [List.Rules:NAME] section in a config
    file, loaded via --config=<this file> --rules=CTF."""
    body = "\n".join(default_rule_lines())
    rule_path.write_text(f"[List.Rules:CTF]\n{body}\n")


def write_default_rules_hashcat(rule_path: Path) -> None:
    """Hashcat rule files are plain text, one rule per line, no section
    header - loaded via -r <this file>."""
    rule_path.write_text("\n".join(default_rule_lines()) + "\n")


# ---------------------------------------------------------------------------
# Container -> john hash file
# ---------------------------------------------------------------------------

def extract_hash_file(target: Path, tools: Tools, work_dir: Path) -> tuple[Path, str]:
    """
    Returns (hash_file_path, kind) where kind is one of
    'zip' / 'rar' / '7z' / 'pdf' / 'ssh' / 'raw'.
    For 'raw', the input file is assumed to already be a hash / hash-list file
    and is used as-is.
    """
    container = sniff_container(target)
    out_hash = work_dir / f"{target.name}.hash"

    helper_for = {
        "zip": "zip2john",
        "rar": "rar2john",
        "7z": "7z2john",
        "pdf": "pdf2john",
        "ssh": "ssh2john",
    }

    if container is None:
        return target, "raw"

    helper = tools.require_helper(helper_for[container])
    with out_hash.open("w") as fh:
        subprocess.run([helper, str(target)], stdout=fh, check=True)

    if out_hash.stat().st_size == 0:
        raise RuntimeError(f"{helper} produced an empty hash for {target} - is it actually a {container}?")

    return out_hash, container


# ---------------------------------------------------------------------------
# Cracking phases
# ---------------------------------------------------------------------------

@dataclass
class Phase:
    name: str
    cmd: list[str]
    timeout: float | None


def run_phase(phase: Phase, log_dir: Path) -> tuple[bool, str]:
    print(f"\n=== Phase: {phase.name} ===")
    print("  $ " + " ".join(phase.cmd))
    log_path = log_dir / f"{phase.name.replace(' ', '_')}.log"
    start = time.time()
    try:
        with log_path.open("w") as log:
            proc = subprocess.run(
                phase.cmd, stdout=log, stderr=subprocess.STDOUT, timeout=phase.timeout
            )
        elapsed = time.time() - start
        print(f"  finished in {elapsed:.1f}s, exit={proc.returncode} (log: {log_path})")
        return proc.returncode == 0, str(log_path)
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"  timed out after {elapsed:.1f}s (log: {log_path})")
        return False, str(log_path)
    except FileNotFoundError as e:
        print(f"  could not run: {e}")
        return False, str(log_path)


def check_cracked_john(john: str, hash_file: Path, jformat: str | None) -> str | None:
    cmd = [john, "--show"]
    if jformat:
        cmd.append(f"--format={jformat}")
    cmd.append(str(hash_file))
    out = subprocess.run(cmd, capture_output=True, text=True)
    for line in out.stdout.splitlines():
        if ":" in line and not line.startswith("0 password hash"):
            return line
    return None


def check_cracked_hashcat(hashcat: str, hash_file: Path, mode: int) -> str | None:
    cmd = [hashcat, "-m", str(mode), "--show", str(hash_file)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    return lines[0] if lines else None


MASKS = {
    "loweralpha": "?l",
    "upperalpha": "?u",
    "alpha": "?l?u",
    "alphanum": "?l?u?d",
    "digits": "?d",
    "full": "?a",
}


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="CTF password/hash cracker wrapping john and hashcat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", type=Path, help="hash file, hash-list, or protected archive/key")
    p.add_argument("--wordlist", type=Path, default=None,
                    help="path to a wordlist, e.g. rockyou.txt (default: skip phase A base wordlist)")
    p.add_argument("--keywords", type=str, default=None,
                    help="comma-separated challenge-specific keywords (challenge name, hints, flag tag, etc.)")
    p.add_argument("--keywords-file", type=Path, default=None,
                    help="file with one keyword per line, merged with --keywords")
    p.add_argument("--rules", type=Path, default=None,
                    help="rule file to use instead of the built-in CTF rule set. NOTE: john and "
                         "hashcat rule file formats differ (john wraps rules in a [List.Rules:X] "
                         "config section; hashcat wants plain one-rule-per-line). Pass a file in "
                         "the format matching --backend, or leave unset to use the built-in set, "
                         "which is generated correctly for whichever backend actually runs.")
    p.add_argument("--mask", type=str, default="?d?d?d?d",
                    help="hashcat mask appended/prepended to keywords in the hybrid phase (default: ?d?d?d?d)")
    p.add_argument("--backend", choices=["auto", "john", "hashcat"], default="auto")
    p.add_argument("--hash-type", type=str, default=None,
                    help="force john format name (e.g. raw-sha256); skips auto-detection")
    p.add_argument("--hashcat-mode", type=int, default=None,
                    help="force hashcat -m mode number; skips auto-detection")
    p.add_argument("--bruteforce", action="store_true",
                    help="also run phase C, pure mask/incremental brute force")
    p.add_argument("--min-len", type=int, default=4)
    p.add_argument("--max-len", type=int, default=6)
    p.add_argument("--charset", choices=list(MASKS), default="alphanum")
    p.add_argument("--wordlist-timeout", type=float, default=900)
    p.add_argument("--hybrid-timeout", type=float, default=900)
    p.add_argument("--bruteforce-timeout", type=float, default=1800)
    p.add_argument("--workdir", type=Path, default=None)
    args = p.parse_args()

    if not args.target.exists():
        print(f"error: {args.target} does not exist", file=sys.stderr)
        return 2

    tools = Tools.discover()
    if args.backend == "john" and not tools.john:
        print("error: --backend john requested but 'john' is not on PATH", file=sys.stderr)
        return 2
    if args.backend == "hashcat" and not tools.hashcat:
        print("error: --backend hashcat requested but 'hashcat' is not on PATH", file=sys.stderr)
        return 2
    if args.backend == "auto" and not (tools.john or tools.hashcat):
        print("error: neither 'john' nor 'hashcat' found on PATH. Install one - see README.md.",
              file=sys.stderr)
        return 2

    use_john = args.backend in ("auto", "john") and tools.john
    use_hashcat = args.backend in ("auto", "hashcat") and tools.hashcat

    work_dir = args.workdir or Path(f".ctf_cracker_{args.target.name}")
    work_dir.mkdir(exist_ok=True)
    log_dir = work_dir / "logs"
    log_dir.mkdir(exist_ok=True)

    # --- Step 1: normalize input into a hash file ---------------------------
    try:
        hash_file, kind = extract_hash_file(args.target, tools, work_dir)
    except Exception as e:
        print(f"error preparing hash file: {e}", file=sys.stderr)
        return 2
    print(f"[*] input type: {kind}  ->  hash file: {hash_file}")

    first_line = hash_file.read_text(errors="ignore").splitlines()[0] if hash_file.stat().st_size else ""
    jformat, hmode = (args.hash_type, args.hashcat_mode)
    if jformat is None or hmode is None:
        guessed_j, guessed_h = guess_hash_type(first_line)
        jformat = jformat or guessed_j
        hmode = hmode or guessed_h
    print(f"[*] detected format: john={jformat or 'unknown (let john auto-detect)'}  "
          f"hashcat_mode={hmode if hmode is not None else 'unknown - pass --hashcat-mode'}")

    # --- Step 2: build the keyword wordlist ----------------------------------
    keywords: list[str] = []
    if args.keywords:
        keywords += [k for k in args.keywords.split(",") if k.strip()]
    if args.keywords_file and args.keywords_file.exists():
        keywords += [l.strip() for l in args.keywords_file.read_text().splitlines() if l.strip()]

    keyword_wordlist = None
    if keywords:
        keyword_wordlist = work_dir / "keywords.wordlist"
        n = build_keyword_wordlist(keywords, keyword_wordlist)
        print(f"[*] built {n} keyword-derived candidates -> {keyword_wordlist}")

    john_rule_file = args.rules
    hashcat_rule_file = args.rules
    if args.rules is None:
        john_rule_file = work_dir / "ctf_john.rule"
        write_default_rules_john(john_rule_file)
        hashcat_rule_file = work_dir / "ctf_hashcat.rule"
        write_default_rules_hashcat(hashcat_rule_file)

    results: dict[str, str | None] = {}

    def try_report(stage: str) -> str | None:
        found = None
        if use_hashcat and hmode is not None:
            found = check_cracked_hashcat(tools.hashcat, hash_file, hmode)
        if not found and use_john:
            found = check_cracked_john(tools.john, hash_file, jformat)
        if found:
            print(f"\n[+] CRACKED during {stage}: {found}")
            results["cracked"] = found
            results["stage"] = stage
        return found

    # --- Phase A: wordlist attack (rockyou + keywords, with mangling rules) -
    wordlists_to_try = [w for w in [args.wordlist, keyword_wordlist] if w]
    if wordlists_to_try and not results.get("cracked"):
        for wl in wordlists_to_try:
            if use_hashcat and hmode is not None:
                cmd = [tools.hashcat, "-m", str(hmode), "-a", "0", str(hash_file), str(wl)]
                if hashcat_rule_file:
                    cmd += ["-r", str(hashcat_rule_file)]
                ok, log = run_phase(Phase(f"wordlist_hashcat_{wl.stem}", cmd, args.wordlist_timeout), log_dir)
            elif use_john:
                cmd = [tools.john, str(hash_file), f"--wordlist={wl}"]
                if jformat:
                    cmd.append(f"--format={jformat}")
                if john_rule_file:
                    # Built-in rule file defines [List.Rules:CTF]; --config loads it alongside
                    # john's own config, --rules=CTF selects it. A user-supplied --rules file is
                    # assumed to already be a john.conf-style file defining that same section.
                    cmd += [f"--config={john_rule_file}", "--rules=CTF"]
                ok, log = run_phase(Phase(f"wordlist_john_{wl.stem}", cmd, args.wordlist_timeout), log_dir)
            else:
                break
            if try_report(f"wordlist ({wl.name})"):
                break

    # --- Phase B: hybrid keyword + brute-forced suffix (hashcat only) -------
    if not results.get("cracked") and keyword_wordlist and use_hashcat and hmode is not None:
        for attack_mode, label in [("6", "keyword+mask"), ("7", "mask+keyword")]:
            if attack_mode == "6":
                cmd = [tools.hashcat, "-m", str(hmode), "-a", "6", str(hash_file), str(keyword_wordlist), args.mask]
            else:
                cmd = [tools.hashcat, "-m", str(hmode), "-a", "7", str(hash_file), args.mask, str(keyword_wordlist)]
            ok, log = run_phase(Phase(f"hybrid_{label}", cmd, args.hybrid_timeout), log_dir)
            if try_report(f"hybrid ({label})"):
                break
    elif not results.get("cracked") and keyword_wordlist and not use_hashcat:
        print("\n[!] skipping hybrid phase: it needs hashcat (-a 6 / -a 7), which isn't available. "
              "john has no equivalent hybrid mode.")

    # --- Phase C: pure brute force / incremental (optional, bounded) --------
    if not results.get("cracked") and args.bruteforce:
        charset_mask = MASKS[args.charset]
        if use_hashcat and hmode is not None:
            for length in range(args.min_len, args.max_len + 1):
                mask = charset_mask * length
                cmd = [tools.hashcat, "-m", str(hmode), "-a", "3", str(hash_file), mask]
                ok, log = run_phase(Phase(f"bruteforce_len{length}", cmd, args.bruteforce_timeout), log_dir)
                if try_report(f"bruteforce (len {length})"):
                    break
        elif use_john:
            cmd = [tools.john, str(hash_file), "--incremental"]
            if jformat:
                cmd.append(f"--format={jformat}")
            ok, log = run_phase(Phase("bruteforce_incremental", cmd, args.bruteforce_timeout), log_dir)
            try_report("bruteforce (incremental)")

    # --- Final report ---------------------------------------------------------
    summary_path = work_dir / "summary.json"
    results.setdefault("cracked", None)
    results["hash_file"] = str(hash_file)
    results["input_kind"] = kind
    results["john_format"] = jformat
    results["hashcat_mode"] = hmode
    summary_path.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 60)
    if results.get("cracked"):
        print(f"[+] DONE - cracked: {results['cracked']}")
        print(f"[+] stage: {results.get('stage')}")
    else:
        print("[-] not cracked in the phases run. Options:")
        print("    - point --wordlist at a bigger list (rockyou, SecLists)")
        print("    - add more --keywords specific to the challenge (theme words, hint text, author handles)")
        print("    - widen --mask (e.g. ?d?d?d?d?d, or ?s?d?d?d for a symbol+digits suffix)")
        print("    - re-run with --bruteforce and a tighter --max-len once you have a length hint")
    print(f"[*] full logs: {log_dir}")
    print(f"[*] summary:   {summary_path}")
    print("=" * 60)

    return 0 if results.get("cracked") else 1


if __name__ == "__main__":
    raise SystemExit(main())
