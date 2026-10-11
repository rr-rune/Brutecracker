# Brutecracker.py

A wrapper script around `john` (John the Ripper) and `hashcat` for CTF password
cracking: hash lists and password-protected zip/7z/rar/pdf files and SSH keys.

It is built around the pattern you'll hit most in CTFs: the password isn't in
rockyou as-is, but it's a recognisable word (challenge name, hint, flag tag)
with a predictable twist — different casing, leetspeak, or a few digits/symbols
tacked on. That's what the "hybrid" phase targets.

**This only operates on files you give it** (hashes you've dumped, archives
you own, keys you've been given). It does not attack live services or
anything over a network, and it needs `john` and/or `hashcat` already
installed — it doesn't install them.

## Install the actual crackers first

This script is just a driver. On the machine you're actually using (not
necessarily this sandbox):

```bash
# Debian/Ubuntu/Kali
sudo apt install john john-data hashcat          # john-data brings *2john helpers

# macOS (Homebrew)
brew install john-jumbo hashcat

# or build john-jumbo from source for the *2john helpers:
# https://github.com/openwall/john
```

Grab rockyou.txt if you don't have it (Kali ships it at
`/usr/share/wordlists/rockyou.txt.gz`, otherwise SecLists has a copy).

## Usage

```bash
# Password-protected zip, with challenge-specific keywords
./ctf_cracker.py challenge.zip --keywords "ctfname,flagprefix,hintword" --backend hashcat

# Raw hash list, force the hash type, use rockyou too
./ctf_cracker.py hashes.txt --wordlist /usr/share/wordlists/rockyou.txt \
    --keywords "admin,service" --hash-type raw-sha256

# SSH private key
./ctf_cracker.py id_rsa --keywords "ctf2026,admin"

# Widen the brute-force phase for a "word + symbol + 3 digits" guess
./ctf_cracker.py hashes.txt --keywords "service" --mask "?s?d?d?d"

# Last resort: pure brute force, bounded length (can run a long time)
./ctf_cracker.py hashes.txt --bruteforce --min-len 4 --max-len 6 --charset alphanum
```

## What it does, phase by phase

1. **Detect & normalize.** Sniffs the input (zip/7z/rar/pdf magic bytes, SSH
   key header, or "it's already a hash"). Containers get run through the
   matching `*2john` helper (`zip2john`, `rar2john`, `7z2john`, `pdf2john`,
   `ssh2john`) to produce a crackable hash. The hash format is then guessed
   from its prefix (`$zip2$`, `$7z$`, `$rar5$`, bcrypt's `$2b$`, etc.) or, for
   bare hex, by length — override with `--hash-type` / `--hashcat-mode` if it
   guesses wrong or can't tell.

2. **Phase A — wordlist.** Runs any `--wordlist` you gave it (e.g. rockyou)
   and/or a wordlist built from your `--keywords`, each with mangling rules
   (case toggles, leetspeak, common CTF suffixes like `123`, `!`, `2025`,
   `2026`). This is the "maybe it's just literally the word" pass.

3. **Phase B — hybrid (hashcat only).** The one aimed at your "keyword +
   something rockyou doesn't have" case: combines the keyword list with a
   brute-forced mask, both as `keyword` + mask (`-a 6`) and mask + `keyword`
   (`-a 7`). Default mask is `?d?d?d?d` (4 digits); pass `--mask` for
   something else, e.g. `--mask "?s?d?d"` for a symbol then 2 digits. John has
   no equivalent hybrid attack mode, so this phase is skipped if only `john`
   is available.

4. **Phase C — brute force (opt-in via `--bruteforce`).** Hashcat mask attack
   stepping through lengths `--min-len`..`--max-len` with `--charset`
   (`loweralpha`/`upperalpha`/`alpha`/`digits`/`alphanum`/`full`), or John's
   `--incremental` if only John is available. Off by default because it can
   run indefinitely — it's bounded by length, not time, so pick a realistic
   `--max-len`.

Each phase stops as soon as a crack is confirmed (checked via `--show`), logs
go to `<workdir>/logs/`, and a `summary.json` records what ran and what (if
anything) was found.

## Notes

- **Rule file formats differ between the two tools.** John wants rules
  wrapped in a `[List.Rules:NAME]` section of a config file; hashcat wants a
  plain one-rule-per-line file. If you don't pass `--rules`, the script
  generates both correctly. If you do pass `--rules`, give it a file in the
  format matching whichever `--backend` actually runs.
- `--keywords-file` takes one keyword per line and merges with `--keywords`
  — handy for dumping in every word from the challenge description/hints at
  once.
- The keyword wordlist is capped (20k lines by default) so Phase A doesn't
  blow up; the real "unknown suffix" coverage comes from Phase B's hybrid
  mask, not from expanding every case/leet/suffix combination by hand.
