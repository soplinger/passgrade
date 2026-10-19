# passgrade

**Offline password strength estimator, policy checker and generator.**

passgrade rates passwords by estimated entropy, names the patterns that weaken them, and checks them against a plain-text policy file. It can batch-check a list of candidates without ever printing them, and it generates random passwords and word passphrases. It is one Python file, uses only the standard library, and makes no network calls.

## Features

- **Entropy estimate** from the character classes actually used (lower, upper, digit, symbol, other), with bits and a 0–4 score.
- **Pattern detection**: repeated runs (`aaa`), ascending or descending sequences (`1234`, `dcba`), keyboard walks (`qwer`, `asdf`), four-digit years (`1999`, `2024`), and common words hidden behind leetspeak (`P@ssw0rd`).
- **Penalties that matter**: each pattern removes bits from the estimate, and a common word caps it, so `P@ssw0rd` scores as weak no matter how long it is.
- **Crack-time table** for three attacker models: throttled online, slow salted hashes, and fast GPU hashes, in human units from "instantly" to "over a billion years".
- **Policy files** with `key = value` rules: minimum and maximum length, minimum character classes, forbidden words, minimum estimated bits, and switches for common-word and pattern bans.
- **Line-numbered policy lint** (`file:line: message`) so a broken rules file fails loudly, with exit code 2.
- **Hidden single-password check** (`rate`) that reads with `getpass`, so nothing is echoed or saved.
- **Batch checking** (`batch`) of one candidate per line, with masked output, a per-line verdict, and a summary count.
- **Masking everywhere**: the tool shows only the length of a password, and JSON output contains no plaintext.
- **CI-friendly exit codes**: `0` all pass, `1` at least one failure, `2` bad input, bad policy, or missing file.
- **JSON output** for `rate` and `batch`, for scripts and dashboards.
- **Random password generator** (`generate`) using `secrets`, guaranteeing at least one character from each requested class.
- **Word passphrases** (`passphrase`) from a built-in list of 64 words, with the exact entropy printed (6 bits per word).

## Quick start

No install is needed. Python 3.10 or newer is required.

```sh
# 1. Write a policy: at least 12 characters, three character classes,
#    and no company name anywhere in the password.
cat > rules.txt <<'EOF'
# website rules
min_length = 12
min_classes = 3
forbid = acme
forbid_common = yes
EOF

# 2. Check the policy file itself.
python3 passgrade.py policy rules.txt
```

Output:

```
rules.txt: OK
  min_length = 12
  min_classes = 3
  forbid = acme
  forbid_common = yes
  forbid_patterns = no
```

```sh
# 3. Put candidates in a file, one per line, and check them all.
printf '%s\n' 'maple-quartz-7' 'password' > candidates.txt
python3 passgrade.py batch candidates.txt --policy rules.txt
echo "exit code: $?"
```

Output ends with the summary line:

```
2 checked, 1 passed, 1 failed
exit code: 1
```

`password` fails on length and as a common word. The candidates themselves are printed as masked placeholders, so the terminal and any log never show them.

## Usage

```sh
python3 passgrade.py rate [--policy FILE] [--json]          # type one password, hidden
python3 passgrade.py batch FILE [--policy FILE] [--json]    # one candidate per line
python3 passgrade.py policy FILE                            # lint a policy file
python3 passgrade.py generate [--length N] [--count N] [--classes lower,upper,digit,symbol]
python3 passgrade.py passphrase [--words N] [--count N] [--separator C]
```

Policy keys: `min_length`, `max_length`, `min_classes` (1 to 4), `forbid` (comma-separated, may repeat), `min_bits`, `forbid_common`, `forbid_patterns`. Text after `#` is a comment.

## Requirements

- Python 3.10 or newer
- Nothing else for the tool. Tests need `pytest`.

## How to run

Run the commands above from the project directory. The tool is a single file, so you can also copy `passgrade.py` anywhere and run it with `python3`.

## How to test

```sh
python3 -m pip install pytest
python3 -m pytest
```

The tests in `tests/test_passgrade.py` cover the entropy and pattern logic, score boundaries, crack-time formatting, policy parsing with line numbers, policy evaluation, masking, random generation, and the batch and policy command-line exit codes.

## Notes and limits

- The entropy figure is an estimate. It assumes the password was chosen from the character classes it uses and does not model real dictionaries beyond the short built-in common-word list.
- Crack times are averages for guessing a random password of that strength. They are not a promise about any real system.
- Passwords are never stored. Batch input is read from the file you name, and no output includes the password text.
