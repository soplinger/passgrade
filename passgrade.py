#!/usr/bin/env python3
"""passgrade: offline password strength estimator, policy checker and generator.

Standard library only. Nothing is sent over the network, and no password is
ever written to disk or printed in full by the batch commands.
"""

import argparse
import getpass
import json
import math
import re
import secrets
import string
import sys
from dataclasses import dataclass
from pathlib import Path

__version__ = "1.0.0"

# Size of the character pool each class contributes to the brute-force keyspace.
POOL = {"lower": 26, "upper": 26, "digit": 10, "symbol": 32, "other": 100}

# Guesses per second for three attacker models. Online attacks are throttled
# by the service; the offline rates are rough single-GPU figures for fast and
# slow (salted, iterated) hashes.
ATTACK_RATES = {
    "online-throttled": 100 / 3600,
    "offline-slow": 1e4,
    "offline-fast": 1e11,
}

# Entropy lost for each structural pattern found in a password.
PATTERN_PENALTY = {"repeat": 6, "sequence": 6, "keyboard": 6, "year": 4}
COMMON_CAP_BITS = 10.0

# Score boundaries on estimated bits: below each limit gets that score.
SCORE_LIMITS = (28, 36, 60, 80)
SCORE_LABELS = ("very weak", "weak", "fair", "strong", "very strong")

COMMON_WORDS = (
    "password", "letmein", "welcome", "monkey", "dragon", "qwerty", "login",
    "admin", "sunshine", "iloveyou", "football", "baseball", "master", "shadow",
    "princess", "hello", "freedom", "whatever", "batman", "superman", "trustno",
    "access", "secret",
)

KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

# Common leetspeak substitutions, undone before checking for common words.
LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
        "$": "s", "5": "s", "7": "t", "+": "t", "8": "b", "9": "g"}

# 64 short words, so each word adds exactly 6 bits.
WORDS = (
    "acorn", "amber", "anchor", "aspen", "badge", "basin", "beacon", "birch",
    "bloom", "brick", "cabin", "candle", "cedar", "cloud", "comet", "coral",
    "crane", "delta", "drift", "ember", "fable", "fern", "flint", "forest",
    "frost", "garden", "glade", "harbor", "hazel", "heron", "island", "ivory",
    "jewel", "juniper", "kettle", "lantern", "maple", "meadow", "mirror", "moss",
    "nectar", "orbit", "otter", "pebble", "pine", "prairie", "quartz", "raven",
    "river", "saddle", "sable", "silver", "spruce", "summit", "tulip", "valley",
    "velvet", "willow", "yarrow", "zephyr", "canyon", "meteor", "pillow", "lichen",
)

CLASS_POOLS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digit": string.digits,
    "symbol": string.punctuation,
}

YEAR = 31557600  # seconds in a Julian year

BOOL_WORDS = {"yes": True, "true": True, "on": True, "1": True,
              "no": False, "false": False, "off": False, "0": False}


def classify(char):
    """Return the character class name for one character."""
    if char.isascii():
        if char.islower():
            return "lower"
        if char.isupper():
            return "upper"
        if char.isdigit():
            return "digit"
        if char in string.punctuation:
            return "symbol"
    return "other"


def char_classes(pw):
    """Return the set of character classes present in the password."""
    return {classify(c) for c in pw}


def pool_size(pw):
    """Return the brute-force alphabet size implied by the classes present."""
    return sum(POOL[name] for name in char_classes(pw))


def _has_sequence(pw):
    """True if four adjacent letters or digits run in order, up or down."""
    for i in range(len(pw) - 3):
        window = pw[i:i + 4]
        if not all(c.isascii() and c.isalnum() for c in window):
            continue
        steps = [ord(window[j + 1]) - ord(window[j]) for j in range(3)]
        if steps in ([1, 1, 1], [-1, -1, -1]):
            return True
    return False


def _has_keyboard_walk(lowered):
    """True if four keys in a row on the keyboard appear, forwards or backwards."""
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            run = row[i:i + 4]
            if run in lowered or run[::-1] in lowered:
                return True
    return False


def _has_common_word(lowered):
    """True if a common word appears after undoing leetspeak substitutions."""
    folded = "".join(LEET.get(c, c) for c in lowered)
    folded = re.sub(r"[^a-z]", "", folded)
    return any(word in folded for word in COMMON_WORDS)


def find_patterns(pw):
    """Return the structural weaknesses found in the password."""
    lowered = pw.lower()
    found = []
    if re.search(r"(.)\1\1", pw):
        found.append("repeat")
    if _has_sequence(pw):
        found.append("sequence")
    if _has_keyboard_walk(lowered):
        found.append("keyboard")
    if re.search(r"(?<!\d)(19|20)\d\d(?!\d)", pw):
        found.append("year")
    if _has_common_word(lowered):
        found.append("common")
    return found


def analyse(pw):
    """Return (estimated bits, patterns) for a password."""
    if not pw:
        return 0.0, []
    patterns = find_patterns(pw)
    bits = len(pw) * math.log2(pool_size(pw))
    bits -= sum(PATTERN_PENALTY.get(p, 0) for p in patterns)
    if "common" in patterns:
        bits = min(bits, COMMON_CAP_BITS)
    return max(bits, 0.0), patterns


def score_bits(bits):
    """Map estimated bits to a 0-4 score."""
    for score, limit in enumerate(SCORE_LIMITS):
        if bits < limit:
            return score
    return len(SCORE_LIMITS)


def crack_seconds(bits, rate):
    """Average seconds to find the password at the given guesses per second."""
    if bits > 1000:
        return math.inf
    return 2.0 ** max(bits - 1, 0) / rate


def humanize(seconds):
    """Turn seconds into a short phrase such as '3 days' or 'over a billion years'."""
    if math.isinf(seconds):
        return "effectively forever"
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        value, unit = seconds, "second"
    elif seconds < 3600:
        value, unit = seconds / 60, "minute"
    elif seconds < 86400:
        value, unit = seconds / 3600, "hour"
    elif seconds < YEAR:
        value, unit = seconds / 86400, "day"
    elif seconds < 1e9 * YEAR:
        value, unit = seconds / YEAR, "year"
    else:
        return "over a billion years"
    count = round(value)
    return f"{count:,} {unit}{'' if count == 1 else 's'}"


@dataclass
class Policy:
    """Rules a password must meet. Defaults are a sensible minimum."""

    min_length: int = 8
    max_length: int | None = None
    min_classes: int = 1
    forbid: tuple = ()
    min_bits: float = 0.0
    forbid_common: bool = True
    forbid_patterns: bool = False

    def describe(self):
        """Return the effective rules as readable lines."""
        lines = [f"min_length = {self.min_length}"]
        if self.max_length is not None:
            lines.append(f"max_length = {self.max_length}")
        lines.append(f"min_classes = {self.min_classes}")
        if self.forbid:
            lines.append("forbid = " + ", ".join(self.forbid))
        if self.min_bits:
            lines.append(f"min_bits = {self.min_bits:g}")
        lines.append(f"forbid_common = {'yes' if self.forbid_common else 'no'}")
        lines.append(f"forbid_patterns = {'yes' if self.forbid_patterns else 'no'}")
        return lines


def _whole(value, low, high):
    try:
        number = int(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a whole number") from None
    if not low <= number <= high:
        raise ValueError(f"{number} is outside {low}-{high}")
    return number


def _flag(value):
    try:
        return BOOL_WORDS[value.lower()]
    except KeyError:
        raise ValueError(f"'{value}' is not yes or no") from None


def _amount(value):
    try:
        number = float(value)
    except ValueError:
        raise ValueError(f"'{value}' is not a number") from None
    if number < 0 or math.isnan(number):
        raise ValueError("must not be negative")
    return number


def parse_policy(text):
    """Parse a 'key = value' policy file. Returns (Policy, [(line, message)])."""
    policy = Policy()
    errors = []
    key_lines = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            errors.append((number, "expected 'key = value'"))
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        key = key.lower()
        key_lines[key] = number
        try:
            if key == "min_length":
                policy.min_length = _whole(value, 1, 1024)
            elif key == "max_length":
                policy.max_length = _whole(value, 1, 1024)
            elif key == "min_classes":
                policy.min_classes = _whole(value, 1, 4)
            elif key == "min_bits":
                policy.min_bits = _amount(value)
            elif key == "forbid":
                words = tuple(w.strip().lower() for w in value.split(",") if w.strip())
                policy.forbid = policy.forbid + words
            elif key == "forbid_common":
                policy.forbid_common = _flag(value)
            elif key == "forbid_patterns":
                policy.forbid_patterns = _flag(value)
            else:
                errors.append((number, f"unknown key '{key}'"))
        except ValueError as exc:
            errors.append((number, f"{key}: {exc}"))
    if policy.max_length is not None and policy.min_length > policy.max_length:
        errors.append((key_lines["max_length"], "max_length is below min_length"))
    return policy, errors


def mask(pw):
    """Hide a password completely, keeping only its length."""
    if not pw:
        return "(empty)"
    return f"{'*' * len(pw)} ({len(pw)} chars)"


def evaluate(pw, policy=None):
    """Estimate strength and check the password against the policy."""
    policy = policy or Policy()
    bits, patterns = analyse(pw)
    classes = char_classes(pw)
    lowered = pw.lower()
    failures = []

    if len(pw) < policy.min_length:
        failures.append(f"shorter than {policy.min_length} characters")
    if policy.max_length is not None and len(pw) > policy.max_length:
        failures.append(f"longer than {policy.max_length} characters")
    if len(classes) < policy.min_classes:
        failures.append(f"uses {len(classes)} character class(es), needs {policy.min_classes}")
    for word in policy.forbid:
        if word in lowered:
            failures.append(f"contains forbidden text '{word}'")
    if policy.forbid_common and "common" in patterns:
        failures.append("contains a common word from the built-in list")
    if policy.forbid_patterns:
        for pattern in patterns:
            if pattern != "common":
                failures.append(f"contains a {pattern} pattern")
    if bits < policy.min_bits:
        failures.append(f"estimated {bits:.1f} bits, needs {policy.min_bits:g}")

    score = score_bits(bits)
    return {
        "ok": not failures,
        "failures": failures,
        "length": len(pw),
        "bits": round(bits, 1),
        "score": score,
        "label": SCORE_LABELS[score],
        "patterns": patterns,
        "classes": sorted(classes),
        "crack_times": {name: humanize(crack_seconds(bits, rate))
                        for name, rate in ATTACK_RATES.items()},
    }


def check_lines(lines, policy):
    """Evaluate each non-empty line. Results carry line numbers and masked text only."""
    results = []
    for number, raw in enumerate(lines, start=1):
        pw = raw.rstrip("\r\n")
        if not pw:
            continue
        results.append({"line": number, "masked": mask(pw), **evaluate(pw, policy)})
    return results


def generate(length=16, classes=("lower", "upper", "digit", "symbol")):
    """Return a random password with at least one character from each class."""
    classes = tuple(classes)
    for name in classes:
        if name not in CLASS_POOLS:
            raise ValueError(f"unknown class '{name}'")
    if len(set(classes)) != len(classes) or not classes:
        raise ValueError("classes must be a non-empty list with no repeats")
    if length < len(classes):
        raise ValueError(f"length {length} is too short for {len(classes)} classes")
    alphabet = "".join(CLASS_POOLS[name] for name in classes)
    chars = [secrets.choice(CLASS_POOLS[name]) for name in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(classes))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def passphrase(words=6, separator="-"):
    """Return a random passphrase of common words."""
    if words < 1:
        raise ValueError("words must be at least 1")
    return separator.join(secrets.choice(WORDS) for _ in range(words))


def passphrase_bits(words):
    """Exact entropy of a passphrase made by passphrase()."""
    return words * math.log2(len(WORDS))


def _load_policy(path):
    if path is None:
        return Policy(), []
    return parse_policy(Path(path).read_text(encoding="utf-8"))


def _render(result, indent="  "):
    status = "PASS" if result["ok"] else "FAIL"
    lines = [f"{indent}{status}  {result['bits']:>6.1f} bits  score {result['score']}/4 "
             f"({result['label']})"]
    if result["patterns"]:
        lines.append(f"{indent}patterns: {', '.join(result['patterns'])}")
    for reason in result["failures"]:
        lines.append(f"{indent}- {reason}")
    return lines


def cmd_rate(args):
    policy, errors = _load_policy(args.policy)
    if errors:
        _report_policy_errors(args.policy, errors)
        return 2
    pw = getpass.getpass("Password: ")
    if not pw:
        print("no password entered", file=sys.stderr)
        return 2
    result = evaluate(pw, policy)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("\n".join(_render(result, indent="")))
        print("crack time (average guess):")
        for name, text in result["crack_times"].items():
            print(f"  {name:<18} {text}")
    return 0 if result["ok"] else 1


def cmd_batch(args):
    policy, errors = _load_policy(args.policy)
    if errors:
        _report_policy_errors(args.policy, errors)
        return 2
    text = Path(args.file).read_text(encoding="utf-8")
    results = check_lines(text.splitlines(), policy)
    if not results:
        print(f"{args.file}: no passwords found", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print(f"line {result['line']:>4}  {result['masked']}")
            print("\n".join(_render(result, indent="    ")))
        passed = sum(1 for r in results if r["ok"])
        print(f"{len(results)} checked, {passed} passed, {len(results) - passed} failed")
    return 0 if all(r["ok"] for r in results) else 1


def cmd_policy(args):
    policy, errors = _load_policy(args.file)
    if errors:
        _report_policy_errors(args.file, errors)
        return 2
    print(f"{args.file}: OK")
    for line in policy.describe():
        print(f"  {line}")
    return 0


def cmd_generate(args):
    classes = [c.strip() for c in args.classes.split(",") if c.strip()]
    try:
        for _ in range(args.count):
            print(generate(args.length, classes))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_passphrase(args):
    try:
        for _ in range(args.count):
            print(passphrase(args.words, args.separator))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.words >= 1:
        print(f"entropy: {passphrase_bits(args.words):.1f} bits each", file=sys.stderr)
    return 0


def _report_policy_errors(path, errors):
    for number, message in errors:
        print(f"{path}:{number}: {message}", file=sys.stderr)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="passgrade",
        description="Offline password strength estimator, policy checker and generator.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    rate = sub.add_parser("rate", help="type one password (hidden) and rate it")
    rate.add_argument("--policy", help="policy file to check against")
    rate.add_argument("--json", action="store_true", help="print JSON")
    rate.set_defaults(handler=cmd_rate)

    batch = sub.add_parser("batch", help="rate one password per line of a file")
    batch.add_argument("file", help="file with one candidate password per line")
    batch.add_argument("--policy", help="policy file to check against")
    batch.add_argument("--json", action="store_true", help="print JSON (masked)")
    batch.set_defaults(handler=cmd_batch)

    policy = sub.add_parser("policy", help="lint a policy file")
    policy.add_argument("file")
    policy.set_defaults(handler=cmd_policy)

    gen = sub.add_parser("generate", help="random passwords with guaranteed classes")
    gen.add_argument("--length", type=int, default=16)
    gen.add_argument("--count", type=int, default=1)
    gen.add_argument("--classes", default="lower,upper,digit,symbol",
                     help="comma list of lower,upper,digit,symbol")
    gen.set_defaults(handler=cmd_generate)

    phrase = sub.add_parser("passphrase", help="random word passphrases")
    phrase.add_argument("--words", type=int, default=6)
    phrase.add_argument("--count", type=int, default=1)
    phrase.add_argument("--separator", default="-")
    phrase.set_defaults(handler=cmd_passphrase)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
