import math

import pytest

import passgrade as pg


def test_char_classes_and_pool_size():
    assert pg.char_classes("aA1!") == {"lower", "upper", "digit", "symbol"}
    assert pg.pool_size("aA1!") == 26 + 26 + 10 + 32
    assert pg.pool_size("") == 0


def test_raw_entropy_of_lowercase_only_word():
    bits, patterns = pg.analyse("abc")
    assert patterns == []
    assert bits == pytest.approx(3 * math.log2(26))


def test_empty_password_has_no_bits():
    assert pg.analyse("") == (0.0, [])


def test_repeat_and_sequence_patterns_are_found():
    assert "repeat" in pg.find_patterns("xaaay9Q")
    assert "sequence" in pg.find_patterns("zq1234Zr")
    assert "sequence" in pg.find_patterns("Tq4321wz")


def test_keyboard_walk_and_year_are_found():
    assert "keyboard" in pg.find_patterns("qwertyX!")
    assert "year" in pg.find_patterns("summer2024")
    assert "year" not in pg.find_patterns("ref120345")


def test_leetspeak_common_word_is_flagged_and_capped():
    bits, patterns = pg.analyse("P@ssw0rd")
    assert "common" in patterns
    assert bits <= pg.COMMON_CAP_BITS


def test_patterns_reduce_estimated_bits():
    plain, _ = pg.analyse("hxvmzqtb")
    patterned, _ = pg.analyse("hxvmaaab")
    assert patterned < plain


def test_score_and_labels_are_monotonic():
    scores = [pg.score_bits(b) for b in (0, 30, 40, 70, 120)]
    assert scores == [0, 1, 2, 3, 4]
    assert pg.SCORE_LABELS[pg.score_bits(120)] == "very strong"


def test_humanize_and_crack_times():
    assert pg.humanize(0.2) == "instantly"
    assert pg.humanize(1) == "1 second"
    assert pg.humanize(3 * 86400) == "3 days"
    assert pg.humanize(math.inf) == "effectively forever"
    assert pg.crack_seconds(10, 1.0) == pytest.approx(2 ** 9)
    assert pg.crack_seconds(2000, 1.0) == math.inf


def test_parse_policy_reads_rules_and_reports_line_numbers():
    text = (
        "# website rules\n"
        "min_length = 12\n"
        "max_length = 64\n"
        "min_classes = 3\n"
        "forbid = Acme, Company\n"
        "forbid_patterns = yes\n"
        "\n"
        "min_bits = lots\n"
        "colour = red\n"
        "forbid_common = maybe\n"
    )
    policy, errors = pg.parse_policy(text)
    assert policy.min_length == 12
    assert policy.max_length == 64
    assert policy.min_classes == 3
    assert policy.forbid == ("acme", "company")
    assert policy.forbid_patterns is True
    assert errors == [
        (8, "min_bits: 'lots' is not a number"),
        (9, "unknown key 'colour'"),
        (10, "forbid_common: 'maybe' is not yes or no"),
    ]


def test_parse_policy_rejects_inverted_lengths_and_bad_lines():
    policy, errors = pg.parse_policy("min_length = 20\nmax_length = 10\nnonsense\n")
    assert (2, "max_length is below min_length") in errors
    assert (3, "expected 'key = value'") in errors


def test_evaluate_applies_every_rule():
    policy = pg.Policy(min_length=10, min_classes=3, forbid=("acme",), forbid_patterns=True)
    result = pg.evaluate("acme1234", policy)
    assert result["ok"] is False
    joined = " | ".join(result["failures"])
    assert "shorter than 10" in joined
    assert "needs 3" in joined
    assert "forbidden text 'acme'" in joined
    assert "sequence pattern" in joined


def test_evaluate_passes_a_strong_passphrase():
    result = pg.evaluate("maple-Quartz-7-otter!", pg.Policy(min_length=12, min_classes=3))
    assert result["ok"] is True
    assert result["score"] >= 3


def test_mask_hides_every_character():
    assert pg.mask("hunter2x") == "******** (8 chars)"
    assert "hunter" not in pg.mask("hunter2x")
    assert pg.mask("") == "(empty)"


def test_check_lines_keeps_line_numbers_and_skips_blanks():
    results = pg.check_lines(["maple-quartz-7", "", "password"], pg.Policy())
    assert [r["line"] for r in results] == [1, 3]
    assert results[1]["ok"] is False
    assert all("password" not in r["masked"] for r in results)


def test_generate_meets_class_requirements():
    for _ in range(50):
        pw = pg.generate(12)
        assert len(pw) == 12
        assert pg.char_classes(pw) == {"lower", "upper", "digit", "symbol"}


def test_generate_validates_arguments():
    with pytest.raises(ValueError):
        pg.generate(2)
    with pytest.raises(ValueError):
        pg.generate(10, ["lower", "emoji"])


def test_passphrase_word_count_and_entropy():
    phrase = pg.passphrase(5)
    assert len(phrase.split("-")) == 5
    assert all(word in pg.WORDS for word in phrase.split("-"))
    assert len(pg.WORDS) == 64
    assert pg.passphrase_bits(5) == pytest.approx(30.0)


def test_cli_batch_exit_codes_and_masking(tmp_path, capsys):
    candidates = tmp_path / "candidates.txt"
    candidates.write_text("maple-quartz-7\npassword\n", encoding="utf-8")
    assert pg.main(["batch", str(candidates)]) == 1
    out = capsys.readouterr().out
    assert "line    2" in out
    assert "password" not in out
    assert "2 checked, 1 passed, 1 failed" in out

    candidates.write_text("maple-quartz-7\n", encoding="utf-8")
    assert pg.main(["batch", str(candidates)]) == 0


def test_cli_batch_json_output_has_no_plaintext(tmp_path, capsys):
    import json

    candidates = tmp_path / "list.txt"
    candidates.write_text("maple-quartz-7\n", encoding="utf-8")
    assert pg.main(["batch", str(candidates), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["line"] == 1
    assert "maple" not in json.dumps(data)


def test_cli_policy_lint_fails_with_exit_two(tmp_path, capsys):
    policy_file = tmp_path / "policy.txt"
    policy_file.write_text("min_length = nope\n", encoding="utf-8")
    assert pg.main(["policy", str(policy_file)]) == 2
    assert f"{policy_file}:1:" in capsys.readouterr().err


def test_cli_missing_file_exits_two(tmp_path, capsys):
    assert pg.main(["batch", str(tmp_path / "absent.txt")]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_generate_and_passphrase_print_requested_counts(capsys):
    assert pg.main(["generate", "--length", "20", "--count", "3"]) == 0
    lines = capsys.readouterr().out.split()
    assert len(lines) == 3 and all(len(p) == 20 for p in lines)
    assert pg.main(["passphrase", "--words", "4", "--count", "2"]) == 0
    assert len(capsys.readouterr().out.split()) == 2
