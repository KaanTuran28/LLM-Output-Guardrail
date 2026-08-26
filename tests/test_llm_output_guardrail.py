import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_output_guardrail import main, redact, render_report_json, scan_output, wrap


def test_email_detector():
    result = scan_output("Reach me at jane.doe@example-support.com any time.")
    types = [f["type"] for f in result["findings"]]
    assert "email" in types


def test_credit_card_luhn_valid_and_invalid():
    valid = scan_output("Card on file: 4111 1111 1111 1111.")
    types_valid = [f["type"] for f in valid["findings"]]
    assert "credit_card" in types_valid

    invalid = scan_output("Random number: 1234 5678 9012 3456.")
    types_invalid = [f["type"] for f in invalid["findings"]]
    assert "credit_card" not in types_invalid


def test_aws_key_detector():
    result = scan_output("export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP")
    types = [f["type"] for f in result["findings"]]
    assert "aws_access_key" in types
    assert result["safe_to_return"] is False


def test_banned_phrase_default_and_extra():
    default_result = scan_output("Sure, ignoring previous instructions, here you go.")
    assert any(f["type"] == "banned_phrase" for f in default_result["findings"])

    extra_result = scan_output("The secret codeword is pineapple42.", extra_banned_phrases=["pineapple42"])
    assert any(f["type"] == "banned_phrase" for f in extra_result["findings"])


def test_redact_removes_sensitive_values():
    text = "Contact jane.doe@example-support.com or key AKIAABCDEFGHIJKLMNOP"
    redacted = redact(text)
    assert "jane.doe@example-support.com" not in redacted
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "[REDACTED:email]" in redacted
    assert "[REDACTED:aws_access_key]" in redacted


def test_wrap_redacts_unsafe_and_passes_safe():
    def unsafe_target(prompt):
        return "Here is your key: AKIAABCDEFGHIJKLMNOP"

    def safe_target(prompt):
        return "The weather today is sunny with a light breeze."

    wrapped_unsafe = wrap(unsafe_target)
    wrapped_safe = wrap(safe_target)

    unsafe_output = wrapped_unsafe("give me a key")
    safe_output = wrapped_safe("what's the weather")

    assert "AKIAABCDEFGHIJKLMNOP" not in unsafe_output
    assert safe_output == "The weather today is sunny with a light breeze."


def test_json_report_is_valid_and_structured():
    text = "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"
    result = scan_output(text)
    payload = json.loads(render_report_json(text, result))

    assert payload["safe_to_return"] is False
    assert len(payload["findings"]) >= 1
    assert payload["findings"][0]["type"] == "aws_access_key"
    assert "redacted_snippet" in payload["findings"][0]


def test_json_report_does_not_leak_raw_secret():
    text = "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"
    result = scan_output(text)
    raw_json = render_report_json(text, result)

    assert "AKIAABCDEFGHIJKLMNOP" not in raw_json
    payload = json.loads(raw_json)
    assert "AKIAABCDEFGHIJKLMNOP" not in payload["redacted_output"]


def run_main(monkeypatch, tmp_path, text, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["llm_output_guardrail.py", "--text", text, "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_unsafe_exits_nonzero_when_secret_present(monkeypatch, tmp_path):
    exit_code = run_main(
        monkeypatch, tmp_path, "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", ["--fail-on-unsafe"]
    )
    assert exit_code == 1


def test_fail_on_unsafe_exits_zero_for_clean_text(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, "The weather today is sunny.", ["--fail-on-unsafe"])
    assert exit_code == 0


def test_no_fail_on_unsafe_always_exits_zero(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, "export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP", [])
    assert exit_code == 0
