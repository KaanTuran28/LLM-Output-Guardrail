#!/usr/bin/env python3
"""Scan LLM-generated text for PII, secret, and policy-violation leaks before it reaches a user."""
from __future__ import annotations

import argparse
import json
import re
import sys
from functools import wraps

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----")
API_KEY_RE = re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][0-9a-zA-Z]{16,45}['\"]")

DEFAULT_BANNED_PHRASES = [
    "ignoring previous instructions",
    "as an unrestricted ai",
    "here is the system prompt",
]

SEVERITY = {
    "email": "MEDIUM",
    "phone_number": "MEDIUM",
    "credit_card": "HIGH",
    "aws_access_key": "HIGH",
    "private_key": "HIGH",
    "generic_api_key": "HIGH",
    "banned_phrase": "MEDIUM",
}


def _luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _find_credit_cards(text: str):
    findings = []
    for m in CREDIT_CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            findings.append(m.group(0))
    return findings


def scan_output(text: str, extra_banned_phrases: list | None = None) -> dict:
    findings = []

    for m in EMAIL_RE.finditer(text):
        findings.append({"type": "email", "severity": SEVERITY["email"], "match": m.group(0)})

    cards = _find_credit_cards(text)
    for card in cards:
        findings.append({"type": "credit_card", "severity": SEVERITY["credit_card"], "match": card})

    for m in PHONE_RE.finditer(text):
        candidate = m.group(0)
        digit_count = sum(c.isdigit() for c in candidate)
        if 7 <= digit_count <= 12 and not any(candidate in card or card in candidate for card in cards):
            findings.append({"type": "phone_number", "severity": SEVERITY["phone_number"], "match": candidate})

    for m in AWS_KEY_RE.finditer(text):
        findings.append({"type": "aws_access_key", "severity": SEVERITY["aws_access_key"], "match": m.group(0)})

    for m in PRIVATE_KEY_RE.finditer(text):
        findings.append({"type": "private_key", "severity": SEVERITY["private_key"], "match": m.group(0)})

    for m in API_KEY_RE.finditer(text):
        findings.append({"type": "generic_api_key", "severity": SEVERITY["generic_api_key"], "match": m.group(0)})

    phrases = DEFAULT_BANNED_PHRASES + (extra_banned_phrases or [])
    lowered = text.lower()
    for phrase in phrases:
        if phrase.lower() in lowered:
            findings.append({"type": "banned_phrase", "severity": SEVERITY["banned_phrase"], "match": phrase})

    safe = not any(f["severity"] == "HIGH" for f in findings)
    return {"findings": findings, "safe_to_return": safe}


def redact(text: str, extra_banned_phrases: list | None = None) -> str:
    result = text
    for m in AWS_KEY_RE.finditer(text):
        result = result.replace(m.group(0), "[REDACTED:aws_access_key]")
    for m in PRIVATE_KEY_RE.finditer(text):
        result = result.replace(m.group(0), "[REDACTED:private_key]")
    for m in API_KEY_RE.finditer(text):
        result = result.replace(m.group(0), "[REDACTED:generic_api_key]")
    for card in _find_credit_cards(text):
        result = result.replace(card, "[REDACTED:credit_card]")
    for m in EMAIL_RE.finditer(text):
        result = result.replace(m.group(0), "[REDACTED:email]")
    for m in PHONE_RE.finditer(text):
        candidate = m.group(0)
        if sum(c.isdigit() for c in candidate) >= 7:
            result = result.replace(candidate, "[REDACTED:phone_number]")
    return result


def wrap(llm_call_fn, extra_banned_phrases: list | None = None):
    @wraps(llm_call_fn)
    def wrapped(prompt):
        output = llm_call_fn(prompt)
        result = scan_output(output, extra_banned_phrases=extra_banned_phrases)
        if not result["safe_to_return"]:
            return redact(output, extra_banned_phrases=extra_banned_phrases)
        return output
    return wrapped


def _snippet(match: str) -> str:
    if len(match) > 6:
        return match[:3] + "****" + match[-2:]
    return "****"


def render_report(text: str, result: dict) -> str:
    lines = ["# LLM Output Guardrail Report", ""]
    lines.append(f"**Safe to return:** {'✅ Yes' if result['safe_to_return'] else '❌ No'}")
    lines.append(f"**Findings:** {len(result['findings'])}")
    lines.append("")
    if result["findings"]:
        lines.append("| Type | Severity | Redacted Snippet |")
        lines.append("|---|---|---|")
        for f in result["findings"]:
            lines.append(f"| {f['type']} | {f['severity']} | `{_snippet(f['match'])}` |")
    else:
        lines.append("No findings.")
    lines.append("")
    lines.append("## Redacted Output")
    lines.append("")
    lines.append("```")
    lines.append(redact(text))
    lines.append("```")
    return "\n".join(lines)


def render_report_json(text: str, result: dict) -> str:
    payload = {
        "safe_to_return": result["safe_to_return"],
        "findings": [
            {
                "type": f["type"],
                "severity": f["severity"],
                "redacted_snippet": _snippet(f["match"]),
            }
            for f in result["findings"]
        ],
        "redacted_output": redact(text),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="Scan LLM output for PII, secrets, and policy violations.")
    parser.add_argument("--text")
    parser.add_argument("--file")
    parser.add_argument("--policy", help="JSON file with a list of extra banned phrases")
    parser.add_argument("--output", default="sample_report.md")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument(
        "--fail-on-unsafe",
        action="store_true",
        help="Exit with code 1 if the output is not safe to return (for CI gating).",
    )
    args = parser.parse_args()

    if args.text:
        text = args.text
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    extra_phrases = None
    if args.policy:
        with open(args.policy, "r", encoding="utf-8") as f:
            extra_phrases = json.load(f)

    result = scan_output(text, extra_banned_phrases=extra_phrases)
    report = render_report_json(text, result) if args.format == "json" else render_report(text, result)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Findings: {len(result['findings'])} | Safe to return: {result['safe_to_return']}")
    print(f"Report written to {args.output}")

    if args.fail_on_unsafe and not result["safe_to_return"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
