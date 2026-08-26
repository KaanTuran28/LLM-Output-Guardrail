# Clean Output

# LLM Output Guardrail Report

**Safe to return:** ✅ Yes
**Findings:** 0

No findings.

## Redacted Output

```
Sure, here's a summary of the quarterly report: revenue grew 12% year over year,
driven mainly by the expansion of the small-business segment. No action items
require immediate attention, and the team plans to revisit the roadmap next month.

```

---

# PII Leak Output

# LLM Output Guardrail Report

**Safe to return:** ❌ No
**Findings:** 3

| Type | Severity | Redacted Snippet |
|---|---|---|
| email | MEDIUM | `jan****om` |
| credit_card | HIGH | `411****11` |
| phone_number | MEDIUM | `+1 ****82` |

## Redacted Output

```
Thanks for reaching out! You can contact our support agent directly at
[REDACTED:email] or by phone at [REDACTED:phone_number]. For the refund,
please confirm the last four digits of the card ending in ...1111. Full card
number on file: [REDACTED:credit_card].

```

---

# Secret Leak Output

# LLM Output Guardrail Report

**Safe to return:** ❌ No
**Findings:** 1

| Type | Severity | Redacted Snippet |
|---|---|---|
| aws_access_key | HIGH | `AKI****OP` |

## Redacted Output

```
Here is the deployment snippet you asked for:

export AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key]
export AWS_SECRET_ACCESS_KEY=fake-example-secret-do-not-use

This should let the CI pipeline push artifacts to the S3 bucket.

```