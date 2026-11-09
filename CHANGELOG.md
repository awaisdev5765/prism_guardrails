# Changelog

## 0.1.0

Initial release.

- GuardPipeline with inspectInput / inspectOutput and a capped AuditLog
- PromptInjectionRule: instruction overrides, role hijacking, fake chat
  control tokens, system-prompt exfiltration phrasing
- PiiRedactionRule: emails, phones, Luhn-validated credit cards, public IPv4
  with private-range awareness, SSN-shaped IDs, IBANs, custom patterns
- SecretDetectorRule: OpenAI/GitHub/AWS/Slack/Google/Stripe credential
  shapes, bearer tokens, JWTs, PEM private keys, credential assignments
- UnicodeSafetyRule: zero-width/bidi/tag-character stripping, homoglyph
  detection
- ProfanityRule: whole-word blocklist with masking
- UrlFilterRule: allow/deny host lists and scheme enforcement
- SchemaRule: JSON schema-lite validation tolerant of fenced and
  prose-wrapped model output
- TokenBudgetRule: per-request and rolling-window token budgets
