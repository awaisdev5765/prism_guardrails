# ai_guardrails

The AI safety layer for Dart and Flutter.

Prompt injection detection, PII redaction, secret detection, content
filtering, structured-output validation and token budgeting — one composable
pipeline, zero dependencies, pure Dart. Runs in Flutter apps, on servers with
`dart:io`, in CLI tools, and in tests.

## Why

If your app sends user text to an LLM and shows the reply, you have three
problems: users paste things they shouldn't (API keys, cards, PII), prompts
get hijacked ("ignore all previous instructions"), and model output drifts
from the JSON you asked for. `ai_guardrails` turns all three into a single,
auditable check on each side of the call.

```dart
import 'package:ai_guardrails/ai_guardrails.dart';

final pipeline = GuardPipeline(
  rules: [
    UnicodeSafetyRule(),
    PromptInjectionRule(),
    PiiRedactionRule(),
    SecretDetectorRule(),
    UrlFilterRule(),
  ],
);

final input = pipeline.inspectInput(userText);
if (input.blocked) return refuse();
final reply = await model.chat(input.cleaned);
final output = pipeline.inspectOutput(reply);
show(output.blocked ? refusalText : output.cleaned);
```

## The rules

| Rule | Fires on | Default action |
|---|---|---|
| UnicodeSafetyRule | zero-width chars, bidi overrides, tag characters | redact |
| PromptInjectionRule | instruction overrides, role hijacking, fake chat tokens, prompt exfiltration | block |
| PiiRedactionRule | emails, phones, Luhn-valid cards, public IPs, SSN-shaped IDs, IBANs | redact |
| SecretDetectorRule | sk-..., ghp_..., AKIA..., xox...-, AIza..., Stripe live keys, bearer tokens, JWTs, PEM keys, credential assignments | block |
| ProfanityRule | your word list, whole-word only | configurable |
| UrlFilterRule | non-allow-listed hosts, denied hosts, non-http(s) schemes | block |
| SchemaRule | model JSON that misses required fields, wrong types, bad enum values, out-of-range numbers | flag |
| TokenBudgetRule | requests above a per-request or rolling-window token estimate | block |

Every rule is one class. Add your own by implementing GuardRule:

```dart
class NoDiscussPrices implements GuardRule {
  @override
  String get id => 'no_prices';
  @override
  GuardAction get action => GuardAction.block;
  @override
  List<GuardFinding> inspect(String text) =>
      RegExp(r'\$\s?\d+')
          .allMatches(text)
          .map((m) => GuardFinding(
                ruleId: id,
                severity: GuardSeverity.warning,
                message: 'Mentions a price',
              ))
          .toList();
}
```

## The pipeline

- inspectInput(text) — what the user typed, heading to the model.
- inspectOutput(text) — what the model replied, heading to the user.
- redact rules rewrite `cleaned`; block rules reject when they find a
  finding at or above `blockAt` (default: critical); flag rules only report.
- Every decision lands in the optional AuditLog — capped, and safe to
  persist because redacted rules never store the matched secret text.

```dart
final result = pipeline.inspectInput(text, label: 'conversation-42');
print(result.summary); // blocked, 3 findings, 2 critical
for (final f in result.atLeast(GuardSeverity.warning)) {
  print('${f.ruleId}: ${f.message}');
}
```

## Structured output, before it crashes your UI

Models omit fields and invent enum values. Check the reply against the shape
you asked for:

```dart
final rule = SchemaRule(
  fields: [
    SchemaField(
      name: 'sentiment',
      type: SchemaType.string,
      allowedValues: ['positive', 'negative', 'neutral'],
    ),
    SchemaField(name: 'confidence', type: SchemaType.number, min: 0, max: 1),
  ],
);

final findings = rule.inspectJson(modelReply); // tolerates fenced/prose JSON
```

## Budgets that survive real usage

TokenBudgetRule estimates ~4 characters per token (calibrate with
tokensPerChar), rejects oversized requests, and enforces a rolling window you
feed with spend() after each successful call.

## Why zero dependencies

Guardrails sit in front of everything — your app, your server, your CLI.
Every extra dependency is another audit surface for the component whose only
job is to be trustworthy. ai_guardrails is pure Dart: no http, no platform
channels, no transitive anything.

## Install

```bash
dart pub add ai_guardrails
```

## Testing

dart test — 44 tests cover every rule, the Luhn check, private-IP ranges,
homoglyph evasion, fenced-JSON extraction, rolling budgets and pipeline
composition.

## License

MIT — see LICENSE.
