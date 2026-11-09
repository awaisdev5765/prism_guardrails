/// The AI safety layer for Dart and Flutter.
///
/// One import gives you the whole toolkit:
///
/// ```dart
/// import 'package:ai_guardrails/ai_guardrails.dart';
///
/// final pipeline = GuardPipeline(
///   rules: [
///     UnicodeSafetyRule(),
///     PromptInjectionRule(),
///     PiiRedactionRule(),
///     SecretDetectorRule(),
///     UrlFilterRule(),
///   ],
/// );
///
/// final input = pipeline.inspectInput(userText);
/// if (input.blocked) return refuse();
/// final reply = await model.chat(input.cleaned);
/// final output = pipeline.inspectOutput(reply);
/// show(output.blocked ? refusalMessage() : output.cleaned);
/// ```
///
/// Everything is pure Dart: it runs in Flutter apps, on the server with
/// `dart:io`, in CLI tools, and in tests — with zero package dependencies.
library;

export 'src/audit_log.dart';
export 'src/finding.dart';
export 'src/pipeline.dart';
export 'src/rule.dart';
export 'src/rules/injection.dart';
export 'src/rules/pii.dart';
export 'src/rules/profanity.dart';
export 'src/rules/schema.dart';
export 'src/rules/secrets.dart';
export 'src/rules/token_budget.dart';
export 'src/rules/unicode_safety.dart';
export 'src/rules/url_filter.dart';
