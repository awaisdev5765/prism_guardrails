import 'finding.dart';

/// A single guard check over a piece of text.
///
/// Rules are pure: `inspect` never mutates global state and is safe to call
/// concurrently. Rules that sanitise rather than merely report return the
/// cleaned text through [clean].
///
/// Implement this to plug your own checks into a pipeline — e.g. your
/// blocklist, your moderation endpoint, or a domain-specific validator.
abstract class GuardRule {
  /// Stable identifier used in findings and audit logs, e.g. `pii_email`.
  String get id;

  /// What the pipeline should do when this rule fires.
  GuardAction get action;

  /// Inspects [text] and returns every finding.
  List<GuardFinding> inspect(String text);

  /// Optional sanitised replacement for [text]. Return `null` (the default)
  /// when the rule never rewrites text.
  String? clean(String text) => null;
}

/// The outcome of inspecting one piece of text with a pipeline.
class GuardInspection {
  /// Creates an inspection result.
  const GuardInspection({
    required this.original,
    required this.cleaned,
    required this.findings,
    required this.blocked,
  });

  /// The text as it was handed to the pipeline.
  final String original;

  /// The text after every `redact`-action rule has run.
  final String cleaned;

  /// Every finding, ordered by severity (most severe first).
  final List<GuardFinding> findings;

  /// True when at least one `block`-action rule fired.
  final bool blocked;

  /// Findings at or above [severity].
  List<GuardFinding> atLeast(GuardSeverity severity) =>
      findings.where((f) => f.severity.index >= severity.index).toList();

  /// A one-line summary for logs, e.g. `blocked, 3 findings (2 critical)`.
  String get summary {
    final critical =
        findings.where((f) => f.severity == GuardSeverity.critical).length;
    final kind = blocked ? 'blocked' : 'passed';
    return '$kind, ${findings.length} findings, $critical critical';
  }
}
