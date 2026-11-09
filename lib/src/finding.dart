/// Severity levels for guard findings.
///
/// Ordered from least to most severe: `info < warning < critical`.
/// A rule that finds nothing returns an empty list of findings.
enum GuardSeverity {
  /// Worth logging but not actionable on its own — e.g. an unusual amount of
  /// capitalisation in a prompt.
  info,

  /// Suspicious and likely worth surfacing to the caller — e.g. a URL outside
  /// the allow list.
  warning,

  /// Almost certainly hostile or irreversible — e.g. a leaked API key or an
  /// explicit injection phrase. By default these block the request.
  critical,
}

/// What the pipeline should do when a rule fires.
enum GuardAction {
  /// Remove or mask the offending text and continue.
  redact,

  /// Reject the whole request or response.
  block,

  /// Record the finding but change nothing.
  flag,
}

/// A single problem a guard rule found.
class GuardFinding {
  /// Creates a finding.
  const GuardFinding({
    required this.ruleId,
    required this.severity,
    required this.message,
    this.matchedText,
    this.start,
    this.end,
  });

  /// Stable identifier of the rule that produced this finding, e.g.
  /// `prompt_injection`.
  final String ruleId;

  /// How severe the finding is.
  final GuardSeverity severity;

  /// Human-readable description, safe to show in logs and UIs.
  final String message;

  /// The offending text, when the rule can isolate it. Redacted findings
  /// never carry the matched text itself (it is already gone).
  final String? matchedText;

  /// Start offset of the match in the inspected text, when known.
  final int? start;

  /// End offset (exclusive) of the match, when known.
  final int? end;

  @override
  String toString() => 'GuardFinding($ruleId, $severity, $message)';
}
