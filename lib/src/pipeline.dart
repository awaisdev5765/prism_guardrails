import 'audit_log.dart';
import 'finding.dart';
import 'rule.dart';

/// A composable chain of guard rules with one call for each side of a model
/// conversation.
///
/// ```dart
/// final pipeline = GuardPipeline(
///   rules: [
///     UnicodeSafetyRule(),
///     PromptInjectionRule(),
///     PiiRedactionRule(),
///     SecretDetectorRule(),
///   ],
/// );
///
/// final input = pipeline.inspectInput(userMessage);
/// if (input.blocked) return showBlocked();
/// await sendToModel(input.cleaned);
///
/// final output = pipeline.inspectOutput(modelReply);
/// if (output.blocked) return showRefusal();
/// display(output.cleaned);
/// ```
///
/// The default policy is: **redact rules clean the text, critical findings
/// from `block` rules reject it, everything else is recorded**. You can
/// override how any severity is treated with [blockAt].
class GuardPipeline {
  /// Creates a pipeline.
  GuardPipeline({
    required this.rules,
    this.auditLog,
    this.blockAt = GuardSeverity.critical,
  });

  /// The rules, applied in order for cleaning.
  final List<GuardRule> rules;

  /// Optional audit trail receiving every decision.
  final AuditLog? auditLog;

  /// The lowest severity that counts as a block for `block`-action rules.
  final GuardSeverity blockAt;

  /// Inspects user input heading *towards* the model.
  GuardInspection inspectInput(String text, {String? label}) =>
      _run(text, 'input', label);

  /// Inspects a model response heading *towards* the user.
  GuardInspection inspectOutput(String text, {String? label}) =>
      _run(text, 'output', label);

  GuardInspection _run(String text, String stage, String? label) {
    var working = text;
    final findings = <GuardFinding>[];
    var blocked = false;

    for (final rule in rules) {
      // Inspect the current (possibly already cleaned) text so a finding's
      // offsets line up with the text downstream rules will see.
      final ruleFindings = rule.inspect(working);
      findings.addAll(ruleFindings);
      if (rule.action == GuardAction.block &&
          ruleFindings.any((f) => f.severity.index >= blockAt.index)) {
        blocked = true;
      }
      if (rule.action == GuardAction.redact) {
        final cleaned = rule.clean(working);
        if (cleaned != null) working = cleaned;
      }
    }

    findings.sort((a, b) => b.severity.index.compareTo(a.severity.index));
    final inspection = GuardInspection(
      original: text,
      cleaned: working,
      findings: findings,
      blocked: blocked,
    );
    auditLog?.add(stage: stage, inspection: inspection, label: label);
    return inspection;
  }
}
