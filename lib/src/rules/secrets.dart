import '../finding.dart';
import '../rule.dart';

/// Detects credentials before they leave your process.
///
/// Covers the credential shapes most often pasted into chat boxes:
/// - OpenAI-style keys (`sk-…`)
/// - GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
/// - AWS access keys (`AKIA…`)
/// - Slack tokens (`xoxb-`, `xoxp-`)
/// - Google API keys (`AIza…`)
/// - Stripe keys (`sk_live_`, `pk_live_`)
/// - Bearer headers and JSON Web Tokens
/// - PEM private key blocks
/// - Generic `password:`, `api_key:` assignments
///
/// Every finding is `critical`: a leaked credential is an incident even if
/// the user "meant" to share it, so the rule blocks by default and refuses to
/// redact silently (masking a live key without telling anyone hides a breach).
class SecretDetectorRule extends GuardRule {
  /// Creates a secret detector.
  SecretDetectorRule({this.action = GuardAction.block, this.customPatterns = const []});

  @override
  GuardAction action;

  /// Additional patterns treated as critical secrets.
  final List<RegExp> customPatterns;

  static final _patterns = <(RegExp, String)>[
    (
      RegExp(r'\bsk-[A-Za-z0-9_-]{20,}\b'),
      'OpenAI-style API key',
    ),
    (
      RegExp(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
      'GitHub token',
    ),
    (
      RegExp(r'\bAKIA[0-9A-Z]{16}\b'),
      'AWS access key',
    ),
    (
      RegExp(r'\bxox[bpas]-[A-Za-z0-9-]{10,}\b'),
      'Slack token',
    ),
    (
      RegExp(r'\bAIza[0-9A-Za-z_-]{35}\b'),
      'Google API key',
    ),
    (
      RegExp(r'\b[sr]k_live_[A-Za-z0-9]{16,}\b'),
      'Stripe secret key',
    ),
    (
      RegExp(r'\bBearer\s+[A-Za-z0-9_\-.=]{20,}\b', caseSensitive: false),
      'Bearer token',
    ),
    (
      RegExp(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b'),
      'JWT',
    ),
    (
      RegExp(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
      'PEM private key',
    ),
    (
      RegExp(
        r"\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*"
        r'''["']?[A-Za-z0-9_\-/+]{12,}''',
        caseSensitive: false,
      ),
      'Credential assignment',
    ),
  ];

  @override
  String get id => 'secret_detection';

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];
    for (final (pattern, label) in _patterns) {
      for (final m in pattern.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message: label,
            start: m.start,
            end: m.end,
          ),
        );
      }
    }
    for (final p in customPatterns) {
      for (final m in p.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message: 'Custom secret pattern',
            start: m.start,
            end: m.end,
          ),
        );
      }
    }
    return findings;
  }
}
