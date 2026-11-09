import '../finding.dart';
import '../rule.dart';

/// Detects the classic prompt-injection patterns in user input.
///
/// Covers the families seen in the wild most often:
/// - instruction overrides ("ignore all previous instructions")
/// - role hijacking ("you are now DAN", "system: you must obey")
/// - constraint escapes ("no restrictions", "without any filters")
/// - tool/data exfiltration phrasing ("print your system prompt")
///
/// Heuristic by design: over-inclusive at `info`/`warning` level, `critical`
/// only on phrases hostile in essentially any context. Tune [customPatterns]
/// and [paranoid] for your product.
class PromptInjectionRule extends GuardRule {
  /// Creates an injection detector.
  PromptInjectionRule({
    this.action = GuardAction.block,
    this.customPatterns = const [],
    this.paranoid = false,
  }) {
    _patterns = [
      _p(
        r"ignore\s+(all\s+|any\s+|your\s+)?(previous|prior|above|earlier)"
        r"(\s+\w+){0,3}\s+(instructions?|prompts?|rules?|directions?|constraints?)",
        GuardSeverity.critical,
      ),
      _p(
        r"disregard\s+(all\s+|any\s+)?(previous|prior|above|earlier)"
        r"(\s+\w+){0,3}\s+(instructions?|prompts?|rules?)",
        GuardSeverity.critical,
      ),
      _p(
        r"forget\s+(everything|all|what)\s+(you|that|your)"
        r"(\s+\w+){0,3}\s+(were|was|have been|been)\s+(told|taught|instructed)",
        GuardSeverity.critical,
      ),
      _p(
        r"(reveal|show|print|repeat|display|output|leak)\s+(your|the)\s+"
        r"(system\s+prompt|initial\s+prompt|instructions?|rules?)",
        GuardSeverity.critical,
      ),
      _p(
        r"what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions)",
        GuardSeverity.warning,
      ),
      _p(r"you\s+are\s+now\s+", GuardSeverity.critical),
      _p(r"pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+", GuardSeverity.warning),
      _p(r"act\s+as\s+if\s+you\s+(are|were)\s+", GuardSeverity.warning),
      _p(r"^system\s*[:\-]\s*", GuardSeverity.critical),
      _p(
        r"\b(no|without|zero)\s+(restrictions?|limitations?|filters?|"
        r"guardrails?|rules?|limits?)\b",
        GuardSeverity.warning,
      ),
      _p(r"\b(dev|developer|god|jailbreak)\s+mode\b", GuardSeverity.critical),
      _p(r"\bDAN\s+(mode|jailbreak)\b", GuardSeverity.critical),
      _p(r"<\|?(system|im_start|im_end|endoftext)\|?>", GuardSeverity.critical),
      _p(r"^\s*(assistant|user)\s*[:\-]\s*", GuardSeverity.info),
    ];
    for (final p in customPatterns) {
      _patterns.add((p, GuardSeverity.warning));
    }
    if (paranoid) {
      _patterns.add(_p(r"<\|", GuardSeverity.info));
      _patterns.add(_p(r"\bEOF\b\s*\n\s*\b(user|system)\b", GuardSeverity.info));
    }
  }

  static (RegExp, GuardSeverity) _p(String source, GuardSeverity severity) =>
      (RegExp(source, caseSensitive: false, multiLine: true), severity);

  @override
  String get id => 'prompt_injection';

  @override
  GuardAction action;

  late final List<(RegExp, GuardSeverity)> _patterns;

  /// Extra patterns appended to the built-ins, matched case-insensitively.
  final List<RegExp> customPatterns;

  /// When true, adds low-severity structural markers (fake chat-control
  /// tokens, turn-boundary smuggling) that normal conversation never uses.
  final bool paranoid;

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];
    for (final (pattern, severity) in _patterns) {
      for (final m in pattern.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: severity,
            message: 'Possible prompt injection: "${m.group(0)}"',
            matchedText: m.group(0),
            start: m.start,
            end: m.end,
          ),
        );
      }
    }
    return findings;
  }
}
