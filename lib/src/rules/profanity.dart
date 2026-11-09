import '../finding.dart';
import '../rule.dart';

/// Blocks or masks blocked words with real word boundaries.
///
/// Matching is whole-word and case-insensitive, so "class", "assess" and
/// "grass" never trip on "ass". Use [severity] to control how the pipeline
/// treats a hit and [mask] to configure [clean].
class ProfanityRule extends GuardRule {
  /// Creates a profanity filter. Pass an empty [words] to disable it.
  ProfanityRule({
    this.words = const [],
    this.severity = GuardSeverity.critical,
    this.action = GuardAction.block,
    this.mask = '*',
  });

  @override
  GuardAction action;

  /// Severity reported for a match.
  final GuardSeverity severity;

  /// Blocked words. Comparison is lower-cased; entries may contain spaces.
  final List<String> words;

  /// Character used to mask matches in [clean].
  final String mask;

  late final List<RegExp> _matchers = [
    for (final w in words)
      RegExp(
        r'\b' +
            w
                .split('')
                .map((c) => c == ' '
                    ? r'\s+'
                    : RegExp.escape(c.toLowerCase()))
                .join() +
            r'\b',
        caseSensitive: false,
      ),
  ];

  @override
  String get id => 'profanity';

  @override
  List<GuardFinding> inspect(String text) {
    if (words.isEmpty) return const [];
    final findings = <GuardFinding>[];
    for (final pattern in _matchers) {
      for (final m in pattern.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: severity,
            message: 'Blocked word',
            start: m.start,
            end: m.end,
          ),
        );
      }
    }
    return findings;
  }

  @override
  String? clean(String text) {
    if (words.isEmpty) return null;
    var out = text;
    for (final pattern in _matchers) {
      out = out.replaceAllMapped(
        pattern,
        (m) => mask * (m.group(0)?.length ?? 0),
      );
    }
    return out == text ? null : out;
  }
}
