import '../finding.dart';
import '../rule.dart';

/// Strips the invisible characters used to smuggle instructions past both
/// humans and downstream filters.
///
/// Attackers hide payloads inside:
/// - zero-width joiners, spaces and bidi control characters
/// - Unicode direction overrides that visually reorder text
/// - tag characters (U+E0000 block) that render as nothing
/// - homoglyph lookalikes that survive naive keyword filters
///
/// The rule always reports at `warning`; with the default `redact` action the
/// dangerous characters are stripped from [clean] so downstream rules and the
/// model itself see the same string a human thinks they typed.
class UnicodeSafetyRule extends GuardRule {
  /// Creates a Unicode sanitiser.
  UnicodeSafetyRule({this.action = GuardAction.redact, this.normaliseHomoglyphs = true});

  @override
  GuardAction action;

  /// Whether Cyrillic/Greek lookalikes in Latin-only words are flagged.
  final bool normaliseHomoglyphs;

  /// The invisible and bidi-control characters this rule removes.
    static final _invisible = RegExp(
    '[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]'
    '|\uDB40[\uDC00-\uDC7F]',
  );

  /// Latin letters that are actually Cyrillic or Greek lookalikes.
  static final _homoglyph = RegExp('[\u{0400}-\u{04FF}\u{0370}-\u{03FF}]');

  @override
  String get id => 'unicode_safety';

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];
    final invisible = _invisible.allMatches(text);
    if (invisible.isNotEmpty) {
      findings.add(
        GuardFinding(
          ruleId: id,
          severity: GuardSeverity.warning,
          message: '${invisible.length} invisible control character(s) '
              'removed — often used to smuggle instructions',
          start: invisible.first.start,
          end: invisible.last.end,
        ),
      );
    }
    if (normaliseHomoglyphs && _homoglyph.hasMatch(text)) {
      findings.add(
        GuardFinding(
          ruleId: id,
          severity: GuardSeverity.info,
          message: 'Text mixes non-Latin lookalike characters (possible '
              'homoglyph filter evasion)',
        ),
      );
    }
    return findings;
  }

  @override
  String? clean(String text) {
    final out = text.replaceAll(_invisible, '');
    return out == text ? null : out;
  }
}
