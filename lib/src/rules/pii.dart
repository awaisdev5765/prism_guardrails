import '../finding.dart';
import '../rule.dart';

/// Detects and masks personally identifiable information.
///
/// Supported detectors, each individually toggleable:
/// - email addresses
/// - phone numbers (international formats)
/// - credit card numbers (Luhn-validated)
/// - IPv4 addresses (with private-range awareness)
/// - national IDs / SSN-shaped numbers
/// - IBANs
///
/// The default behaviour is [GuardAction.redact]: findings are produced and
/// [clean] masks the matches so the redacted text can be sent to the model.
class PiiRedactionRule extends GuardRule {
  /// Creates a PII redactor.
  PiiRedactionRule({
    this.action = GuardAction.redact,
    this.mask = '█',
    this.detectEmail = true,
    this.detectPhone = true,
    this.detectCreditCard = true,
    this.detectIpAddress = true,
    this.detectNationalId = true,
    this.detectIban = true,
    this.customPatterns = const [],
  });

  @override
  GuardAction action;

  /// Character used to mask matched text in [clean].
  final String mask;

  /// Whether email addresses are detected.
  final bool detectEmail;

  /// Whether phone numbers are detected.
  final bool detectPhone;

  /// Whether credit-card-shaped numbers are detected (Luhn-validated).
  final bool detectCreditCard;

  /// Whether IPv4 addresses are detected.
  final bool detectIpAddress;

  /// Whether SSN/national-ID-shaped numbers are detected.
  final bool detectNationalId;

  /// Whether IBANs are detected.
  final bool detectIban;

  /// Additional patterns to redact, e.g. patient numbers.
  final List<RegExp> customPatterns;

  static final _email = RegExp(
    r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
  );
  static final _phone = RegExp(
    r'(\+?\d{1,3}[\s.-]?)?(\(?\d{2,4}\)?[\s.-]?)?\d{3}[\s.-]?\d{3,4}'
    r'(?!\d)',
  );
  static final _creditCard = RegExp(r'\b(?:\d[ -]?){13,19}\b');
  static final _ipv4 = RegExp(r'\b(?:\d{1,3}\.){3}\d{1,3}\b');
  static final _nationalId = RegExp(r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b');
  static final _iban = RegExp(r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b');

  @override
  String get id => 'pii_redaction';

  bool _luhnValid(String digits) {
    digits = digits.replaceAll(RegExp(r'[ -]'), '');
    if (digits.length < 13 || digits.length > 19) return false;
    var sum = 0;
    var double = false;
    for (var i = digits.length - 1; i >= 0; i--) {
      var d = int.parse(digits[i]);
      if (double) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      double = !double;
    }
    return sum % 10 == 0;
  }

  bool _isPublicIp(String ip) {
    final parts = ip.split('.').map(int.parse).toList();
    // Private, loopback and link-local ranges are usually harmless context —
    // flagging them adds noise without protecting anyone.
    if (parts[0] == 10 ||
        parts[0] == 127 ||
        (parts[0] == 192 && parts[1] == 168) ||
        (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] == 169 && parts[1] == 254)) {
      return false;
    }
    return true;
  }

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];

    void scan(RegExp pattern, String label, GuardSeverity severity) {
      for (final m in pattern.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: severity,
            message: label,
            start: m.start,
            end: m.end,
          ),
        );
      }
    }

    if (detectEmail) scan(_email, 'Email address', GuardSeverity.warning);
    if (detectPhone) scan(_phone, 'Phone number', GuardSeverity.info);
    if (detectNationalId) {
      scan(_nationalId, 'National ID / SSN', GuardSeverity.critical);
    }
    if (detectIban) scan(_iban, 'IBAN', GuardSeverity.critical);
    if (detectCreditCard) {
      for (final m in _creditCard.allMatches(text)) {
        if (_luhnValid(m.group(0)!)) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.critical,
              message: 'Credit card number',
              start: m.start,
              end: m.end,
            ),
          );
        }
      }
    }
    if (detectIpAddress) {
      for (final m in _ipv4.allMatches(text)) {
        final ip = m.group(0)!;
        if (ip.split('.').every((p) => int.parse(p) <= 255) &&
            _isPublicIp(ip)) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.warning,
              message: 'Public IP address',
              start: m.start,
              end: m.end,
            ),
          );
        }
      }
    }
    for (final p in customPatterns) {
      for (final m in p.allMatches(text)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.warning,
            message: 'Custom PII pattern',
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
    var out = text;
    void maskAll(RegExp pattern) {
      out = out.replaceAllMapped(pattern, (m) => mask * m.group(0)!.length);
    }

    if (detectEmail) maskAll(_email);
    if (detectNationalId) maskAll(_nationalId);
    if (detectIban) maskAll(_iban);
    if (detectCreditCard) {
      out = out.replaceAllMapped(_creditCard, (m) {
        return _luhnValid(m.group(0)!) ? mask * m.group(0)!.length : m.group(0)!;
      });
    }
    if (detectPhone) maskAll(_phone);
    if (detectIpAddress) {
      out = out.replaceAllMapped(_ipv4, (m) {
        final ip = m.group(0)!;
        final valid = ip.split('.').every((p) => int.parse(p) <= 255);
        return valid && _isPublicIp(ip) ? mask * ip.length : ip;
      });
    }
    for (final p in customPatterns) {
      out = out.replaceAllMapped(p, (m) => mask * m.group(0)!.length);
    }
    return out == text ? null : out;
  }
}
