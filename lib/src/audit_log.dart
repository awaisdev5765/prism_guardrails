import 'finding.dart';
import 'rule.dart';

/// One audited pipeline decision.
class AuditEntry {
  /// Creates an audit entry.
  const AuditEntry({
    required this.at,
    required this.stage,
    required this.summary,
    required this.findings,
    this.label,
  });

  /// When the decision happened.
  final DateTime at;

  /// `input` or `output` — which side of the model call was inspected.
  final String stage;

  /// The inspection summary, e.g. `blocked, 3 findings, 2 critical`.
  final String summary;

  /// The findings. Redacted rules never include matched secret/PII text, so
  /// this log is safe to persist by default.
  final List<GuardFinding> findings;

  /// Optional caller label, e.g. the conversation id.
  final String? label;
}

/// An append-only, in-memory trail of pipeline decisions.
///
/// Kept small by design: [capacity] bounds memory in long sessions, and
/// entries never contain raw matched text for critical rules — a log dump must
/// never become the breach.
class AuditLog {
  /// Creates an audit log keeping the most recent [capacity] entries.
  AuditLog({this.capacity = 200, this.enabled = true});

  /// Maximum retained entries; the oldest are dropped.
  final int capacity;

  /// Set false to make the pipeline skip logging entirely.
  bool enabled;

  final List<AuditEntry> _entries = [];

  /// The retained entries, oldest first.
  List<AuditEntry> get entries => List.unmodifiable(_entries);

  /// Records a decision.
  void add({
    required String stage,
    required GuardInspection inspection,
    String? label,
    DateTime? at,
  }) {
    if (!enabled) return;
    _entries.add(
      AuditEntry(
        at: at ?? DateTime.now(),
        stage: stage,
        summary: inspection.summary,
        findings: inspection.findings,
        label: label,
      ),
    );
    if (_entries.length > capacity) {
      _entries.removeAt(0);
    }
  }

  /// Entries whose inspection was blocked.
  Iterable<AuditEntry> get blocked =>
      _entries.where((e) => e.summary.startsWith('blocked'));

  /// Clears the log.
  void clear() => _entries.clear();
}
