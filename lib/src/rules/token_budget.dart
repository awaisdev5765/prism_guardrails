import '../finding.dart';
import '../rule.dart';

/// Estimates request size and enforces a rolling spend budget.
///
/// Uses the de-facto standard ~4-characters-per-token approximation. Good
/// enough for budget guardrails (it errs neither side by more than ~15% on
/// typical prose); pass [tokensPerChar] to calibrate for your model.
///
/// [TokenBudgetRule] is stateful — call [spend] after each successful request
/// so the rolling window tracks real usage.
class TokenBudgetRule extends GuardRule {
  /// Creates a budget rule.
  TokenBudgetRule({
    this.action = GuardAction.block,
    this.maxTokensPerRequest,
    this.maxTokensPerWindow,
    this.window = const Duration(hours: 1),
    this.tokensPerChar = 0.25,
  });

  @override
  GuardAction action;

  /// Reject any single request estimated above this many tokens.
  final int? maxTokensPerRequest;

  /// Reject requests once the rolling window exceeds this many tokens.
  final int? maxTokensPerWindow;

  /// Length of the rolling spend window.
  final Duration window;

  /// Estimated tokens per character (default: 1 token per 4 characters).
  final double tokensPerChar;

  final List<(DateTime, int)> _spend = [];

  /// Estimated token count for [text].
  int estimateTokens(String text) =>
      (text.length * tokensPerChar).ceil();

  /// Records [tokens] of actual usage at [when] (defaults to now).
  void spend(int tokens, {DateTime? when}) {
    _spend.add((when ?? DateTime.now(), tokens));
  }

  /// Tokens spent inside the rolling window as of [now].
  int spentInWindow({DateTime? now}) {
    final t = now ?? DateTime.now();
    _spend.retainWhere((e) => t.difference(e.$1) <= window);
    return _spend.fold(0, (sum, e) => sum + e.$2);
  }

  /// Clears all recorded spend.
  void reset() => _spend.clear();

  @override
  String get id => 'token_budget';

  @override
  List<GuardFinding> inspect(String text) {
    final findings = <GuardFinding>[];
    final tokens = estimateTokens(text);
    if (maxTokensPerRequest != null && tokens > maxTokensPerRequest!) {
      findings.add(
        GuardFinding(
          ruleId: id,
          severity: GuardSeverity.critical,
          message: 'Request is ~$tokens tokens, above the '
              '$maxTokensPerRequest limit',
        ),
      );
    }
    if (maxTokensPerWindow != null) {
      final spent = spentInWindow();
      if (spent + tokens > maxTokensPerWindow!) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message: 'Budget exceeded: $spent spent, ~$tokens more needed, '
                'limit $maxTokensPerWindow per $window',
          ),
        );
      }
    }
    return findings;
  }
}
