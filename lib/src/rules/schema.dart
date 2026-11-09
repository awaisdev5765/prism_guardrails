import 'dart:convert';

import '../finding.dart';
import '../rule.dart';

/// A field specification for [SchemaRule].
class SchemaField {
  /// Creates a field spec.
  const SchemaField({
    required this.name,
    required this.type,
    this.required = true,
    this.allowedValues = const [],
    this.min,
    this.max,
    this.maxLength,
  });

  /// Key name in the JSON object.
  final String name;

  /// Expected value type.
  final SchemaType type;

  /// Whether the field must be present.
  final bool required;

  /// When non-empty, the value must be one of these.
  final List<Object> allowedValues;

  /// Minimum numeric value.
  final num? min;

  /// Maximum numeric value.
  final num? max;

  /// Maximum string length.
  final int? maxLength;
}

/// Expected JSON value types for [SchemaField].
enum SchemaType { string, number, integer, boolean, list, object }

/// Validates that a model's output is the JSON you asked for — before your
/// code trusts it.
///
/// Models drift: they omit fields, return strings where you expected numbers,
/// or invent enum values. [SchemaRule] turns that into findings instead of
/// runtime crashes two screens later.
///
/// ```dart
/// final rule = SchemaRule(
///   fields: [
///     SchemaField(name: 'sentiment', type: SchemaType.string,
///         allowedValues: ['positive', 'negative', 'neutral']),
///     SchemaField(name: 'confidence', type: SchemaType.number,
///         min: 0, max: 1),
///   ],
/// );
/// final findings = rule.inspectJson(modelReplyText);
/// ```
class SchemaRule extends GuardRule {
  /// Creates a schema validator for a top-level JSON object.
  SchemaRule({
    this.fields = const [],
    this.action = GuardAction.flag,
    this.allowExtraKeys = true,
  });

  @override
  GuardAction action;

  /// The fields to validate.
  final List<SchemaField> fields;

  /// Whether keys outside [fields] are acceptable.
  final bool allowExtraKeys;

  @override
  String get id => 'schema';

  /// Convenience: inspect a raw model reply, extracting the first JSON object
  /// it contains. Returns an empty list when no JSON object is present (use
  /// [requireJson] for strict behaviour).
  List<GuardFinding> inspectJson(String text) {
    final parsed = _extract(text);
    if (parsed == null) {
      return [
        GuardFinding(
          ruleId: id,
          severity: GuardSeverity.warning,
          message: 'No JSON object found in output',
        ),
      ];
    }
    return inspectMap(parsed);
  }

  /// Strict variant: flags any reply without a JSON object.
  List<GuardFinding> requireJson(String text) {
    final parsed = _extract(text);
    if (parsed == null) {
      return [
        GuardFinding(
          ruleId: id,
          severity: GuardSeverity.critical,
          message: 'Expected a JSON object but none was found',
        ),
      ];
    }
    return inspectMap(parsed);
  }

  /// Validates an already-parsed map.
  List<GuardFinding> inspectMap(Map<String, Object?> map) {
    final findings = <GuardFinding>[];
    for (final field in fields) {
      if (!map.containsKey(field.name)) {
        if (field.required) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.critical,
              message: 'Missing required field: ${field.name}',
            ),
          );
        }
        continue;
      }
      final value = map[field.name];
      if (!_typeOk(value, field.type)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message:
                'Field ${field.name} should be ${field.type.name} '
                '(got ${value.runtimeType})',
          ),
        );
        continue;
      }
      if (field.allowedValues.isNotEmpty &&
          !field.allowedValues.contains(value)) {
        findings.add(
          GuardFinding(
            ruleId: id,
            severity: GuardSeverity.critical,
            message:
                'Field ${field.name} must be one of '
                '${field.allowedValues.join(', ')}',
          ),
        );
      }
      if (value is num) {
        if (field.min != null && value < field.min!) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.critical,
              message: 'Field ${field.name} below minimum ${field.min}',
            ),
          );
        }
        if (field.max != null && value > field.max!) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.critical,
              message: 'Field ${field.name} above maximum ${field.max}',
            ),
          );
        }
      }
      if (value is String && field.maxLength != null) {
        if (value.length > field.maxLength!) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.warning,
              message: 'Field ${field.name} longer than '
                  '${field.maxLength} characters',
            ),
          );
        }
      }
    }
    if (!allowExtraKeys) {
      final known = fields.map((f) => f.name).toSet();
      for (final key in map.keys) {
        if (!known.contains(key)) {
          findings.add(
            GuardFinding(
              ruleId: id,
              severity: GuardSeverity.warning,
              message: 'Unexpected field: $key',
            ),
          );
        }
      }
    }
    return findings;
  }

  @override
  List<GuardFinding> inspect(String text) => inspectJson(text);

  bool _typeOk(Object? value, SchemaType type) => switch (type) {
        SchemaType.string => value is String,
        SchemaType.number => value is num,
        SchemaType.integer => value is int,
        SchemaType.boolean => value is bool,
        SchemaType.list => value is List,
        SchemaType.object => value is Map,
      };

  static Map<String, Object?>? _extract(String text) {
    // Prefer a fenced ```json block, then any {...} span that parses.
    final fenced = RegExp(
      r'```(?:json)?\s*(\{[\s\S]*?\})\s*```',
      multiLine: true,
    ).firstMatch(text);
    final candidates = <String>[
      if (fenced != null) fenced.group(1)!,
    ];
    final start = text.indexOf('{');
    final end = text.lastIndexOf('}');
    if (start >= 0 && end > start) {
      candidates.add(text.substring(start, end + 1));
    }
    for (final c in candidates) {
      try {
        final decoded = jsonDecode(c);
        if (decoded is Map<String, Object?>) return decoded;
      } on FormatException {
        // try next candidate
      }
    }
    return null;
  }
}
