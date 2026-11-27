import 'package:emrtd_core/emrtd_core.dart';

/// Which of the three entered fields a [MrzInputError] is about.
enum MrzField { documentNumber, dateOfBirth, dateOfExpiry }

/// Why a field was rejected.
enum MrzErrorReason {
  /// Nothing left after trimming.
  empty,

  /// A character outside the MRZ set `[0-9A-Z<]`.
  illegalCharacter,

  /// A date that is not exactly six characters.
  wrongLength,
}

class MrzInputError implements Exception {
  const MrzInputError(this.field, this.reason);

  final MrzField field;
  final MrzErrorReason reason;

  @override
  String toString() => 'MrzInputError($field, $reason)';
}

/// The three opaque MRZ strings `composeMrzKey` takes, validated only as far
/// as the package's own contract allows.
///
/// The package takes three strings and derives the access keys; it does not
/// read an MRZ and will not. This class is the whole of what an app must do
/// between a manual-entry form and `readPassport`.
class MrzInput {
  const MrzInput._(this.documentNumber, this.dateOfBirth, this.dateOfExpiry);

  final String documentNumber;

  /// `YYMMDD`, verbatim.
  final String dateOfBirth;

  /// `YYMMDD`, verbatim.
  final String dateOfExpiry;

  /// Trims and uppercases, then checks only what the MRZ character set and
  /// the field widths require. Returns the parsed input or throws
  /// [MrzInputError] naming the first field that failed, in the order
  /// document number -> date of birth -> date of expiry.
  static MrzInput parse({
    required String documentNumber,
    required String dateOfBirth,
    required String dateOfExpiry,
  }) {
    final doc = _canonical(documentNumber);
    if (doc.isEmpty) {
      throw const MrzInputError(MrzField.documentNumber, MrzErrorReason.empty);
    }
    if (!_isMrzText(doc)) {
      throw const MrzInputError(
        MrzField.documentNumber,
        MrzErrorReason.illegalCharacter,
      );
    }
    // No upper bound. A document number longer than nine characters is the
    // TD1 concatenated case, which `composeMrzKey` passes through unpadded
    // because ICAO 9303 Part 11 §9.7.3 wants the complete number.

    final dob = _canonical(dateOfBirth);
    _checkDate(dob, MrzField.dateOfBirth);
    final expiry = _canonical(dateOfExpiry);
    _checkDate(expiry, MrzField.dateOfExpiry);

    return MrzInput._(doc, dob, expiry);
  }

  /// The 24-character MRZ-info string `readPassport` takes.
  String get mrzKey => composeMrzKey(
    documentNumber: documentNumber,
    dateOfBirth: dateOfBirth,
    dateOfExpiry: dateOfExpiry,
  );

  static void _checkDate(String value, MrzField field) {
    if (value.length != 6) {
      throw MrzInputError(
        field,
        value.isEmpty ? MrzErrorReason.empty : MrzErrorReason.wrongLength,
      );
    }
    // Digits and `<` only. Part 3 §4.8 completes an unknown date wholly or
    // partly with `<` fillers, so `85<<<<` is a legal date and counts as zero
    // in the check digit; it must not be rejected as "not a date".
    for (final c in value.codeUnits) {
      final isDigit = c >= 0x30 && c <= 0x39;
      if (!isDigit && c != 0x3C) {
        throw MrzInputError(field, MrzErrorReason.illegalCharacter);
      }
    }
  }

  static String _canonical(String raw) => raw.trim().toUpperCase();

  static bool _isMrzText(String value) {
    for (final c in value.codeUnits) {
      final isDigit = c >= 0x30 && c <= 0x39;
      final isUpper = c >= 0x41 && c <= 0x5A;
      if (!isDigit && !isUpper && c != 0x3C) return false;
    }
    return true;
  }
}
