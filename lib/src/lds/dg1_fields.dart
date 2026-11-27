/// DG1 typed-field extraction: [Dg1Fields.from] lifts the raw ICAO tag map
/// in [DataGroup1.elements] into typed, canonically stripped fields, so
/// consumers stop re-deriving the same tag plumbing.
///
/// A Dart-only addition, like `composeMrzKey`: upstream has no equivalent
/// shape, and its `NFCPassportModel` getters are the design input, with the
/// departures listed in UPSTREAM.md. The parser layer beneath is pinned and
/// untouched: this sits strictly on top of `elements` (conformance-locked).
///
/// Derived solely from the public ICAO 9303 spec and the upstream Swift
/// source; references: P3 §4.8-4.9, P4/P5/P6 §4.2.2 (note j), P7 (MRV),
/// P11 §9.7.3.
library;

import '../errors.dart';
import '../proto/bac.dart' show mrzCheckDigit;
import 'data_group1.dart';
import 'mrz_text.dart';

/// MRZ layout discriminated from `elements['5F1F']`: length 90 -> [td1],
/// 72 -> [td2], anything else -> [td3] (the TD3-shaped fixed-offset parse,
/// including nonstandard 89/91+ bodies, mirroring the parser's length-driven
/// dispatch), except when `5F03` starts with `V` at exactly 88 -> [mrvA] or
/// exactly 72 -> [mrvB] (ICAO 9303 P7; MRV-A/B collide with TD3/TD2 on
/// length alone; only the document code disambiguates).
enum Dg1Layout {
  /// 90-char three-line ID card (ICAO 9303 P5).
  td1,

  /// 72-char two-line document (ICAO 9303 P6).
  td2,

  /// The TD3-shaped fixed-offset layout (ICAO 9303 P4): any body length
  /// other than 90/72 without the MRV document-code tiebreak.
  td3,

  /// 88-char MRV-A visa (ICAO 9303 P7): `5F03` starts with `V`.
  mrvA,

  /// 72-char MRV-B visa (ICAO 9303 P7): `5F03` starts with `V`.
  mrvB,
}

/// Advisory check-digit flags: each compares the digit stored in its `5F1F`
/// slot against `mrzCheckDigit` recomputed over the layout's positional
/// slice, so the computation is single-sourced and layout-exact. A stored `<`
/// in a digit slot matches a computed 0 (the `<`/`0` equivalence real
/// documents use, on which dmrtd crashed).
///
/// `null` = not evaluable: the layout precludes the digit, `5F1F` is
/// absent, or the slice contains an out-of-MRZ-charset character. `false`
/// is expected on real documents (P3 §7.3.4.3
/// `id-Deviation-MRZ-WrongCheckDigit`; a Portuguese ID whose TD1 composite
/// digit is computed including fillers), which is exactly why these are
/// flags, not gates.
class Dg1CheckDigits {
  const Dg1CheckDigits({
    this.documentNumber,
    this.dateOfBirth,
    this.dateOfExpiry,
    this.optionalData,
    this.composite,
  });

  /// Document-number digit. Under ICAO note j this compares the transferred
  /// digit (the continuation's last char) against the digit of the complete
  /// document number.
  final bool? documentNumber;

  /// Date-of-birth digit.
  final bool? dateOfBirth;

  /// Date-of-expiry digit.
  final bool? dateOfExpiry;

  /// Optional-data digit: TD3 only (TD1/TD2 have none; MRVs have neither
  /// this nor [composite]).
  final bool? optionalData;

  /// Composite digit: TD1/TD2/TD3 only.
  final bool? composite;
}

/// Typed DG1 fields: an immutable value built by [Dg1Fields.from]; no
/// getters are added to [DataGroup1] itself (the ported class stays
/// upstream-shaped).
///
/// **Trust framing: this layer is explicitly untrusted**, display/DX
/// convenience, never an input to a trust decision. A verifying backend
/// re-parses the hash-verified raw DG1 regardless; [checkDigits] results are
/// advisory UX signals, not gates.
///
/// Vocabulary is ICAO 9303's, not upstream's:
/// [primaryIdentifier]/[secondaryIdentifier] (not lastName/firstName),
/// [documentCode] (not documentType), [issuingState], [sex] (not gender).
///
/// Nullability: every field is nullable; `null` means the source element is
/// absent (the parser drops a key whose bytes are invalid UTF-8) or the
/// layout precludes the field; `''` means present but empty after canonical
/// stripping. No upstream `"?"`/`"NOT FOUND"` sentinels.
///
/// Dates are opaque YYMMDD strings, verbatim: no stripping, no digit
/// validation, no parsing; P3 §4.8 completes unknown dates with `<` fillers,
/// which are legal and meaningful.
class Dg1Fields {
  const Dg1Fields._({
    required this.layout,
    required this.documentCode,
    required this.issuingState,
    required this.primaryIdentifier,
    required this.secondaryIdentifier,
    required this.documentNumber,
    required this.nationality,
    required this.dateOfBirth,
    required this.sex,
    required this.dateOfExpiry,
    required this.optionalData,
    required this.mrz,
    required this.checkDigits,
  });

  /// Builds the typed fields from a parsed [DataGroup1]. **Total, it never
  /// throws**: worst case is a value whose fields are all null.
  factory Dg1Fields.from(DataGroup1 dg1) {
    final elements = dg1.elements;
    final mrz = elements['5F1F'];

    // Layout from the 5F1F length, 5F03[0] == 'V' MRV tiebreak.
    Dg1Layout? layout;
    if (mrz != null) {
      final isVisaCode = elements['5F03']?.startsWith('V') ?? false;
      if (mrz.length == 90) {
        layout = Dg1Layout.td1;
      } else if (mrz.length == 72) {
        layout = isVisaCode ? Dg1Layout.mrvB : Dg1Layout.td2;
      } else if (mrz.length == 88 && isVisaCode) {
        layout = Dg1Layout.mrvA;
      } else {
        layout = Dg1Layout.td3;
      }
    }

    // Name split: strip trailing fillers, split at the FIRST `<<`; right
    // part is '' (not null) when 5B has no separator, the Brunei shape.
    // Within each part `<` -> space, then trim. The rule itself lives in
    // `mrz_text.dart` (shared with Dg11Fields/Dg12Fields).
    String? primaryIdentifier;
    String? secondaryIdentifier;
    final rawName = elements['5B'];
    if (rawName != null) {
      final parts = splitMrzName(rawName);
      primaryIdentifier = parts.primaryIdentifier;
      secondaryIdentifier = parts.secondaryIdentifier;
    }

    // Note-j guard: TD1/TD2 only, `<` in the check-digit slot, and the
    // raw 53 starting with a non-`<` run of length ≥ 2 (≤ 15 on TD1; it
    // must fit optional-data-I, the first half of the parser's concatenated
    // 53; ≤ its length on TD2). The run's last char is the transferred
    // check digit. Guard fails -> plain extraction.
    final raw53 = elements['53'];
    String? noteJContinuation;
    if ((layout == Dg1Layout.td1 || layout == Dg1Layout.td2) &&
        elements['5F04'] == '<' &&
        raw53 != null) {
      final run = leadingNonFillerRun(raw53);
      final maxRun = layout == Dg1Layout.td1 ? 15 : raw53.length;
      if (run.length >= 2 && run.length <= maxRun) {
        noteJContinuation = run;
      }
    }

    // Document number: the 9 chars of 5A + continuation minus its last
    // char under note j; trailing-stripped 5A otherwise.
    final raw5A = elements['5A'];
    String? documentNumber;
    if (raw5A != null) {
      documentNumber = noteJContinuation != null
          ? raw5A + noteJContinuation.substring(0, noteJContinuation.length - 1)
          : stripTrailingFillers(raw5A);
    }

    // Optional data. MRV layouts re-slice from 5F1F; the parser's
    // 53/5F02/5F07 slots are actually one contiguous optional-data field on
    // visas ([72,88) for mrvA, [64,72) for mrvB). Otherwise the 53 element,
    // minus the note-j continuation plus its one following filler separator
    // when the note-j guard passed. Trailing strip last; leading and
    // embedded fillers are data (the Norwegian TD1 shape).
    String? optionalData;
    if (layout == Dg1Layout.mrvA) {
      optionalData = stripTrailingFillers(mrz!.substring(72, 88));
    } else if (layout == Dg1Layout.mrvB) {
      optionalData = stripTrailingFillers(mrz!.substring(64, 72));
    } else if (raw53 != null) {
      var od = raw53;
      if (noteJContinuation != null) {
        var spliceEnd = noteJContinuation.length;
        if (spliceEnd < od.length && od[spliceEnd] == '<') {
          spliceEnd++; // the note-j separator filler
        }
        od = od.substring(spliceEnd);
      }
      optionalData = stripTrailingFillers(od);
    }

    return Dg1Fields._(
      layout: layout,
      documentCode: stripTrailingFillersOrNull(elements['5F03']),
      issuingState: stripTrailingFillersOrNull(elements['5F28']),
      primaryIdentifier: primaryIdentifier,
      secondaryIdentifier: secondaryIdentifier,
      documentNumber: documentNumber,
      nationality: stripTrailingFillersOrNull(elements['5F2C']),
      dateOfBirth: elements['5F57'],
      sex: elements['5F35'],
      dateOfExpiry: elements['59'],
      optionalData: optionalData,
      mrz: mrz,
      checkDigits: _computeCheckDigits(
        mrz: mrz,
        layout: layout,
        raw5A: raw5A,
        noteJContinuation: noteJContinuation,
      ),
    );
  }

  /// Layout discriminator; null when `5F1F` is absent: per-tag fields still
  /// extract, but every layout-dependent feature (MRV reinterpretation,
  /// note-j, all check-digit flags) degrades to null/off.
  final Dg1Layout? layout;

  /// `5F03`, trailing fillers stripped (`P<` -> `P`).
  final String? documentCode;

  /// `5F28`, trailing fillers stripped (`D<<` -> `D`).
  final String? issuingState;

  /// Left part of the `5B` name split.
  final String? primaryIdentifier;

  /// Right part of the `5B` name split; `''` (not null) when `5B` has no
  /// `<<` separator, the Brunei shape.
  final String? secondaryIdentifier;

  /// `5A`, trailing fillers stripped; under ICAO note j the complete
  /// number reassembled from the optional-data continuation.
  final String? documentNumber;

  /// `5F2C`, trailing fillers stripped.
  final String? nationality;

  /// `5F57`, verbatim 6 chars, fillers preserved.
  final String? dateOfBirth;

  /// `5F35`, verbatim single char (`M`/`F`/`<`).
  final String? sex;

  /// `59`, verbatim 6 chars.
  final String? dateOfExpiry;

  /// `53` after the note-j splice and trailing strip, or the contiguous visa
  /// optional-data re-slice of `5F1F` on MRV layouts. Leading fillers
  /// preserved.
  final String? optionalData;

  /// `5F1F`, verbatim.
  final String? mrz;

  /// Advisory check-digit flags: non-null; individual flags nullable.
  final Dg1CheckDigits checkDigits;
}

/// The check-digit slices. All indices are 0-based into the `5F1F` body;
/// every flag degrades to null when its slice runs out of range (a `5F1F`
/// string shorter than the layout's offsets; [Dg1Fields.from] is total).
Dg1CheckDigits _computeCheckDigits({
  required String? mrz,
  required Dg1Layout? layout,
  required String? raw5A,
  required String? noteJContinuation,
}) {
  if (mrz == null || layout == null) {
    return const Dg1CheckDigits();
  }

  // Stored-vs-recomputed over positional slices; stored `<` matches
  // computed 0; out-of-charset slice char -> null (mrzCheckDigit throws
  // InvalidDataPassed; caught).
  bool? sliceFlag(List<(int, int)> parts, int digitIndex) {
    if (digitIndex >= mrz.length) {
      return null;
    }
    final input = StringBuffer();
    for (final (start, end) in parts) {
      if (end > mrz.length) {
        return null;
      }
      input.write(mrz.substring(start, end));
    }
    final int computed;
    try {
      computed = mrzCheckDigit(input.toString());
    } on InvalidDataPassed {
      return null;
    }
    final stored = mrz[digitIndex];
    return stored == '$computed' || (stored == '<' && computed == 0);
  }

  // Note-j override: the transferred digit (continuation's last char, never
  // `<`) against the digit of the complete document number.
  bool? noteJDocumentNumberFlag() {
    if (raw5A == null) {
      return null;
    }
    final continuation = noteJContinuation!;
    final transferred = continuation[continuation.length - 1];
    final complete = raw5A + continuation.substring(0, continuation.length - 1);
    final int computed;
    try {
      computed = mrzCheckDigit(complete);
    } on InvalidDataPassed {
      return null;
    }
    return transferred == '$computed';
  }

  return switch (layout) {
    Dg1Layout.td3 => Dg1CheckDigits(
      documentNumber: sliceFlag([(44, 53)], 53),
      dateOfBirth: sliceFlag([(57, 63)], 63),
      dateOfExpiry: sliceFlag([(65, 71)], 71),
      optionalData: sliceFlag([(72, 86)], 86),
      composite: sliceFlag([(44, 54), (57, 64), (65, 87)], 87),
    ),
    Dg1Layout.td1 => Dg1CheckDigits(
      documentNumber: noteJContinuation != null
          ? noteJDocumentNumberFlag()
          : sliceFlag([(5, 14)], 14),
      dateOfBirth: sliceFlag([(30, 36)], 36),
      dateOfExpiry: sliceFlag([(38, 44)], 44),
      composite: sliceFlag([(5, 30), (30, 37), (38, 45), (48, 59)], 59),
    ),
    Dg1Layout.td2 => Dg1CheckDigits(
      documentNumber: noteJContinuation != null
          ? noteJDocumentNumberFlag()
          : sliceFlag([(36, 45)], 45),
      dateOfBirth: sliceFlag([(49, 55)], 55),
      dateOfExpiry: sliceFlag([(57, 63)], 63),
      composite: sliceFlag([(36, 46), (49, 56), (57, 71)], 71),
    ),
    // MRVs: per-field digits at the TD3/TD2 positions; no optional-data or
    // composite digit exists.
    Dg1Layout.mrvA => Dg1CheckDigits(
      documentNumber: sliceFlag([(44, 53)], 53),
      dateOfBirth: sliceFlag([(57, 63)], 63),
      dateOfExpiry: sliceFlag([(65, 71)], 71),
    ),
    Dg1Layout.mrvB => Dg1CheckDigits(
      documentNumber: sliceFlag([(36, 45)], 45),
      dateOfBirth: sliceFlag([(49, 55)], 55),
      dateOfExpiry: sliceFlag([(57, 63)], 63),
    ),
  };
}
