/// DG12 typed-field extraction: [Dg12Fields.from] lifts the ported
/// [DataGroup12] into ICAO-vocabulary fields, with the other-persons records
/// split into name parts and the two document images sniffed for format.
///
/// A Dart-only addition on the same contract as `Dg1Fields`: immutable,
/// **total; [Dg12Fields.from] never throws**, every field nullable, dates
/// opaque, and no getters added to the ported class.
///
/// References: ICAO 9303 P10 §4.7.12 Tables 73-74.
library;

import 'dart:typed_data';

import 'data_group12.dart';
import 'data_group2.dart' show FaceImageFormat, sniffImageFormat;
import 'dg11_fields.dart' show MrzNameParts;
import 'mrz_text.dart';

/// Typed DG12 fields: an immutable value built by [Dg12Fields.from].
///
/// **Trust framing, as for `Dg1Fields`: this layer is explicitly untrusted**,
/// display/DX convenience, never an input to a trust decision. A verifying
/// backend re-parses the hash-verified raw DG12 regardless.
class Dg12Fields {
  const Dg12Fields._({
    required this.issuingAuthority,
    required this.dateOfIssue,
    required this.otherPersons,
    required this.endorsementsOrObservations,
    required this.taxOrExitRequirements,
    required this.frontImage,
    required this.frontImageFormat,
    required this.rearImage,
    required this.rearImageFormat,
    required this.personalizationTime,
    required this.personalizationDeviceSerialNumber,
  });

  /// Builds the typed fields from a parsed [DataGroup12]. **Total, it never
  /// throws**: worst case is a value whose fields are all null/empty.
  factory Dg12Fields.from(DataGroup12 dg12) {
    final frontImage = dg12.frontImage;
    final rearImage = dg12.rearImage;
    return Dg12Fields._(
      issuingAuthority: dg12.issuingAuthority,
      dateOfIssue: dg12.dateOfIssue,
      otherPersons: [
        for (final other in dg12.otherPersons) splitMrzName(other),
      ],
      endorsementsOrObservations: dg12.endorsementsOrObservations,
      taxOrExitRequirements: dg12.taxOrExitRequirements,
      frontImage: frontImage,
      frontImageFormat: frontImage == null
          ? null
          : sniffImageFormat(frontImage),
      rearImage: rearImage,
      rearImageFormat: rearImage == null ? null : sniffImageFormat(rearImage),
      personalizationTime: dg12.personalizationTime,
      personalizationDeviceSerialNumber: dg12.personalizationDeviceSerialNr,
    );
  }

  /// `5F19`, verbatim.
  final String? issuingAuthority;

  /// `5F26`, opaque: 8 digits, the BCD expansion of a 4-byte value, or
  /// whatever else the file carried, including P10's partial-date
  /// `00`/`0000` conventions, untouched.
  final String? dateOfIssue;

  /// The `A0`/`5F1A` other persons, each split by the MRZ name rules, in
  /// file order; empty when the group is absent (a Dart-only surface;
  /// upstream's `otherPersonsDetails` is dead API and is not ported).
  final List<MrzNameParts> otherPersons;

  /// `5F1B`, verbatim.
  final String? endorsementsOrObservations;

  /// `5F1C`, verbatim.
  final String? taxOrExitRequirements;

  /// `5F1D` image bytes, verbatim.
  final Uint8List? frontImage;

  /// The header-sniffed format of [frontImage]; `null` when the image is
  /// absent **or** its prefix matches none of the three known formats (the
  /// sniff never throws).
  final FaceImageFormat? frontImageFormat;

  /// `5F1E` image bytes, verbatim.
  final Uint8List? rearImage;

  /// The header-sniffed format of [rearImage]; `null` on absence or no match.
  final FaceImageFormat? rearImageFormat;

  /// `5F55`, opaque 14-char date-time, verbatim (the parser is UTF-8-only
  /// here, as upstream, so a BCD-encoded value arrives as garbage or null).
  final String? personalizationTime;

  /// `5F56`: the ICAO-full spelling of the ported class's
  /// `personalizationDeviceSerialNr` (the one rename from upstream).
  final String? personalizationDeviceSerialNumber;
}
