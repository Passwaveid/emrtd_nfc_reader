/// DG11 typed-field extraction: [Dg11Fields.from] lifts the ported
/// [DataGroup11] into ICAO-vocabulary fields with the canonical processing a
/// consumer would otherwise redo: the MRZ name split, the P10 `<`-separated
/// component splits, and the other-names records as name parts.
///
/// A Dart-only addition on the same contract as `Dg1Fields`: immutable,
/// **total; [Dg11Fields.from] never throws**, every field nullable (`null` =
/// the source field was absent or undecodable), dates opaque, and no getters
/// added to the ported class (which stays upstream-shaped).
///
/// Because [DataGroup11] is already typed (unlike DG1's raw `elements` map),
/// this layer is thin; its value is the canonicalization, not the plumbing.
///
/// References: ICAO 9303 P10 §4.7.11 Tables 71-72; P3 §4.8-4.9 (name
/// formatting, filler `<`, partial dates completed with `00`/`0000`).
library;

import 'data_group11.dart';
import 'mrz_text.dart';

/// One name split into its ICAO parts. `secondaryIdentifier` is `''`, never
/// null, when the record carries no `<<` separator: the Brunei shape.
/// Records travel in the public API the way `PassportReadTrace.paceInfos`
/// does.
typedef MrzNameParts = ({String primaryIdentifier, String secondaryIdentifier});

/// Typed DG11 fields: an immutable value built by [Dg11Fields.from].
///
/// **Trust framing, as for `Dg1Fields`: this layer is explicitly untrusted**,
/// display/DX convenience, never an input to a trust decision. A verifying
/// backend re-parses the hash-verified raw DG11 regardless.
///
/// `5F16` (proof of citizenship) is deliberately **omitted**: P10 Table 71
/// declares it a compressed image, upstream string-decodes it, and the port
/// keeps that; surfacing a knowingly-garbage field here would be API
/// noise. It stays available as `DataGroup11.proofOfCitizenship`.
class Dg11Fields {
  const Dg11Fields._({
    required this.primaryIdentifier,
    required this.secondaryIdentifier,
    required this.otherNames,
    required this.personalNumber,
    required this.fullDateOfBirth,
    required this.placeOfBirth,
    required this.permanentAddress,
    required this.telephone,
    required this.profession,
    required this.title,
    required this.personalSummary,
    required this.otherTravelDocumentNumbers,
    required this.custodyInfo,
  });

  /// Builds the typed fields from a parsed [DataGroup11]. **Total, it never
  /// throws**: worst case is a value whose fields are all null/empty.
  factory Dg11Fields.from(DataGroup11 dg11) {
    final fullName = dg11.fullName;
    final name = fullName == null ? null : splitMrzName(fullName);
    return Dg11Fields._(
      primaryIdentifier: name?.primaryIdentifier,
      secondaryIdentifier: name?.secondaryIdentifier,
      otherNames: [for (final other in dg11.otherNames) splitMrzName(other)],
      personalNumber: dg11.personalNumber,
      fullDateOfBirth: dg11.dateOfBirth,
      placeOfBirth: dg11.placeOfBirth?.split('<'),
      permanentAddress: dg11.address?.split('<'),
      telephone: dg11.telephone,
      profession: dg11.profession,
      title: dg11.title,
      personalSummary: dg11.personalSummary,
      otherTravelDocumentNumbers: dg11.tdNumbers?.split('<'),
      custodyInfo: dg11.custodyInfo,
    );
  }

  /// Left part of the `5F0E` name split.
  final String? primaryIdentifier;

  /// Right part of the `5F0E` name split; `''` (not null) when the name
  /// carries no `<<` separator.
  final String? secondaryIdentifier;

  /// The `A0`/`5F0F` other names, same split applied, in file order; empty
  /// when the group is absent (a Dart-only surface).
  final List<MrzNameParts> otherNames;

  /// `5F10`, verbatim: P10 makes this free-form, so **no** filler strip.
  final String? personalNumber;

  /// `5F2B`, opaque: 8 digits, a BCD expansion, or whatever else the file
  /// carried. P10's partial-date conventions (unknown MM/DD as `00`, unknown
  /// CCYY as `0000`) pass through untouched.
  final String? fullDateOfBirth;

  /// `5F11` split on the P10-documented `<` separator: segments verbatim, no
  /// trimming, empty segments preserved (leading/embedded fillers are data,
  /// as in the MRZ filler rule).
  final List<String>? placeOfBirth;

  /// `5F42`, split on `<` like [placeOfBirth].
  final List<String>? permanentAddress;

  /// `5F12`, verbatim.
  final String? telephone;

  /// `5F13`, verbatim.
  final String? profession;

  /// `5F14`, verbatim.
  final String? title;

  /// `5F15`, verbatim.
  final String? personalSummary;

  /// `5F17`, split on `<` like [placeOfBirth].
  final List<String>? otherTravelDocumentNumbers;

  /// `5F18`, verbatim.
  final String? custodyInfo;
}
