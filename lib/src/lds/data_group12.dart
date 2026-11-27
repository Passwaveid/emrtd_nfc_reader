// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup12.swift @ 3bf5456 (2.3.2)
//   `otherPersonsDetails` is dropped, not ported: upstream declares it and
//   never assigns it, dead public API the port does not carry.

/// DG12 (additional document details) parsing.
///
/// P10 §4.7.12 Table 73: `6C { 5C tag list, 5F19 issuing authority,
/// 5F26 date of issue, A0 { 02 count, 5F1A name of other person × count },
/// 5F1B endorsements/observations, 5F1C tax/exit requirements,
/// 5F1D front image, 5F1E rear image, 5F55 personalization date-time,
/// 5F56 personalization system serial }`.
///
/// Kept as upstream has them: the do-while body runs at least once, so a
/// template holding only the `5C` tag list throws [TagNotValid]; the tag
/// list is read and never cross-checked (upstream's own comment says
/// "ideally we would check this but..."); unknown tags are consumed and
/// silently dropped; a first tag other than `5C` throws `InvalidResponse`;
/// **any** 4-byte `5F26` value takes the BCD branch; `5F55` is UTF-8-only
/// despite carrying a date-*time* P10 recommends BCD support for; and
/// invalid UTF-8 leaves that field `null`.
///
/// Unlike upstream: the `A0` other-persons group is parsed into
/// [otherPersons] where upstream's branch is a literal `// Not yet handled`
/// no-op; the dead `otherPersonsDetails` field is not ported; and a
/// truncated file throws the base walk's typed errors.
library;

import 'dart:typed_data';

import 'data_group.dart';
import 'data_group_id.dart';
import 'dg_text.dart';

/// Upstream `DataGroup12`.
class DataGroup12 extends DataGroup {
  DataGroup12(super.data);

  /// `5F19`.
  String? issuingAuthority;

  /// `5F26`, date of issue. Opaque: 8 ASCII digits, or the BCD expansion of
  /// a 4-byte value, verbatim either way.
  String? dateOfIssue;

  /// `5F1B`.
  String? endorsementsOrObservations;

  /// `5F1C`.
  String? taxOrExitRequirements;

  /// `5F1D`: image **bytes**, not a string.
  Uint8List? frontImage;

  /// `5F1E`: image **bytes**, not a string.
  Uint8List? rearImage;

  /// `5F55`, personalization date-time. UTF-8-only, verbatim upstream: a
  /// BCD-encoded value decodes to garbage or `null`. Unlike DG11's `5F2B`,
  /// it gets no BCD branch.
  String? personalizationTime;

  /// `5F56`: upstream's abbreviated spelling is kept on the ported class
  /// (`Dg12Fields` is where the ICAO-full name lives).
  String? personalizationDeviceSerialNr;

  /// The `5F1A` records inside the `A0` content-specific group, in file
  /// order; empty when the group is absent, malformed, or holds no decodable
  /// record. **Dart-only addition**: upstream's `A0` arm is a no-op and its
  /// `otherPersonsDetails` field is never assigned.
  /// Multiple `A0` groups append.
  List<String> otherPersons = const [];

  @override
  DataGroupId get datagroupType => DataGroupId.DG12;

  @override
  void parse(List<int> data) {
    var tag = getNextTag();
    verifyTag(tag, equals: 0x5C);

    // Skip the taglist - ideally we would check this but... (upstream
    // comment).
    getNextValue();

    // `repeat { ... } while` upstream; the body runs at least once.
    do {
      tag = getNextTag();
      final val = getNextValue();

      if (tag == 0x5F19) {
        issuingAuthority = decodeUtf8OrNull(val);
      } else if (tag == 0x5F26) {
        dateOfIssue = decodeDateValue(val);
      } else if (tag == 0xA0) {
        // Upstream: "Not yet handled". Dart-only, and total; a malformed
        // interior leaves the list untouched.
        otherPersons = [...otherPersons, ...decodeContentGroup(val, 0x5F1A)];
      } else if (tag == 0x5F1B) {
        endorsementsOrObservations = decodeUtf8OrNull(val);
      } else if (tag == 0x5F1C) {
        taxOrExitRequirements = decodeUtf8OrNull(val);
      } else if (tag == 0x5F1D) {
        frontImage = val;
      } else if (tag == 0x5F1E) {
        rearImage = val;
      } else if (tag == 0x5F55) {
        // UTF-8 only, no BCD branch, upstream verbatim.
        personalizationTime = decodeUtf8OrNull(val);
      } else if (tag == 0x5F56) {
        personalizationDeviceSerialNr = decodeUtf8OrNull(val);
      }
      // As upstream, every other tag is consumed above and silently dropped.
    } while (pos < data.length);
  }
}
