// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup11.swift @ 3bf5456 (2.3.2)

/// DG11 (additional personal details) parsing.
///
/// P10 §4.7.11 Table 71: `6B { 5C tag list, 5F0E full name, A0 { 02 count,
/// 5F0F other name × count }, 5F10 personal number, 5F2B full date of birth,
/// 5F11 place of birth, 5F42 permanent address, 5F12 telephone,
/// 5F13 profession, 5F14 title, 5F15 personal summary, 5F16 proof of
/// citizenship, 5F17 other TD numbers, 5F18 custody information }`. The
/// template may carry non-Latin characters.
///
/// Kept as upstream has them: the do-while body runs at least once, so a
/// template holding only the `5C` tag list throws [TagNotValid] rather than
/// yielding all-nulls; the tag list is read and never cross-checked against
/// the elements actually present; unknown tags are consumed and silently
/// dropped; a first tag other than `5C` throws `InvalidResponse`, so the tag
/// list is de facto mandatory; `5F16` is a compressed image per P10 but is
/// string-decoded, so real payloads yield `null`; and invalid UTF-8 in any
/// element leaves that field `null` and the walk continues, as Swift's
/// failable `String(bytes:encoding:)` does.
///
/// Unlike upstream: the `A0` other-names group is parsed into [otherNames]
/// where upstream consumes and drops it; `5F2B` gets DG12's 4-byte-BCD
/// branch, a fix; and a truncated file throws the base walk's typed
/// errors.
library;

import 'data_group.dart';
import 'data_group_id.dart';
import 'dg_text.dart';

/// Upstream `DataGroup11`.
class DataGroup11 extends DataGroup {
  DataGroup11(super.data);

  /// `5F0E`.
  String? fullName;

  /// `5F10`: free-form per P10 (no filler stripping anywhere in the port).
  String? personalNumber;

  /// `5F2B`, full date of birth. Opaque: 8 ASCII digits, or the BCD
  /// expansion of a 4-byte value, verbatim either way.
  String? dateOfBirth;

  /// `5F11`: components separated by `<`, as P10 specifies.
  String? placeOfBirth;

  /// `5F42` permanent address: components separated by `<`, as P10
  /// specifies.
  String? address;

  /// `5F12`.
  String? telephone;

  /// `5F13`.
  String? profession;

  /// `5F14`.
  String? title;

  /// `5F15`.
  String? personalSummary;

  /// `5F16`: P10 Table 71 calls this a *compressed image* (ISO/IEC 10918);
  /// upstream string-decodes it and the port keeps that, so real payloads
  /// land here as `null` or mojibake.
  String? proofOfCitizenship;

  /// `5F17` other valid travel document numbers: separated by `<`, as P10
  /// specifies.
  String? tdNumbers;

  /// `5F18`.
  String? custodyInfo;

  /// The `5F0F` records inside the `A0` content-specific group, in file
  /// order; empty when the group is absent, malformed, or holds no decodable
  /// record. **Dart-only addition**: upstream consumes the whole `A0` value
  /// and drops it. Multiple `A0` groups append.
  List<String> otherNames = const [];

  @override
  DataGroupId get datagroupType => DataGroupId.DG11;

  @override
  void parse(List<int> data) {
    var tag = getNextTag();
    verifyTag(tag, equals: 0x5C);
    // As upstream, the tag list is read and never checked against what
    // follows.
    getNextValue();

    // `repeat { ... } while` upstream; the body runs at least once, so a
    // template with nothing after the tag list throws TagNotValid.
    do {
      tag = getNextTag();
      final value = getNextValue();
      final val = decodeUtf8OrNull(value);
      if (tag == 0x5F0E) {
        fullName = val;
      } else if (tag == 0x5F10) {
        personalNumber = val;
      } else if (tag == 0x5F11) {
        placeOfBirth = val;
      } else if (tag == 0x5F2B) {
        // The identical rule DG12 applies to 5F26; upstream has no BCD
        // branch here.
        dateOfBirth = decodeDateValue(value);
      } else if (tag == 0x5F42) {
        address = val;
      } else if (tag == 0x5F12) {
        telephone = val;
      } else if (tag == 0x5F13) {
        profession = val;
      } else if (tag == 0x5F14) {
        title = val;
      } else if (tag == 0x5F15) {
        personalSummary = val;
      } else if (tag == 0x5F16) {
        proofOfCitizenship = val;
      } else if (tag == 0x5F17) {
        tdNumbers = val;
      } else if (tag == 0x5F18) {
        custodyInfo = val;
      } else if (tag == 0xA0) {
        // Dart-only. Total by construction; a malformed interior
        // leaves the list untouched and the sibling walk unaffected.
        otherNames = [...otherNames, ...decodeContentGroup(value, 0x5F0F)];
      }
      // As upstream, every other tag is consumed above and silently dropped.
    } while (pos < data.length);
  }
}
