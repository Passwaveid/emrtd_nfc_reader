// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup.swift @ 3bf5456 (2.3.2)

/// `DataGroup` base class: the LDS TLV walk every DG parser shares.
///
/// As upstream, [body] takes everything after the length field, ignoring the
/// declared length. Unlike upstream, an unknown [hash] name throws instead of
/// returning empty; a truncated walk throws typed errors where upstream
/// index-crashes; and the two-byte-tag test is BER's low-five-bits rule, not
/// upstream's low-nibble rule, so one tag-classification rule holds
/// package-wide, the same as `TlvRecord`'s.
library;

import 'dart:typed_data';

import '../crypto/hashes.dart';
import '../errors.dart';
import '../utils.dart';
import 'data_group_id.dart';
import 'tlv.dart';

/// Upstream `DataGroup`.
class DataGroup {
  /// Upstream `init(_ data:)`: header-byte skip + length parse + [parse].
  ///
  /// An empty or 1-byte blob feeds [asn1Length] an empty slice and throws
  /// [CannotDecodeASN1Length] (upstream: slice-construction crash).
  DataGroup(List<int> data) {
    this.data = Uint8List.fromList(data);
    // Skip the first byte which is the header byte (upstream comment).
    pos = 1;
    getNextLength();
    // As upstream, body is everything after the length field, even when the
    // declared length disagrees (short or long).
    body = this.data.sublist(pos);
    parse(data);
  }

  /// Upstream `datagroupType`: `.Unknown` in the base.
  DataGroupId get datagroupType => DataGroupId.Unknown;

  /// Body contains the actual data (upstream comment).
  late final Uint8List body;

  /// Data contains the whole DataGroup data (as that is what the hash is
  /// calculated from (upstream comment).
  late final Uint8List data;

  /// Walk position into [data].
  int pos = 0;

  /// Overridden per DG; the base implementation is empty.
  void parse(List<int> data) {}

  /// Upstream `getNextTag()`.
  ///
  /// The two-byte-tag test is `& 0x1F == 0x1F` (BER low five bits), fixing
  /// upstream's `& 0x0F == 0x0F` low-nibble test; split conformance cases pin
  /// the `6F 1F` divergence. A two-byte tag starting at the last byte throws
  /// [TagNotValid] (the same error as the existing has-data guard) where
  /// upstream crashes on the slice.
  int getNextTag() {
    var tag = 0;

    // Fix for some passports that may have invalid data - ensure that we
    // do have data! (upstream comment)
    if (data.length <= pos) {
      throw const TagNotValid();
    }

    if (binToHex(data[pos]) & 0x1F == 0x1F) {
      if (pos + 2 > data.length) {
        throw const TagNotValid(); // upstream: slice crash
      }
      tag = binToHexBytes(data.sublist(pos, pos + 2));
      pos += 2;
    } else {
      tag = data[pos];
      pos += 1;
    }
    return tag;
  }

  /// Upstream `getNextLength()`: via [asn1Length].
  int getNextLength() {
    final end = pos + 4 < data.length ? pos + 4 : data.length;
    // A past-the-end pos yields an empty slice (upstream: slice crash),
    // which asn1Length rejects with CannotDecodeASN1Length.
    final start = pos < end ? pos : end;
    final (len, lenOffset) = asn1Length(data.sublist(start, end));
    pos += lenOffset;
    return len;
  }

  /// Upstream `getNextValue()`.
  ///
  /// A declared length past the end of [data] throws [InvalidASN1Value]
  /// (upstream: slice crash).
  Uint8List getNextValue() {
    final length = getNextLength();
    if (pos + length > data.length) {
      throw const InvalidASN1Value(); // upstream: slice crash
    }
    final value = data.sublist(pos, pos + length);
    pos += length;
    return value;
  }

  /// Upstream `hash(_ hashAlgorythm:)`: hash of [data] (the whole file).
  ///
  /// The five accepted names are exactly
  /// `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512` (case-sensitive, no dashes);
  /// anything else throws [InvalidHashAlgorithmSpecified], fixing upstream,
  /// which silently returns `[]`. Split conformance cases pin both.
  /// The parameter spelling is upstream's.
  Uint8List hash(String hashAlgorythm) {
    if (hashAlgorythm == 'SHA1') {
      return calcSHA1Hash(data);
    } else if (hashAlgorythm == 'SHA224') {
      return calcSHA224Hash(data);
    } else if (hashAlgorythm == 'SHA256') {
      return calcSHA256Hash(data);
    } else if (hashAlgorythm == 'SHA384') {
      return calcSHA384Hash(data);
    } else if (hashAlgorythm == 'SHA512') {
      return calcSHA512Hash(data);
    }
    throw const InvalidHashAlgorithmSpecified(); // upstream returns []
  }

  /// Upstream `verifyTag(_:equals:)`.
  void verifyTag(int tag, {required int equals}) {
    if (tag != equals) {
      throw InvalidResponse(datagroupType, equals, tag);
    }
  }

  /// Upstream `verifyTag(_:oneOf:)` (the Swift overload pair splits into
  /// two Dart names).
  void verifyTagOneOf(int tag, {required List<int> oneOf}) {
    if (!oneOf.contains(tag)) {
      throw InvalidResponse(datagroupType, oneOf.first, tag);
    }
  }
}
