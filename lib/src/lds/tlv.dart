// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Utils.swift @ 3bf5456 (2.3.2)
//         (asn1Length, toAsn1Length, wrapDO, unwrapDO, oidToBytes)
// Source: Sources/NFCPassportReader/OpenSSLUtils.swift @ 3bf5456 (2.3.2)
//         (asn1EncodeOID: pure ASN.1, pulled here to drop an OpenSSL
//          dependency from the crypto and PACE code)

/// ASN.1/TLV handling.
///
/// Two length codecs deliberately coexist and are never unified: the free
/// functions [asn1Length]/[toAsn1Length] mirror upstream's two-byte-capped
/// codec, and SM/DG parsing relies on its rejections, while [TlvRecord] is
/// the fuller BER codec replacing Apple's `TKBERTLVRecord` (used by PACE).
///
/// [TlvRecord]'s parse API is nullable, so call sites throw where
/// upstream's force-unwraps crash.
library;

import 'dart:typed_data';

import '../errors.dart';

/// Swift `asn1Length(_:)`. Decode one BER length: returns the decoded
/// length and how many bytes its encoding occupies. Trailing bytes beyond
/// the length encoding are ignored.
///
/// Upstream quirk kept: rejects `0x80` (indefinite) and `0x83`+ with
/// [CannotDecodeASN1Length], though BER allows `0x83`+. [TlvRecord] *does*
/// accept `0x81`-`0x84`; the split is intentional.
///
/// Input too short for its form (upstream: out-of-range crash) also throws
/// [CannotDecodeASN1Length].
(int length, int lengthBytes) asn1Length(List<int> data) {
  if (data.isEmpty) {
    throw const CannotDecodeASN1Length(); // upstream crashes
  }
  if (data[0] < 0x80) {
    return (data[0], 1);
  }
  if (data[0] == 0x81) {
    if (data.length < 2) {
      throw const CannotDecodeASN1Length(); // upstream crashes
    }
    return (data[1], 2);
  }
  if (data[0] == 0x82) {
    if (data.length < 3) {
      throw const CannotDecodeASN1Length(); // upstream crashes
    }
    return ((data[1] << 8) | data[2], 3);
  }
  throw const CannotDecodeASN1Length(); // 0x80 and 0x83+, as upstream
}

/// Swift `toAsn1Length(_:)`: encode a length in BER (two-byte cap).
///
/// Upstream quirk kept: values above `0xFFFF` throw [InvalidASN1Value].
///
/// Negative input (upstream emits garbage bytes via `%02x` of a negative)
/// throws [InvalidASN1Value].
Uint8List toAsn1Length(int length) {
  if (length < 0) {
    throw const InvalidASN1Value(); // upstream emits garbage
  }
  if (length < 0x80) {
    return Uint8List.fromList([length]);
  }
  if (length <= 0xFF) {
    return Uint8List.fromList([0x81, length]);
  }
  if (length <= 0xFFFF) {
    return Uint8List.fromList([0x82, length >> 8, length & 0xFF]);
  }
  throw const InvalidASN1Value(); // above 0xFFFF, as upstream
}

/// Swift `wrapDO(b:arr:)`: wrap [value] in a TLV data object with [tag].
Uint8List wrapDO(int tag, List<int> value) => TlvRecord(tag, value).data;

/// Swift `unwrapDO(tag:wrappedData:)`: unwrap a TLV data object, checking
/// the tag. Throws [InvalidASN1Value] on malformed data or tag mismatch.
Uint8List unwrapDO(int tag, List<int> wrappedData) {
  final rec = TlvRecord.parse(wrappedData);
  if (rec == null || rec.tag != tag) {
    throw const InvalidASN1Value();
  }
  return rec.value;
}

/// Upstream `OpenSSLUtils.asn1EncodeOID(oid:)`: DER-encode a dotted OID
/// string, tag `0x06` and length included.
///
/// Throws [ArgumentError] on a string that is not a valid OID (upstream
/// hands these to OpenSSL's `OBJ_txt2obj`; no in-scope caller passes one).
Uint8List asn1EncodeOid(String oid) {
  final parts = oid.split('.');
  if (parts.length < 2) {
    throw ArgumentError.value(oid, 'oid', 'an OID has at least two arcs');
  }
  final arcs = parts.map((p) {
    final v = int.tryParse(p);
    if (v == null || v < 0) {
      throw ArgumentError.value(oid, 'oid', 'invalid arc "$p"');
    }
    return v;
  }).toList();
  if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40)) {
    throw ArgumentError.value(
      oid,
      'oid',
      'first arc must be 0..2, second < 40 unless first is 2',
    );
  }
  final body = <int>[];
  _writeBase128(body, 40 * arcs[0] + arcs[1]);
  for (final arc in arcs.skip(2)) {
    _writeBase128(body, arc);
  }
  return Uint8List.fromList([0x06, ..._encodeBerLength(body.length), ...body]);
}

/// Swift `oidToBytes(oid:replaceTag:)`: [asn1EncodeOid], optionally
/// replacing the leading `0x06` tag with `0x80` (PACE MSE:AT reference DO).
Uint8List oidToBytes(String oid, {required bool replaceTag}) {
  final encOid = asn1EncodeOid(oid);
  if (replaceTag) {
    encOid[0] = 0x80;
  }
  return encOid;
}

/// DER OID bytes (tag `0x06`, length, body) back to the dotted string.
///
/// No upstream analogue: `CardAccess` and the other `TlvRecord` walks need
/// it where upstream reads OpenSSL's dump text; pinned dart-only via encoder
/// round-trip vectors. Throws [InvalidASN1Value] on malformed input.
String asn1DecodeOid(List<int> encoded) {
  if (encoded.isEmpty || encoded[0] != 0x06) {
    throw const InvalidASN1Value();
  }
  final int bodyLen;
  final int lengthBytes;
  try {
    (bodyLen, lengthBytes) = asn1Length(encoded.sublist(1));
  } on CannotDecodeASN1Length {
    throw const InvalidASN1Value();
  }
  final bodyStart = 1 + lengthBytes;
  if (bodyLen == 0 || bodyStart + bodyLen != encoded.length) {
    throw const InvalidASN1Value();
  }
  final arcs = <int>[];
  var v = 0;
  var inArc = false;
  for (var i = bodyStart; i < bodyStart + bodyLen; i++) {
    final b = encoded[i];
    v = (v << 7) | (b & 0x7F);
    inArc = (b & 0x80) != 0;
    if (!inArc) {
      arcs.add(v);
      v = 0;
    }
  }
  if (inArc) {
    throw const InvalidASN1Value(); // unterminated base-128 arc
  }
  final first = arcs[0];
  final (a, b) = switch (first) {
    < 40 => (0, first),
    < 80 => (1, first - 40),
    _ => (2, first - 80),
  };
  return [a, b, ...arcs.skip(1)].join('.');
}

void _writeBase128(List<int> out, int v) {
  var rest = v;
  final tmp = <int>[rest & 0x7F];
  rest >>= 7;
  while (rest > 0) {
    tmp.add(0x80 | (rest & 0x7F));
    rest >>= 7;
  }
  out.addAll(tmp.reversed);
}

/// Minimal definite-form BER length (general: used by [TlvRecord] and the
/// OID encoder; unlike [toAsn1Length] it has no two-byte cap).
List<int> _encodeBerLength(int length) {
  if (length < 0x80) {
    return [length];
  }
  final bytes = <int>[];
  var rest = length;
  while (rest > 0) {
    bytes.insert(0, rest & 0xFF);
    rest >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/// Minimal BER-TLV record replacing Apple's `TKBERTLVRecord`, covering
/// exactly upstream's usage.
///
/// [tag] holds the raw tag bytes' big-endian value (`0x7F49` stays
/// `0x7F49`), matching the `TKTLVTag` convention. Parsing follows the BER
/// tag rule (first byte `& 0x1F == 0x1F` => continuation bytes while the
/// high bit is set) and accepts length forms `0x81`-`0x84`, rejecting
/// `0x85`+ and indefinite form (`0x80`); the `0x84`/`0x85`/indefinite
/// edges are assumptions about Apple's closed-source behavior, dart-only
/// until a rented-Mac session pins them.
///
/// Parsing is nil-on-malformed for parity with `TKBERTLVRecord`; ported
/// call sites turn `null` into [InvalidASN1Value].
class TlvRecord {
  /// Construct from tag and raw value bytes.
  TlvRecord(this.tag, List<int> value) : value = Uint8List.fromList(value);

  /// Construct from tag and child records; the value is the concatenated
  /// encoding of [records] (`TKBERTLVRecord(tag:records:)`).
  TlvRecord.fromRecords(this.tag, List<TlvRecord> records)
    : value = Uint8List.fromList([for (final r in records) ...r.data]);

  /// Raw tag bytes as a big-endian int.
  final int tag;

  /// Raw value bytes.
  final Uint8List value;

  /// Full TLV encoding: tag bytes, minimal definite-form length, value.
  Uint8List get data => Uint8List.fromList([
    ..._tagBytes(tag),
    ..._encodeBerLength(value.length),
    ...value,
  ]);

  /// Parse one record from the start of [data] (`TKBERTLVRecord(from:)`).
  /// Returns `null` on malformed input; trailing bytes are ignored.
  static TlvRecord? parse(List<int> data) => _parseAt(data, 0)?.record;

  /// Parse records back-to-back until [data] is exhausted
  /// (`TKBERTLVRecord.sequenceOfRecords(from:)`). Returns `null` if any
  /// record is malformed; empty input yields an empty list.
  static List<TlvRecord>? sequenceOfRecords(List<int> data) {
    final records = <TlvRecord>[];
    var offset = 0;
    while (offset < data.length) {
      final parsed = _parseAt(data, offset);
      if (parsed == null) {
        return null;
      }
      records.add(parsed.record);
      offset = parsed.end;
    }
    return records;
  }

  static ({TlvRecord record, int end})? _parseAt(List<int> data, int start) {
    var idx = start;
    if (idx >= data.length) {
      return null;
    }
    // Tag: BER rule; low five bits all set => multi-byte, continuation
    // bytes while the high bit is set (one tag-classification rule
    // package-wide, the same as `DataGroup.getNextTag`'s).
    final b0 = data[idx++];
    var tag = b0;
    if ((b0 & 0x1F) == 0x1F) {
      while (true) {
        if (idx >= data.length || idx - start > 8) {
          return null; // truncated or absurdly long tag
        }
        final b = data[idx++];
        tag = (tag << 8) | b;
        if ((b & 0x80) == 0) {
          break;
        }
      }
    }
    // Length: short form, or 0x81-0x84; indefinite (0x80) and 0x85+
    // rejected (assumed to match Apple's closed-source parser).
    if (idx >= data.length) {
      return null;
    }
    final l0 = data[idx++];
    var length = 0;
    if (l0 < 0x80) {
      length = l0;
    } else if (l0 >= 0x81 && l0 <= 0x84) {
      final numBytes = l0 & 0x0F;
      if (idx + numBytes > data.length) {
        return null;
      }
      for (var i = 0; i < numBytes; i++) {
        length = (length << 8) | data[idx++];
      }
    } else {
      return null;
    }
    if (idx + length > data.length) {
      return null;
    }
    return (
      record: TlvRecord(tag, data.sublist(idx, idx + length)),
      end: idx + length,
    );
  }

  static List<int> _tagBytes(int tag) {
    if (tag < 0) {
      throw ArgumentError.value(tag, 'tag', 'tag must be non-negative');
    }
    if (tag == 0) {
      return [0];
    }
    final bytes = <int>[];
    var rest = tag;
    while (rest > 0) {
      bytes.insert(0, rest & 0xFF);
      rest >>= 8;
    }
    return bytes;
  }
}
