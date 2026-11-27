// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: no single upstream declaration; upstream reaches ASN.1 through
//   OpenSSL's `d2i_*` family (`OpenSSLUtils.swift`) and never walks DER
//   itself. This is the substrate the pki layer needs underneath it.

/// BER/DER reader for the passive-authentication subsystem.
///
/// Three properties the two existing parsers cannot both supply, which is why
/// this file exists rather than reusing them:
/// - **BER indefinite lengths** (`0x80` + end-of-contents): real CSCA master
///   lists carry them. [TlvRecord] rejects `0x80` by design and that stays.
/// - **Byte-exact raw slices**: every signature input in CMS/X.509 is "the
///   original encoding of element X" (the TBS slice, the signed-attributes
///   slice, an embedded certificate). Nothing here re-encodes.
/// - **Totality**: hostile input yields `null`, never a throw and never a
///   crash.
///
/// pointycastle's parser throws on a zero-length TLV directly inside an
/// indefinite-length region (`asn1_utils.dart:142-144`). This walker has no
/// such bug (an empty TLV is just `contentLength == 0`), and it also lifts
/// pointycastle's two other structural limits: constructed tags ≥ `0xA5` and
/// application-class constructed tags throw there, and its `nextObject`
/// returns an over-long `encodedBytes` view for objects deep into a buffer,
/// which would poison exactly the raw slices this layer lives on.
///
/// Internal: not exported from the barrel.
library;

import 'dart:convert';
import 'dart:typed_data';

/// One parsed BER/TLV element, holding its position in the *source* buffer so
/// callers can take byte-exact slices without re-encoding.
class Asn1Node {
  Asn1Node._({
    required this.source,
    required this.tag,
    required this.start,
    required this.headerLength,
    required this.contentLength,
    required this.indefinite,
    required this.children,
  });

  /// The buffer this element was parsed out of.
  final Uint8List source;

  /// Raw tag bytes as a big-endian int (`0x30`, `0xA0`, `0x7F49`, ...), the
  /// [TlvRecord] convention, kept package-wide.
  final int tag;

  /// Offset of the first identifier octet within [source].
  final int start;

  /// Identifier + length octets.
  final int headerLength;

  /// Content octets, excluding the two end-of-contents octets of an
  /// indefinite-length element.
  final int contentLength;

  /// Whether the element was encoded with the indefinite length form.
  final bool indefinite;

  /// Parsed children of a constructed element; `null` for primitives.
  final List<Asn1Node>? children;

  /// Total octets this element occupies in [source], EOC included.
  int get totalLength => headerLength + contentLength + (indefinite ? 2 : 0);

  /// Offset one past the last octet of this element.
  int get end => start + totalLength;

  /// The element's full encoding, verbatim: the byte-exact slice CMS/X.509
  /// signature inputs are defined over.
  Uint8List get encoded => Uint8List.sublistView(source, start, end);

  /// The content octets, verbatim.
  Uint8List get content => Uint8List.sublistView(
    source,
    start + headerLength,
    start + headerLength + contentLength,
  );

  /// BER constructed bit of the leading identifier octet.
  bool get isConstructed => _leadingTagByte(tag) & 0x20 != 0;

  /// The `i`-th child, or `null` when absent (or this is primitive), the
  /// `ASN1Item.getChild` shape ported call sites expect.
  Asn1Node? child(int i) {
    final c = children;
    if (c == null || i < 0 || i >= c.length) {
      return null;
    }
    return c[i];
  }

  /// Children count (0 for primitives).
  int get childCount => children?.length ?? 0;
}

/// The recursion ceiling. Real SOD/certificate/master-list structures nest
/// well under ten levels; the cap makes a hostile input cheap to reject
/// instead of exhausting the stack.
const int _maxDepth = 40;

/// Parses exactly one element from [data] at [offset]. Returns `null` on any
/// malformed encoding (truncation, bad length, unterminated indefinite region,
/// absurd nesting). Trailing bytes after the element are ignored.
Asn1Node? parseAsn1(Uint8List data, {int offset = 0}) =>
    _parseAt(data, offset, 0);

/// Parses elements back-to-back until [data] is exhausted. Returns `null` if
/// any element is malformed or does not end exactly on the buffer boundary;
/// empty input yields an empty list.
List<Asn1Node>? parseAsn1Sequence(Uint8List data) => _parseRun(data, 0, 0);

/// Parses [node]'s content as a run of elements *in place*, used where a
/// primitive tag carries a nested structure (an OCTET STRING wrapping DER, an
/// extension's `extnValue`). Parsing in place rather than over a copy keeps
/// every nested node's [Asn1Node.encoded] a view of the original buffer.
List<Asn1Node>? parseAsn1Content(Asn1Node node) {
  if (node.indefinite) {
    return node.children;
  }
  final from = node.start + node.headerLength;
  return _parseRun(node.source, from, 0, limit: from + node.contentLength);
}

/// Parses one element from the start of [node]'s content, in place.
Asn1Node? parseAsn1Inside(Asn1Node node) {
  final inner = _parseAt(node.source, node.start + node.headerLength, 0);
  if (inner == null ||
      inner.end > node.start + node.headerLength + node.contentLength) {
    return null;
  }
  return inner;
}

Asn1Node? _parseAt(Uint8List data, int start, int depth) {
  if (depth > _maxDepth) {
    return null;
  }
  var idx = start;
  if (idx < 0 || idx >= data.length) {
    return null;
  }

  // --- identifier octets (BER: low five bits all set => continuation octets
  // while the high bit is set; the one tag rule used package-wide).
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

  // --- length octets: short form, long form (0x81-0x84), or indefinite.
  if (idx >= data.length) {
    return null;
  }
  final l0 = data[idx++];
  var contentLength = 0;
  var indefinite = false;
  if (l0 == 0x80) {
    indefinite = true;
  } else if (l0 < 0x80) {
    contentLength = l0;
  } else {
    final numBytes = l0 & 0x7F;
    if (numBytes > 4 || idx + numBytes > data.length) {
      return null; // > 4 GiB lengths are not real input
    }
    for (var i = 0; i < numBytes; i++) {
      contentLength = (contentLength << 8) | data[idx++];
    }
  }
  final headerLength = idx - start;
  final constructed = (b0 & 0x20) != 0;

  if (indefinite) {
    if (!constructed) {
      return null; // indefinite length is defined for constructed only
    }
    // Children are parsed until the end-of-contents pair; the region's own
    // length is whatever they consumed. A zero-length child (`05 00`, an
    // empty OCTET STRING) is ordinary here; pointycastle's walker throws on it.
    final kids = <Asn1Node>[];
    var pos = idx;
    while (true) {
      if (pos + 1 >= data.length) {
        return null; // unterminated indefinite region
      }
      if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
        break; // end-of-contents
      }
      final kid = _parseAt(data, pos, depth + 1);
      if (kid == null) {
        return null;
      }
      kids.add(kid);
      pos = kid.end;
    }
    return Asn1Node._(
      source: data,
      tag: tag,
      start: start,
      headerLength: headerLength,
      contentLength: pos - idx,
      indefinite: true,
      children: kids,
    );
  }

  if (idx + contentLength > data.length) {
    return null; // truncated content
  }
  List<Asn1Node>? children;
  if (constructed) {
    children = _parseRun(data, idx, depth + 1, limit: idx + contentLength);
    if (children == null) {
      return null;
    }
  }
  return Asn1Node._(
    source: data,
    tag: tag,
    start: start,
    headerLength: headerLength,
    contentLength: contentLength,
    indefinite: false,
    children: children,
  );
}

List<Asn1Node>? _parseRun(Uint8List data, int start, int depth, {int? limit}) {
  final stop = limit ?? data.length;
  final out = <Asn1Node>[];
  var pos = start;
  while (pos < stop) {
    final node = _parseAt(data, pos, depth);
    if (node == null || node.end > stop) {
      return null;
    }
    out.add(node);
    pos = node.end;
  }
  return pos == stop ? out : null;
}

// --- content decoders -------------------------------------------------------

/// Universal tag numbers this layer names.
class Asn1Tag {
  static const int boolean = 0x01;
  static const int integer = 0x02;
  static const int bitString = 0x03;
  static const int octetString = 0x04;
  static const int nullTag = 0x05;
  static const int oid = 0x06;
  static const int utf8String = 0x0C;
  static const int sequence = 0x30;
  static const int set = 0x31;
  static const int printableString = 0x13;
  static const int t61String = 0x14;
  static const int ia5String = 0x16;
  static const int utcTime = 0x17;
  static const int generalizedTime = 0x18;
  static const int bmpString = 0x1E;
  static const int universalString = 0x1C;
}

/// A DER OBJECT IDENTIFIER's **content** octets as a dotted string; `null` on
/// a malformed body. (The [asn1DecodeOid] in `lds/tlv.dart` takes the full
/// tag+length+body encoding and throws; this layer is total and slices
/// content directly.)
String? decodeOidContent(List<int> content) {
  if (content.isEmpty) {
    return null;
  }
  final arcs = <int>[];
  var v = 0;
  var inArc = false;
  for (final b in content) {
    if (v > (1 << 45)) {
      return null; // absurd arc value
    }
    v = (v << 7) | (b & 0x7F);
    inArc = (b & 0x80) != 0;
    if (!inArc) {
      arcs.add(v);
      v = 0;
    }
  }
  if (inArc) {
    return null; // unterminated base-128 arc
  }
  final first = arcs[0];
  final (a, b) = switch (first) {
    < 40 => (0, first),
    < 80 => (1, first - 40),
    _ => (2, first - 80),
  };
  return [a, b, ...arcs.skip(1)].join('.');
}

/// [node] as a dotted OID string, or `null` when it is not an OID.
String? oidOf(Asn1Node? node) {
  if (node == null || node.tag != Asn1Tag.oid) {
    return null;
  }
  return decodeOidContent(node.content);
}

/// A DER INTEGER's content as a two's-complement [BigInt]; `null` when empty.
BigInt? decodeIntegerContent(List<int> content) {
  if (content.isEmpty) {
    return null;
  }
  var v = BigInt.zero;
  for (final b in content) {
    v = (v << 8) | BigInt.from(b);
  }
  if ((content[0] & 0x80) != 0) {
    v -= BigInt.one << (8 * content.length);
  }
  return v;
}

/// [node] as a [BigInt], or `null` when it is not a usable INTEGER.
BigInt? integerOf(Asn1Node? node) {
  if (node == null || node.tag != Asn1Tag.integer) {
    return null;
  }
  return decodeIntegerContent(node.content);
}

/// A BIT STRING's payload with the leading unused-bits octet removed; `null`
/// when the node is not a whole-octet BIT STRING (any key or signature
/// encoding is whole-octet, so a non-zero unused-bits count is malformed).
Uint8List? bitStringBytes(Asn1Node? node) {
  if (node == null || node.tag != Asn1Tag.bitString) {
    return null;
  }
  final c = node.content;
  if (c.isEmpty || c[0] != 0x00) {
    return null;
  }
  return Uint8List.sublistView(c, 1);
}

/// The set bits of a DER BIT STRING, most-significant bit of the first octet
/// first (X.509 `KeyUsage` semantics); `null` on a malformed encoding.
List<bool>? bitStringFlags(Asn1Node? node) {
  if (node == null || node.tag != Asn1Tag.bitString) {
    return null;
  }
  final c = node.content;
  if (c.isEmpty || c[0] > 7) {
    return null;
  }
  final unused = c[0];
  final bits = <bool>[];
  for (var i = 1; i < c.length; i++) {
    final last = i == c.length - 1;
    final count = last ? 8 - unused : 8;
    for (var b = 0; b < count; b++) {
      bits.add((c[i] & (0x80 >> b)) != 0);
    }
  }
  return bits;
}

/// A DER BOOLEAN; `null` when the node is not one. Any non-zero content octet
/// reads as true (BER tolerance: DER mandates `0xFF`).
bool? booleanOf(Asn1Node? node) {
  if (node == null || node.tag != Asn1Tag.boolean || node.content.length != 1) {
    return null;
  }
  return node.content[0] != 0x00;
}

/// X.509 `Time`: `UTCTime` (`YYMMDDHHMMSS[Z|±hhmm]`, two-digit years pivoted
/// at 50 per RFC 5280 §4.1.2.5.1) or `GeneralizedTime` (`YYYYMMDDHHMMSS...`).
/// Returns a UTC [DateTime], or `null` when the node is neither or its body
/// does not parse. Fractional seconds are accepted and dropped (they carry no
/// meaning for a validity window).
DateTime? decodeAsn1Time(Asn1Node? node) {
  if (node == null) {
    return null;
  }
  final isUtc = node.tag == Asn1Tag.utcTime;
  if (!isUtc && node.tag != Asn1Tag.generalizedTime) {
    return null;
  }
  var s = String.fromCharCodes(node.content);
  if (s.isEmpty) {
    return null;
  }

  // Timezone suffix: 'Z', or ±hhmm (a local-time body with no suffix is
  // out-of-profile for X.509; it is read as UTC rather than rejected, the
  // tolerant-reader posture the rest of this layer takes).
  var offsetMinutes = 0;
  if (s.endsWith('Z')) {
    s = s.substring(0, s.length - 1);
  } else {
    final signIdx = s.lastIndexOf(RegExp('[+-]'));
    if (signIdx > 0 && s.length - signIdx == 5) {
      final sign = s[signIdx] == '-' ? -1 : 1;
      final hh = int.tryParse(s.substring(signIdx + 1, signIdx + 3));
      final mm = int.tryParse(s.substring(signIdx + 3, signIdx + 5));
      if (hh == null || mm == null) {
        return null;
      }
      offsetMinutes = sign * (hh * 60 + mm);
      s = s.substring(0, signIdx);
    }
  }
  final dot = s.indexOf(RegExp('[.,]'));
  if (dot >= 0) {
    s = s.substring(0, dot);
  }

  final int year;
  var i = 0;
  if (isUtc) {
    if (s.length < 10) {
      return null;
    }
    final yy = int.tryParse(s.substring(0, 2));
    if (yy == null) {
      return null;
    }
    year = yy >= 50 ? 1900 + yy : 2000 + yy; // RFC 5280 §4.1.2.5.1
    i = 2;
  } else {
    if (s.length < 10) {
      return null;
    }
    final yyyy = int.tryParse(s.substring(0, 4));
    if (yyyy == null) {
      return null;
    }
    year = yyyy;
    i = 4;
  }
  int? take(int n) {
    if (i + n > s.length) {
      return null;
    }
    final v = int.tryParse(s.substring(i, i + n));
    i += n;
    return v;
  }

  final month = take(2);
  final day = take(2);
  final hour = take(2);
  final minute = take(2);
  final second = i < s.length ? take(2) ?? 0 : 0;
  if (month == null || day == null || hour == null || minute == null) {
    return null;
  }
  if (month < 1 ||
      month > 12 ||
      day < 1 ||
      day > 31 ||
      hour > 23 ||
      minute > 59 ||
      second > 60) {
    return null;
  }
  return DateTime.utc(
    year,
    month,
    day,
    hour,
    minute,
    second,
  ).subtract(Duration(minutes: offsetMinutes));
}

/// An ASN.1 string node's text. `BMPString` is UTF-16BE, `UniversalString`
/// UTF-32BE; everything else is read as UTF-8 (a superset of the
/// PrintableString/IA5String repertoires, and the pragmatic reading of the
/// T61Strings real CSCA DNs carry). `null` for a non-string node.
String? decodeAsn1String(Asn1Node? node) {
  if (node == null) {
    return null;
  }
  final c = node.content;
  switch (node.tag) {
    case Asn1Tag.bmpString:
      if (c.length.isOdd) {
        return null;
      }
      final units = <int>[
        for (var i = 0; i + 1 < c.length; i += 2) (c[i] << 8) | c[i + 1],
      ];
      return String.fromCharCodes(units);
    case Asn1Tag.universalString:
      if (c.length % 4 != 0) {
        return null;
      }
      final units = <int>[
        for (var i = 0; i + 3 < c.length; i += 4)
          (c[i] << 24) | (c[i + 1] << 16) | (c[i + 2] << 8) | c[i + 3],
      ];
      return String.fromCharCodes(units);
    case Asn1Tag.utf8String:
    case Asn1Tag.printableString:
    case Asn1Tag.ia5String:
    case Asn1Tag.t61String:
    case 0x12: // NumericString
    case 0x15: // VideotexString
    case 0x1A: // VisibleString
      return _utf8OrLatin1(c);
    default:
      return null;
  }
}

String _utf8OrLatin1(List<int> bytes) {
  try {
    return const Utf8Decoder().convert(bytes);
  } on FormatException {
    return String.fromCharCodes(bytes); // latin-1 fallback, never throws
  }
}

int _leadingTagByte(int tag) {
  var t = tag;
  while (t > 0xFF) {
    t >>= 8;
  }
  return t;
}
