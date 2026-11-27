// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Utils.swift @ 3bf5456 (2.3.2)

/// Byte/hex plumbing from upstream `Utils.swift`.
///
/// Upstream names are kept verbatim so ported call sites stay line-by-line
/// diffable against Swift. Crypto helpers (`mac`, `calcHash`, RNG) are
/// deliberately absent: they live in `crypto/`.
///
/// Where a helper keeps an upstream quirk or departs from upstream (an input
/// guard or a bug fix), its own doc says so.
library;

import 'dart:typed_data';

import 'errors.dart';

/// Swift `binToHexRep([UInt8], asArray:)`.
///
/// Default: uppercase hex, no separators. With [asArray]: the lowercase
/// `"[0xaa, 0xbb, ]"` log format (trailing `", "` included; the TagReader and
/// PACEHandler log lines use it, and those lines are verbatim from upstream).
String binToHexRep(List<int> val, {bool asArray = false}) {
  final buf = StringBuffer(asArray ? '[' : '');
  for (final x in val) {
    if (asArray) {
      buf.write('0x${x.toRadixString(16).padLeft(2, '0')}, ');
    } else {
      buf.write(x.toRadixString(16).padLeft(2, '0'));
    }
  }
  if (asArray) {
    buf.write(']');
    return buf.toString();
  }
  return buf.toString().toUpperCase();
}

/// Swift `binToHexRep(UInt8)`: single byte, uppercase two digits.
/// (The Swift overload needs a distinct Dart name.)
String binToHexRepByte(int val) =>
    val.toRadixString(16).padLeft(2, '0').toUpperCase();

/// Swift `binToHex(UInt8) -> Int`: identity on 0..255, kept for call-site
/// parity (upstream formats to hex and re-parses).
int binToHex(int byte) => byte;

/// Swift `binToHex([UInt8]) -> UInt64`: big-endian bytes to int.
///
/// Guarded to ≤ 7 bytes: Dart `int` is *signed* 64-bit, so an 8-byte value with
/// the top bit set would come out negative. Stricter than upstream, which
/// succeeds on any ≤ 8-byte input here: the 8-byte top-bit-clear slice carries
/// split conformance cases. Empty input (an upstream force-unwrap crash) is
/// also rejected.
int binToHexBytes(List<int> val) => binToInt(val);

/// Swift `binToInt([UInt8]/slice) -> Int`: big-endian bytes to int.
///
/// Same ≤ 7-byte / non-empty guard as [binToHexBytes]; upstream crashes above 8
/// bytes or on 8-byte values with the top bit set, and the port fails loudly
/// one byte earlier so no 8-byte quantity (the SSC) ever round-trips through
/// these helpers.
int binToInt(List<int> val) {
  if (val.isEmpty || val.length > 7) {
    throw ArgumentError.value(
      val,
      'val',
      'binToInt/binToHexBytes take 1..7 bytes',
    );
  }
  var out = 0;
  for (final b in val) {
    out = (out << 8) | (b & 0xFF);
  }
  return out;
}

/// Swift `intToBin(_:pad:)`. [pad] counts HEX DIGITS: 2 => minimum one byte,
/// any other value => upstream's `%04x` branch, minimum two bytes.
///
/// Divergence (bug fix): upstream formats odd-width hex for values above the
/// pad width and mangles bytes via the odd-length `hexRepToBin` quirk
/// (`300 -> [0x12, 0x0C]`). The port always encodes even-width
/// (`300 -> [0x01, 0x2C]`) at both pad settings; split conformance cases pin
/// the Swift behavior separately.
Uint8List intToBin(int data, {int pad = 2}) {
  if (data < 0) {
    throw ArgumentError.value(
      data,
      'data',
      'intToBin takes non-negative values',
    );
  }
  final minDigits = pad == 2 ? 2 : 4;
  var hex = data.toRadixString(16);
  if (hex.length < minDigits) {
    hex = hex.padLeft(minDigits, '0');
  } else if (hex.length.isOdd) {
    hex = '0$hex'; // even-width, unlike upstream
  }
  return hexRepToBin(hex);
}

/// Swift `hexRepToBin(String)`: `'AABB' -> [0xAA, 0xBB]`.
///
/// Quirk preserved: odd-length input reads the final lone hex digit as its own
/// byte, `"ABC" -> [0xAB, 0x0C]`.
Uint8List hexRepToBin(String val) {
  final out = <int>[];
  var x = 0;
  while (x < val.length) {
    if (x + 2 <= val.length) {
      out.add(int.parse(val.substring(x, x + 2), radix: 16));
    } else {
      out.add(int.parse(val.substring(x, x + 1), radix: 16));
    }
    x += 2;
  }
  return Uint8List.fromList(out);
}

/// Swift `xor(kifd, response_kicc)`: byte-wise XOR over `a`'s length.
///
/// Quirk preserved: a longer [b] is silently truncated to [a]'s length, as
/// upstream does. A *shorter* [b] index-crashes upstream and is rejected here
/// (dart-only guard).
Uint8List xor(List<int> a, List<int> b) {
  if (b.length < a.length) {
    throw ArgumentError.value(b, 'b', 'xor needs b.length >= a.length');
  }
  final out = Uint8List(a.length);
  for (var i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/// Swift `intToBytes(val:removePadding:)`: 8-byte big-endian encoding of
/// [val]; `0 -> [0]`; [removePadding] strips leading zero bytes.
///
/// Negative values (upstream emits the raw two's-complement; the sole in-scope
/// caller passes non-negative key ids) are rejected (dart-only guard).
Uint8List intToBytes(int val, {required bool removePadding}) {
  if (val < 0) {
    throw ArgumentError.value(
      val,
      'val',
      'intToBytes takes non-negative values',
    );
  }
  if (val == 0) {
    return Uint8List.fromList([0]);
  }
  final data = Uint8List(8)..buffer.asByteData().setUint64(0, val);
  if (removePadding) {
    var i = 0;
    while (i < data.length && data[i] == 0) {
      i++;
    }
    return Uint8List.sublistView(data, i);
  }
  return data;
}

/// Swift `pad(_:blockSize:)`, ISO 9797-1 padding method 2: append `0x80`,
/// then `0x00` until block-aligned.
///
/// Quirk pinned: already-aligned input gains a full extra block (correct
/// method-2 behavior).
Uint8List pad(List<int> toPad, {required int blockSize}) {
  final ret = <int>[...toPad, 0x80];
  while (ret.length % blockSize != 0) {
    ret.add(0x00);
  }
  return Uint8List.fromList(ret);
}

/// Swift `unpad(_:)`: strip ISO 9797-1 method-2 padding.
///
/// Quirk preserved: after stripping trailing `0x00`s, if the next byte is not
/// `0x80` the input is returned **unchanged** ("no padding" passthrough,
/// including the stripped zeros).
///
/// Divergence (bug fix): empty or all-zero input index-underflows upstream; the
/// port throws [InvalidDataPassed].
Uint8List unpad(List<int> toUnpad) {
  var i = toUnpad.length - 1;
  while (i >= 0 && toUnpad[i] == 0x00) {
    i--;
  }
  if (i < 0) {
    throw const InvalidDataPassed(
      'unpad: empty or all-zero input has no padding boundary',
    );
  }
  if (toUnpad[i] == 0x80) {
    return Uint8List.fromList(toUnpad.sublist(0, i));
  }
  // no padding
  return Uint8List.fromList(toUnpad);
}
