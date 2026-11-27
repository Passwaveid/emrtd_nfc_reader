// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: no single upstream analogue; the raw EC/DH operations upstream
//   performs through OpenSSL (PACEHandler.swift / OpenSSLUtils.swift
//   EVP/EC/BN calls), extracted as a primitive layer pinned against its own
//   fixed vectors and composed by the PACE and Chip Authentication handlers.

/// EC + DH primitives for PACE and Chip Authentication, over pointycastle's
/// `ECDomainParameters`/`ECPoint` and Dart [BigInt].
///
/// Byte conversion turns on leading zero bytes: [bigIntToBytes] takes an
/// explicit `length` (pad: `FE2OS`/`EVP_PKEY_derive` parity) or none (strip:
/// `BN_bn2bin` parity) so both behaviors are expressible and chosen
/// consciously at each call site.
///
/// [ecPointDecode] is **security-critical**: OpenSSL's `EC_POINT_oct2point`,
/// which upstream relies on for DO82/DO84, validates the decoded point is on
/// the curve, and TR-03111 §3.2.1 makes that validation a MUST. The helper
/// validates on-curve and coordinate range, accepts compressed (`02`/`03`)
/// input as `oct2point` does, and rejects the point-at-infinity encoding
/// (`00`) and hybrid `06`/`07` forms, deliberately *stricter* than
/// `oct2point` (which accepts both), spec-safe per TR-03111 (defines no
/// hybrid encoding; its ECKA rejects S = O).
///
/// Cofactor parity: TR-03111 §4.3.1 ECKA's "compatible cofactor multiplication"
/// collapses to plain d·P on cofactor-1 curves, and every PACEInfo standardized
/// curve has h = 1, so pointycastle's plain scalar multiplication is bit-exact.
library;

import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import '../errors.dart';
import 'rng.dart';

/// Unsigned big-endian encoding of [v].
///
/// Without [length]: minimal form, leading zero bytes stripped, `BN_bn2bin`
/// parity; `0` encodes as the empty array. With [length]: left-pad with zeros
/// to exactly [length] bytes, `FE2OS` parity; throws [ArgumentError] if [v]
/// does not fit (helper misuse, dart-only guard).
Uint8List bigIntToBytes(BigInt v, {int? length}) {
  if (v.isNegative) {
    throw ArgumentError.value(v, 'v', 'bigIntToBytes takes unsigned values');
  }
  final minimal = (v.bitLength + 7) >> 3;
  final len = length ?? minimal;
  if (minimal > len) {
    throw ArgumentError.value(
      v,
      'v',
      'value needs $minimal bytes, does not fit in length $len',
    );
  }
  final out = Uint8List(len);
  var x = v;
  for (var i = len - 1; i >= 0 && x != BigInt.zero; i--) {
    out[i] = (x & BigInt.from(0xFF)).toInt();
    x >>= 8;
  }
  return out;
}

/// Unsigned big-endian bytes -> [BigInt]; empty input -> 0 (`BN_bin2bn`
/// parity).
BigInt bytesToBigInt(List<int> bytes) {
  var out = BigInt.zero;
  for (final b in bytes) {
    out = (out << 8) | BigInt.from(b & 0xFF);
  }
  return out;
}

/// Field size of [curve] in bytes (`⌈fieldBits/8⌉`).
int _fieldByteLength(ECDomainParameters curve) =>
    (curve.curve.fieldSize + 7) >> 3;

/// The underlying prime field: every PACEInfo standardized curve is Fp.
fp.ECCurve _fpCurve(ECDomainParameters curve) {
  final c = curve.curve;
  if (c is! fp.ECCurve) {
    throw InvalidDataPassed(
      'ecPointDecode: only prime-field curves are supported, got '
      '${c.runtimeType}',
    );
  }
  return c;
}

bool _isOnCurve(fp.ECCurve c, BigInt x, BigInt y) {
  final p = c.q!;
  final a = c.a!.toBigInteger()!;
  final b = c.b!.toBigInteger()!;
  final lhs = (y * y) % p;
  final rhs = (((x * x) % p * x) + a * x + b) % p;
  return lhs == rhs;
}

/// Decodes an encoded EC point on [curve], `EC_POINT_oct2point` parity with
/// the deliberate restrictions described in the library doc: accepts
/// uncompressed `04‖X‖Y` (validated on-curve + in-range) and compressed
/// `02`/`03`; rejects empty input, the infinity encoding `00`, hybrid
/// `06`/`07`, wrong-length input, off-curve and out-of-range points, all as
/// [InvalidDataPassed].
ECPoint ecPointDecode(ECDomainParameters curve, List<int> encoded) {
  if (encoded.isEmpty) {
    throw const InvalidDataPassed('ecPointDecode: empty point encoding');
  }
  final c = _fpCurve(curve);
  final fLen = _fieldByteLength(curve);
  switch (encoded[0]) {
    case 0x00:
      throw const InvalidDataPassed(
        'ecPointDecode: point-at-infinity encoding rejected',
      );
    case 0x06 || 0x07:
      throw const InvalidDataPassed('ecPointDecode: hybrid encoding rejected');
    case 0x02 || 0x03:
      if (encoded.length != 1 + fLen) {
        throw InvalidDataPassed(
          'ecPointDecode: compressed encoding must be ${1 + fLen} bytes, '
          'got ${encoded.length}',
        );
      }
      final x = bytesToBigInt(encoded.sublist(1));
      if (x >= c.q!) {
        throw const InvalidDataPassed(
          'ecPointDecode: x-coordinate out of field range',
        );
      }
      try {
        // Solves the curve equation: a decompressed point is on-curve by
        // construction; no x satisfying it throws.
        return c.decompressPoint(encoded[0] & 1, x);
      } on ArgumentError {
        throw const InvalidDataPassed(
          'ecPointDecode: invalid compressed point (no curve point at x)',
        );
      }
    case 0x04:
      if (encoded.length != 1 + 2 * fLen) {
        throw InvalidDataPassed(
          'ecPointDecode: uncompressed encoding must be ${1 + 2 * fLen} '
          'bytes, got ${encoded.length}',
        );
      }
      final x = bytesToBigInt(encoded.sublist(1, 1 + fLen));
      final y = bytesToBigInt(encoded.sublist(1 + fLen));
      if (x >= c.q! || y >= c.q!) {
        throw const InvalidDataPassed(
          'ecPointDecode: coordinate out of field range',
        );
      }
      if (!_isOnCurve(c, x, y)) {
        throw const InvalidDataPassed(
          'ecPointDecode: point is not on the curve (TR-03111 3.2.1)',
        );
      }
      return c.createPoint(x, y);
    default:
      throw InvalidDataPassed(
        'ecPointDecode: unsupported point encoding 0x'
        '${encoded[0].toRadixString(16).padLeft(2, '0')}',
      );
  }
}

/// Encodes [p] uncompressed (`04‖X‖Y`, coordinates zero-padded to the field
/// byte length), `EC_POINT_point2oct` parity. Rejects the point at infinity
/// (it has no uncompressed encoding).
Uint8List ecPointEncode(ECPoint p) {
  if (p.isInfinity) {
    throw const InvalidDataPassed(
      'ecPointEncode: point at infinity has no uncompressed encoding',
    );
  }
  return p.getEncoded(false);
}

/// Public key Q = d·G on [curve]. Throws [InvalidDataPassed] for d outside
/// [1, n-1] (dart-only guard: such a scalar is never a valid EC private
/// key).
ECPoint ecPublicFromPrivate(ECDomainParameters curve, BigInt d) {
  if (d <= BigInt.zero || d >= curve.n) {
    throw const InvalidDataPassed(
      'ecPublicFromPrivate: private scalar out of range [1, n-1]',
    );
  }
  return (curve.G * d)!;
}

/// ECDH shared secret: the x-coordinate of d·peer, **zero-padded to the field
/// byte length**, `EVP_PKEY_derive` parity. Throws on a degenerate S = O
/// result (TR-03111 ECKA rejects it).
Uint8List ecdhSharedSecretX(ECDomainParameters curve, BigInt d, ECPoint peer) {
  final s = ecPointMul(curve, d, peer);
  return bigIntToBytes(s.x!.toBigInteger()!, length: _fieldByteLength(curve));
}

/// s·g + h: the generic-mapping shape Ĝ = s·G + H (upstream
/// `EC_POINT_mul(group, out, nonce, H, BN_value_one())`). Throws on an
/// infinity result (unusable as a group generator).
ECPoint ecMulAdd(ECDomainParameters curve, BigInt s, ECPoint g, ECPoint h) {
  final r = (g * s)! + h;
  if (r == null || r.isInfinity) {
    throw const InvalidDataPassed('ecMulAdd: result is the point at infinity');
  }
  return r;
}

/// d·p as a **full point**: the ECDH *mapping* needs the shared point H
/// itself, not its x-coordinate (upstream `computeECDHMappingKeyPoint`).
/// Throws on an infinity result.
ECPoint ecPointMul(ECDomainParameters curve, BigInt d, ECPoint p) {
  final r = p * d;
  if (r == null || r.isInfinity) {
    throw const InvalidDataPassed(
      'ecPointMul: result is the point at infinity',
    );
  }
  return r;
}

/// Fresh EC keypair off the [rng] seam for the live path: d sampled by
/// rejection into [1, n-1] (distribution is unobservable on the wire;
/// deterministic tests inject private keys through the handlers' seams).
({BigInt d, ECPoint q}) ecGenerateKeyPair(
  ECDomainParameters curve,
  EmrtdRandom rng,
) {
  final n = curve.n;
  final byteLen = (n.bitLength + 7) >> 3;
  final excessBits = byteLen * 8 - n.bitLength;
  BigInt d;
  do {
    d = bytesToBigInt(rng.nextBytes(byteLen)) >> excessBits;
  } while (d == BigInt.zero || d >= n);
  return (d: d, q: (curve.G * d)!);
}

/// Fresh DH keypair off the [rng] seam: x sampled by rejection into
/// [1, q-1] when the subgroup order [q] is known (RFC 5114 groups carry one),
/// else into [1, p-2].
({BigInt x, BigInt y}) dhGenerateKeyPair({
  required BigInt p,
  required BigInt g,
  BigInt? q,
  required EmrtdRandom rng,
}) {
  final bound = q ?? (p - BigInt.one);
  final byteLen = (bound.bitLength + 7) >> 3;
  final excessBits = byteLen * 8 - bound.bitLength;
  BigInt x;
  do {
    x = bytesToBigInt(rng.nextBytes(byteLen)) >> excessBits;
  } while (x == BigInt.zero || x >= bound);
  return (x: x, y: g.modPow(x, p));
}

/// DH public key y = g^x mod p (`BigInt.modPow`).
BigInt dhPublic(BigInt p, BigInt g, BigInt x) => g.modPow(x, p);

/// DH shared secret peer^x mod p. No leading-zero handling here: each
/// caller composes [bigIntToBytes] as it needs (upstream's `DH_compute_key`
/// return-ignored quirk lives at the call sites, not in the primitive).
BigInt dhSharedSecret(BigInt p, BigInt x, BigInt peerPublic) =>
    peerPublic.modPow(x, p);
