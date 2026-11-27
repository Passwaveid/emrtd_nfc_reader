// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/OpenSSLUtils.swift:350-377
//   (`decryptRSASignature`), the raw `RSA_public_decrypt(..., RSA_NO_PADDING)`
//   call, re-expressed as a BigInt modular exponentiation.

/// The one RSA operation Active Authentication needs: the *raw* public-key
/// transform `sig^e mod n`, no padding scheme applied.
///
/// Upstream reaches it through `RSA_public_decrypt` with `RSA_NO_PADDING`,
/// which, via `RSA_padding_check_none`, returns the full `RSA_size(n)`-byte
/// buffer, left-padded with zeros. [rsaPublicDecryptRaw] reproduces that
/// byte-for-byte: the ISO 9796-2 recovery walk in
/// `proto/active_authentication.dart` indexes from both ends of that buffer,
/// so a stripped leading zero would shift every offset.
///
/// The two `RSA_public_decrypt` error paths, a signature longer than the
/// modulus (`RSA_R_DATA_GREATER_THAN_MOD_LEN`) and one numerically ≥ the
/// modulus (`RSA_R_DATA_TOO_LARGE_FOR_MODULUS`), return `null` here. Upstream
/// mis-detects both (it tests `outlen == 0` where the C call returns `-1`)
/// and walks its pre-zeroed buffer instead, which dies at the trailer switch;
/// the observable outcome on both sides is AA `failed`.
///
/// Internal: not exported from the barrel (`rng.dart` is the only public
/// crypto file).
library;

import 'dart:typed_data';

import 'ec_dh.dart';

/// `sig^e mod n`, left-padded to `⌈bitLength(n)/8⌉` bytes (`RSA_size`).
///
/// Returns `null` for the two upstream error paths and for a degenerate
/// modulus (`n ≤ 1`: no `d2i_RSA_PUBKEY`-shaped key has one; the guard keeps
/// the primitive total rather than letting `modPow` throw).
Uint8List? rsaPublicDecryptRaw({
  required BigInt modulus,
  required BigInt exponent,
  required List<int> signature,
}) {
  if (modulus <= BigInt.one || exponent < BigInt.zero) {
    return null;
  }
  // RSA_size(rsa): BN_num_bytes(n).
  final keySize = (modulus.bitLength + 7) >> 3;
  if (signature.length > keySize) {
    return null; // RSA_R_DATA_GREATER_THAN_MOD_LEN
  }
  final value = bytesToBigInt(signature);
  if (value >= modulus) {
    return null; // RSA_R_DATA_TOO_LARGE_FOR_MODULUS
  }
  // BN_bn2binpad(ret, buf, num) + RSA_padding_check_none: the full keySize
  // buffer, zero-padded on the left.
  return bigIntToBytes(value.modPow(exponent, modulus), length: keySize);
}
