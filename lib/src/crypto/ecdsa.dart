// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/OpenSSLUtils.swift:410-549
//   (`verifyECDSASignature` + `verifySignature`) minus the plain-to-DER
//   re-encode and the leading-zero "fix" block, both inert on the Active
//   Authentication path: the DER those lines inspect was just produced by
//   `i2d_ECDSA_SIG` and always re-parses, and this verifier consumes `r`/`s`
//   directly.

/// ECDSA *verification* for Active Authentication, the second of the two new
/// primitives the AA port needs.
///
/// Upstream ends at `EVP_DigestVerifyInit`/`Update`/`Final` over an
/// `EVP_PKEY` EC key: hash the data with the selected digest, then verify
/// `(r, s)` against that hash truncated to the group order's bit length.
/// pointycastle's [ECDSASigner] performs exactly that composition (its
/// `_calculateE` is the same left-truncation), so the parity is at the
/// algorithm level rather than through a re-encode.
///
/// `r`/`s` outside `[1, n-1]` return `false`, as `ECDSA_do_verify` does.
///
/// Internal: not exported from the barrel.
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart' show Digest, PublicKeyParameter;
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

/// Verifies the plain-ECDSA pair ([r], [s]) over [data] under [publicPoint]
/// on [domain], hashing with [digest].
bool ecdsaVerify({
  required ECDomainParameters domain,
  required ECPoint publicPoint,
  required Digest digest,
  required List<int> data,
  required BigInt r,
  required BigInt s,
}) {
  final signer = ECDSASigner(digest)
    ..init(
      false,
      PublicKeyParameter<ECPublicKey>(ECPublicKey(publicPoint, domain)),
    );
  return signer.verifySignature(Uint8List.fromList(data), ECSignature(r, s));
}
