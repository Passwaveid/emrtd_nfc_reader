// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/NFCPassportModel.swift:301-384
//   (`verifyActiveAuthentication`) with the two OpenSSLUtils helpers it calls
//   folded in (`decryptRSASignature` :350-377, `verifyECDSASignature` +
//   `verifySignature` :410-549), as the PACE and Chip Authentication ports
//   do with theirs. Upstream houses this on `NFCPassportModel`, which the
//   port deliberately does not have; a pure function is the established
//   substitute (`sod_hash_oracle.dart` precedent), placed beside
//   `chip_authentication.dart`.
//
//   Not ported (no observable effect): the plain->DER re-encode via
//   `ECDSA_SIG_set0`/`i2d_ECDSA_SIG` and the leading-zero "fix" block at
//   :456-520; the DER it inspects was just produced by `i2d_ECDSA_SIG` and
//   always re-parses; this verifier consumes `r`/`s` directly. Upstream's
//   recording of challenge/signature on the model becomes the reader's
//   `PassportReadResult` fields.

/// Active Authentication verification, ICAO 9303-11 §6.1.
///
/// The chip signs an 8-byte terminal challenge with the private half of the
/// DG15 key; this function checks the signature. It is **total**: every
/// failure (no usable DG15 key, a rejected RSA decrypt, an unknown ISO 9796-2
/// trailer, a bad hash, a bad ECDSA pair) comes back as
/// `passed: false`, mirroring upstream's guard-and-return-bool shape. It
/// never throws.
///
/// Quirks preserved verbatim, each pinned by a vector:
/// - **the RSA recovery parse is loose**: exactly one header byte is skipped
///   and never validated (no `6A`/`4A` check, no ISO 9796-2 padding checks),
///   so this is *not* a conformant 9796-2 verification;
/// - **trailer aliases**: `0xBC` and `0x33`(‖`CC`) both select SHA-1;
/// - **digest defaulting**: an empty or unrecognized ECDSA signature-algorithm
///   name falls to SHA-256, including `ecdsa-plain-RIPEMD160`, which
///   [ActiveAuthenticationInfo] itself maps, so a legitimately-signed
///   RIPEMD-160 chip always fails;
/// - **first AA-info wins** when DG14 carries several;
/// - **odd-length plain signature**: floor split, last byte silently dropped.
///
/// Deviations: the `RSA_public_decrypt` error path returns `null` at the
/// crypto seam instead of upstream's silently-zeroed buffer (same `failed`
/// outcome), and the small-modulus underflow is guarded where upstream
/// crashes on a negative range. A zero-length ECDSA signature is likewise
/// answered `failed` rather than crashing on `baseAddress!`.
library;

import 'package:pointycastle/api.dart' show Digest;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart';

import '../crypto/ec_dh.dart';
import '../crypto/ecdsa.dart';
import '../crypto/hashes.dart';
import '../crypto/rsa.dart';
import '../lds/active_authentication_info.dart';
import '../lds/data_group14.dart';
import '../lds/data_group15.dart';
import '../lds/subject_public_key_info.dart';
import '../logging.dart';

/// Which signature scheme the DG15 key selected.
enum AaScheme { rsa, ecdsa }

/// The outcome of [verifyActiveAuthentication].
class ActiveAuthenticationVerdict {
  const ActiveAuthenticationVerdict({
    required this.passed,
    this.scheme,
    this.digestAlgorithm,
  });

  /// Upstream `activeAuthenticationPassed`.
  final bool passed;

  /// `null` when DG15 carried no usable key, upstream's guard path, where
  /// neither branch runs at all.
  final AaScheme? scheme;

  /// The digest the verification actually used (`SHA1`...`SHA512`): for RSA
  /// the one the ISO 9796-2 trailer named, for ECDSA the one the digest chain
  /// selected. `null` when no digest was ever chosen (keyless DG15, rejected
  /// decrypt, unknown trailer). Diagnostic only: no upstream analogue.
  final String? digestAlgorithm;
}

/// Upstream `NFCPassportModel.verifyActiveAuthentication(challenge:signature:)`.
ActiveAuthenticationVerdict verifyActiveAuthentication({
  required DataGroup15 dg15,
  DataGroup14? dg14,
  required List<int> challenge,
  required List<int> signature,
}) {
  switch (dg15.publicKey) {
    case SpkiRsaPublicKey(:final modulus, :final exponent):
      return _verifyRsa(
        modulus: modulus,
        exponent: exponent,
        challenge: challenge,
        signature: signature,
      );
    case SpkiEcPublicKey(:final domain, :final point):
      return _verifyEcdsa(
        domain: domain,
        point: point,
        dg14: dg14,
        challenge: challenge,
        signature: signature,
      );
    case _:
      // Upstream's `guard let dg15 ... else { return }` / neither-key-set path:
      // activeAuthenticationPassed stays false.
      return const ActiveAuthenticationVerdict(passed: false);
  }
}

/// ISO 9796-2 trailer byte -> (hash name, digest length). ISO/IEC 10118-3
/// dedicated-hash-function numbering, upstream's table verbatim, including
/// the `0x33` SHA-1 alias.
const Map<int, (String, int)> _trailerHashes = {
  0xBC: ('SHA1', 20), // 160 bits for SHA-1 -> 20 bytes
  0x33: ('SHA1', 20),
  0x34: ('SHA256', 32),
  0x35: ('SHA512', 64),
  0x36: ('SHA384', 48),
  0x38: ('SHA224', 28),
};

ActiveAuthenticationVerdict _verifyRsa({
  required BigInt modulus,
  required BigInt exponent,
  required List<int> challenge,
  required List<int> signature,
}) {
  final decrypted = rsaPublicDecryptRaw(
    modulus: modulus,
    exponent: exponent,
    signature: signature,
  );
  if (decrypted == null) {
    // Upstream misses RSA_public_decrypt's -1 and walks a zero buffer, which
    // dies at the trailer switch below, the same `failed` outcome.
    passportReaderLog.severe(
      'Error verifying Active Authentication RSA signature - '
      'RSA_public_decrypt rejected the signature',
    );
    return const ActiveAuthenticationVerdict(
      passed: false,
      scheme: AaScheme.rsa,
    );
  }

  // Decrypted signature compromises of header (6A), Message, Digest hash,
  // Trailer. Trailer can be 1 byte (BC - SHA-1 hash) or 2 bytes (xxCC) -
  // where xx identifies the hash algorithm used (upstream comment).
  final sig = decrypted.toList();
  var hashTypeByte = sig.isEmpty ? 0x00 : sig.removeLast(); // popLast() ?? 0
  if (hashTypeByte == 0xCC) {
    hashTypeByte = sig.isEmpty ? 0x00 : sig.removeLast();
  }
  final entry = _trailerHashes[hashTypeByte];
  if (entry == null) {
    passportReaderLog.severe(
      'Error identifying Active Authentication RSA message '
      'digest hash algorithm',
    );
    return const ActiveAuthenticationVerdict(
      passed: false,
      scheme: AaScheme.rsa,
    );
  }
  final (hashType, hashLength) = entry;

  // Guard: upstream slices `decryptedSig[1 ..< count-hashLength]`, a
  // negative range, and a crash, whenever the (chip-supplied, at this point
  // unverified) modulus is smaller than hashLength + 2 bytes. The boundary
  // `count - hashLength == 1` is legal on both sides and recovers an empty
  // message.
  if (sig.length - hashLength < 1) {
    passportReaderLog.severe(
      'Error verifying Active Authentication RSA signature '
      '- recovered block too short for a $hashType digest',
    );
    return ActiveAuthenticationVerdict(
      passed: false,
      scheme: AaScheme.rsa,
      digestAlgorithm: hashType,
    );
  }

  // Exactly one header byte skipped, never validated.
  final message = sig.sublist(1, sig.length - hashLength);
  final digest = sig.sublist(sig.length - hashLength);

  // Concatenate the challenge to the end of the message (upstream comment).
  final fullMsg = <int>[...message, ...challenge];
  final msgHash = calcHash(fullMsg, hashType);

  final passed = _constEq(msgHash, digest);
  if (passed) {
    passportReaderLog.fine('Active Authentication (RSA) successful');
  } else {
    passportReaderLog.severe(
      'Error verifying Active Authentication RSA signature '
      "- Hash doesn't match",
    );
  }
  return ActiveAuthenticationVerdict(
    passed: passed,
    scheme: AaScheme.rsa,
    digestAlgorithm: hashType,
  );
}

ActiveAuthenticationVerdict _verifyEcdsa({
  required ECDomainParameters domain,
  required ECPoint point,
  required DataGroup14? dg14,
  required List<int> challenge,
  required List<int> signature,
}) {
  // Upstream: the FIRST ActiveAuthenticationInfo in DG14, its friendly name,
  // or "" (no DG14, no AA-info, or an unmapped sigAlg OID).
  var digestType = '';
  final aaInfo = dg14?.securityInfos.whereType<ActiveAuthenticationInfo>();
  if (aaInfo != null && aaInfo.isNotEmpty) {
    digestType = aaInfo.first.getSignatureAlgorithmOIDString() ?? '';
  }
  final (digestName, digest) = _digestFor(digestType);

  // PLAIN ECDSA: r ‖ s, split at count/2; an odd-length signature silently
  // drops its last byte.
  final l = signature.length ~/ 2;
  final r = bytesToBigInt(signature.sublist(0, l));
  final s = bytesToBigInt(signature.sublist(l, 2 * l));

  final passed = ecdsaVerify(
    domain: domain,
    publicPoint: point,
    digest: digest,
    data: challenge,
    r: r,
    s: s,
  );
  if (passed) {
    passportReaderLog.fine('Active Authentication (ECDSA) successful');
  } else {
    passportReaderLog.severe(
      'Error verifying Active Authentication ECDSA signature',
    );
  }
  return ActiveAuthenticationVerdict(
    passed: passed,
    scheme: AaScheme.ecdsa,
    digestAlgorithm: digestName,
  );
}

/// Upstream `OpenSSLUtils.verifySignature`'s digest selection: lowercase, then
/// a `contains` chain, **defaulting to SHA-256**. The `rsassapss` arm of that
/// chain shares the SHA-256 default and no `ecdsa-plain-*` name contains it,
/// so it is folded in; there is no `ripemd160` arm.
(String, Digest) _digestFor(String digestType) {
  final name = digestType.toLowerCase();
  if (name.contains('sha1')) {
    return ('SHA1', SHA1Digest());
  } else if (name.contains('sha224')) {
    return ('SHA224', SHA224Digest());
  } else if (name.contains('sha256') || name.contains('rsassapss')) {
    return ('SHA256', SHA256Digest());
  } else if (name.contains('sha384')) {
    return ('SHA384', SHA384Digest());
  } else if (name.contains('sha512')) {
    return ('SHA512', SHA512Digest());
  }
  // The default arm: anything unrecognized, "" included, and
  // ecdsa-plain-RIPEMD160, which has no arm at all.
  return ('SHA256', SHA256Digest());
}

/// Length-then-byte comparison. Constant-time is not a requirement here (both
/// operands are public), but the loop avoids the early exit anyway.
bool _constEq(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
