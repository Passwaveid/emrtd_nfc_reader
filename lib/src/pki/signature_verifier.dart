// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/OpenSSLUtils.swift:440-550
//   (`verifySignature`), the passive-authentication slice. The Active
//   Authentication slice of the same function lives in
//   `proto/active_authentication.dart` and is untouched here: upstream's
//   missing RIPEMD-160 arm stays preserved there, while upstream's digest
//   dispatch is fixed here. Different call paths, opposite stances.
//
//   Not ported: the ECDSA `r`/`s` leading-zero repair block (:456-520).
//   Upstream re-encodes the DER to strip invalid leading `0x00` octets so
//   `d2i_ECDSA_SIG` accepts it; this decoder accepts non-minimal INTEGERs
//   outright, which is the same observable tolerance by a simpler mechanism.

/// The passive-authentication signature verifier.
///
/// **Explicit allowlist, never SOD-driven dispatch**. Upstream picks a digest
/// by lowercase substring match on the algorithm's OpenSSL long name and
/// *defaults to SHA-256*, so a SHA-384 PSS document fails, an unsupported
/// algorithm reports a bare failure instead of "unsupported", and a
/// plain-`rsaEncryption` SignerInfo only verifies in its SHA-256 form. Here an
/// unrecognized algorithm resolves to `null`, which the verdict layer turns
/// into `unverifiable`/`unsupported_algorithm`.
///
/// Accepted (the server-side verifier's map, adopted verbatim):
/// - RSA PKCS#1 v1.5: `sha{1,224,256,384,512}WithRSAEncryption`, plus plain
///   `rsaEncryption` with the digest taken from the SignerInfo's
///   `digestAlgorithm` (the RFC 3370 §3.2 form).
/// - RSASSA-PSS: **params-driven** per RFC 4055; hash, MGF1 digest, salt
///   length and trailer all read from `RSASSA-PSS-params`.
/// - ECDSA: `ecdsa-with-SHA{1,224,256,384,512}` over whatever curve the
///   shared SPKI parser produced a key for (the server-side verifier
///   enforces no curve set either; the port's set is that parser's
///   registered curves plus its explicit-params arm).
///
/// SHA-1 and SHA-224 **verify** (upstream accepts them silently); the
/// caller adds the dart-only `weakDigest` annotation from
/// [ResolvedSignatureAlgorithm.weakDigest].
///
/// Internal: not exported from the barrel.
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart'
    show
        Digest,
        PublicKeyParameter,
        SecureRandom,
        ParametersWithSaltConfiguration;
import 'package:pointycastle/asymmetric/api.dart'
    show PSSSignature, RSAPublicKey, RSASignature;
import 'package:pointycastle/asymmetric/rsa.dart' show RSAEngine;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/signers/pss_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

import '../crypto/ecdsa.dart';
import '../lds/subject_public_key_info.dart';
import 'asn1_reader.dart';

/// Which mechanism the algorithm selected.
enum PkiSignatureScheme {
  rsaPkcs1,
  rsaPss,
  ecdsa;

  /// The wire name the verdict surface reports (`SodSignatureCheck`).
  String get wireName => switch (this) {
    PkiSignatureScheme.rsaPkcs1 => 'rsa_pkcs1',
    PkiSignatureScheme.rsaPss => 'rsa_pss',
    PkiSignatureScheme.ecdsa => 'ecdsa',
  };
}

/// A signature algorithm the allowlist accepted, fully resolved.
class ResolvedSignatureAlgorithm {
  const ResolvedSignatureAlgorithm({
    required this.scheme,
    required this.digestName,
    this.mgfDigestName,
    this.saltLength,
  });

  final PkiSignatureScheme scheme;

  /// `SHA1` | `SHA224` | `SHA256` | `SHA384` | `SHA512`: the spelling
  /// `crypto/hashes.dart` and the SOD hash oracle already use.
  final String digestName;

  /// PSS only: the MGF1 digest (RFC 4055 allows it to differ from the
  /// content digest).
  final String? mgfDigestName;

  /// PSS only: the declared salt length in octets.
  final int? saltLength;

  /// The dart-only `weakDigest` annotation trigger. Does **not** change the
  /// accept/reject outcome: upstream accepts these silently.
  bool get weakDigest => digestName == 'SHA1' || digestName == 'SHA224';
}

// --- OID tables (the allowlist) ---------------------------------------------

const String oidRsaEncryption = '1.2.840.113549.1.1.1';
const String oidRsassaPss = '1.2.840.113549.1.1.10';
const String oidMgf1 = '1.2.840.113549.1.1.8';

/// Digest OIDs -> the port's digest names. Exactly the five SHA-2 family
/// members `calcHash` dispatches on (the SOD hash oracle's strict map,
/// reused).
const Map<String, String> digestOidNames = {
  '1.3.14.3.2.26': 'SHA1',
  '2.16.840.1.101.3.4.2.4': 'SHA224',
  '2.16.840.1.101.3.4.2.1': 'SHA256',
  '2.16.840.1.101.3.4.2.2': 'SHA384',
  '2.16.840.1.101.3.4.2.3': 'SHA512',
};

/// RSA PKCS#1 v1.5 signature OIDs -> digest name.
const Map<String, String> _rsaPkcs1SignatureOids = {
  '1.2.840.113549.1.1.5': 'SHA1',
  '1.2.840.113549.1.1.14': 'SHA224',
  '1.2.840.113549.1.1.11': 'SHA256',
  '1.2.840.113549.1.1.12': 'SHA384',
  '1.2.840.113549.1.1.13': 'SHA512',
};

/// ECDSA signature OIDs -> digest name.
const Map<String, String> _ecdsaSignatureOids = {
  '1.2.840.10045.4.1': 'SHA1',
  '1.2.840.10045.4.3.1': 'SHA224',
  '1.2.840.10045.4.3.2': 'SHA256',
  '1.2.840.10045.4.3.3': 'SHA384',
  '1.2.840.10045.4.3.4': 'SHA512',
};

/// PKCS#1 v1.5 `DigestInfo` prefixes pointycastle's [RSASigner] wants as a
/// hex string (its own table is private; these are the same values).
const Map<String, String> _digestInfoOids = {
  'SHA1': '06052b0e03021a',
  'SHA224': '0609608648016503040204',
  'SHA256': '0609608648016503040201',
  'SHA384': '0609608648016503040202',
  'SHA512': '0609608648016503040203',
};

/// Resolves a signature `AlgorithmIdentifier` against the allowlist.
///
/// [parameters] is the raw DER of the `parameters` field (the whole element),
/// `null` when absent. [signerDigestOid] is the SignerInfo's
/// `digestAlgorithm` OID: consulted **only** for the plain-`rsaEncryption`
/// form, whose AlgorithmIdentifier carries no digest of its own; certificate
/// signatures pass `null`.
///
/// Returns `null` for anything not on the list: DSA, EdDSA, an unknown OID, a
/// PSS configuration outside RFC 4055's profile (non-MGF1 mask, trailer ≠ 1,
/// an unsupported hash), or `rsaEncryption` with no usable SignerInfo digest.
ResolvedSignatureAlgorithm? resolveSignatureAlgorithm({
  required String signatureAlgorithmOid,
  List<int>? parameters,
  String? signerDigestOid,
}) {
  final pkcs1 = _rsaPkcs1SignatureOids[signatureAlgorithmOid];
  if (pkcs1 != null) {
    return ResolvedSignatureAlgorithm(
      scheme: PkiSignatureScheme.rsaPkcs1,
      digestName: pkcs1,
    );
  }
  final ecdsa = _ecdsaSignatureOids[signatureAlgorithmOid];
  if (ecdsa != null) {
    return ResolvedSignatureAlgorithm(
      scheme: PkiSignatureScheme.ecdsa,
      digestName: ecdsa,
    );
  }
  if (signatureAlgorithmOid == oidRsaEncryption) {
    // RFC 3370 §3.2: the digest comes from the SignerInfo. Upstream's
    // substring dispatch lands this on its SHA-256 default, so only the
    // SHA-256 form verifies there.
    final digest = signerDigestOid == null
        ? null
        : digestOidNames[signerDigestOid];
    if (digest == null) {
      return null;
    }
    return ResolvedSignatureAlgorithm(
      scheme: PkiSignatureScheme.rsaPkcs1,
      digestName: digest,
    );
  }
  if (signatureAlgorithmOid == oidRsassaPss) {
    return _resolvePssParameters(parameters);
  }
  return null; // DSA, EdDSA, anything else
}

/// RFC 4055 `RSASSA-PSS-params`, all four fields DEFAULTed as the RFC
/// specifies (`sha1`, `mgf1SHA1`, salt 20, trailer 1).
ResolvedSignatureAlgorithm? _resolvePssParameters(List<int>? parameters) {
  var hash = 'SHA1';
  var mgfHash = 'SHA1';
  var saltLength = 20;

  if (parameters != null && parameters.isNotEmpty) {
    final root = parseAsn1(
      parameters is Uint8List ? parameters : Uint8List.fromList(parameters),
    );
    if (root == null) {
      return null;
    }
    if (root.tag == Asn1Tag.nullTag) {
      // Absent-equivalent: every field takes its DEFAULT.
      return const ResolvedSignatureAlgorithm(
        scheme: PkiSignatureScheme.rsaPss,
        digestName: 'SHA1',
        mgfDigestName: 'SHA1',
        saltLength: 20,
      );
    }
    if (root.tag != Asn1Tag.sequence) {
      return null;
    }
    for (final field in root.children ?? const <Asn1Node>[]) {
      final inner = field.child(0);
      switch (field.tag) {
        case 0xA0: // hashAlgorithm
          final name = digestOidNames[oidOf(inner?.child(0)) ?? ''];
          if (inner == null || inner.tag != Asn1Tag.sequence || name == null) {
            return null;
          }
          hash = name;
        case 0xA1: // maskGenAlgorithm: MGF1 only
          if (inner == null ||
              inner.tag != Asn1Tag.sequence ||
              oidOf(inner.child(0)) != oidMgf1) {
            return null; // a non-MGF1 mask is unsupported, not invalid
          }
          final mgfParams = inner.child(1);
          final name = digestOidNames[oidOf(mgfParams?.child(0)) ?? ''];
          if (mgfParams == null ||
              mgfParams.tag != Asn1Tag.sequence ||
              name == null) {
            return null;
          }
          mgfHash = name;
        case 0xA2: // saltLength
          final v = integerOf(inner);
          if (v == null || v.isNegative || v > BigInt.from(512)) {
            return null;
          }
          saltLength = v.toInt();
        case 0xA3: // trailerField: must be 1 (trailerFieldBC, 0xBC)
          final v = integerOf(inner);
          if (v != BigInt.one) {
            return null; // another trailer is unsupported, not invalid
          }
        default:
          return null;
      }
    }
  }
  return ResolvedSignatureAlgorithm(
    scheme: PkiSignatureScheme.rsaPss,
    digestName: hash,
    mgfDigestName: mgfHash,
    saltLength: saltLength,
  );
}

/// Verifies [signature] over [data] with [key] under [algorithm].
///
/// Total: a key that does not match the scheme, a malformed signature
/// encoding, an out-of-range value or a key too small for the declared PSS
/// parameters all return `false`, the outcome the verdict layer reports as
/// `bad_ds_signature`, never a throw.
bool verifyPkiSignature({
  required SubjectPublicKey key,
  required ResolvedSignatureAlgorithm algorithm,
  required List<int> data,
  required List<int> signature,
}) {
  try {
    switch (algorithm.scheme) {
      case PkiSignatureScheme.rsaPkcs1:
        if (key is! SpkiRsaPublicKey) {
          return false;
        }
        return _verifyRsaPkcs1(key, algorithm.digestName, data, signature);
      case PkiSignatureScheme.rsaPss:
        if (key is! SpkiRsaPublicKey) {
          return false;
        }
        return _verifyRsaPss(key, algorithm, data, signature);
      case PkiSignatureScheme.ecdsa:
        if (key is! SpkiEcPublicKey) {
          return false;
        }
        final rs = decodeEcdsaDerSignature(signature);
        if (rs == null) {
          return false;
        }
        return ecdsaVerify(
          domain: key.domain,
          publicPoint: key.point,
          digest: digestFor(algorithm.digestName)!,
          data: data,
          r: rs.$1,
          s: rs.$2,
        );
    }
  } on ArgumentError {
    // Key too small for the declared PSS salt/hash, an unusable RSA block, a
    // range violation (RangeError is an ArgumentError): all "did not verify".
    return false;
  } on StateError {
    return false;
  }
}

bool _verifyRsaPkcs1(
  SpkiRsaPublicKey key,
  String digestName,
  List<int> data,
  List<int> signature,
) {
  final digestInfoOid = _digestInfoOids[digestName];
  final digest = digestFor(digestName);
  if (digestInfoOid == null || digest == null) {
    return false;
  }
  final signer = RSASigner(digest, digestInfoOid)
    ..init(
      false,
      PublicKeyParameter<RSAPublicKey>(RSAPublicKey(key.modulus, key.exponent)),
    );
  return signer.verifySignature(
    Uint8List.fromList(data),
    RSASignature(Uint8List.fromList(signature)),
  );
}

bool _verifyRsaPss(
  SpkiRsaPublicKey key,
  ResolvedSignatureAlgorithm algorithm,
  List<int> data,
  List<int> signature,
) {
  final contentDigest = digestFor(algorithm.digestName);
  final mgfDigest = digestFor(algorithm.mgfDigestName ?? algorithm.digestName);
  if (contentDigest == null || mgfDigest == null) {
    return false;
  }
  // `ParametersWithSaltConfiguration` demands a `SecureRandom` even for
  // verification (it is only read when *generating* a salt); the salt itself
  // is recovered from EM at the params-declared length.
  final signer = PSSSigner(RSAEngine(), contentDigest, mgfDigest)
    ..init(
      false,
      ParametersWithSaltConfiguration(
        PublicKeyParameter<RSAPublicKey>(
          RSAPublicKey(key.modulus, key.exponent),
        ),
        _unusedRandom,
        algorithm.saltLength ?? contentDigest.digestSize,
      ),
    );
  return signer.verifySignature(
    Uint8List.fromList(data),
    PSSSignature(Uint8List.fromList(signature)),
  );
}

/// `Digest` for one of the five names, or `null`.
Digest? digestFor(String name) => switch (name) {
  'SHA1' => SHA1Digest(),
  'SHA224' => SHA224Digest(),
  'SHA256' => SHA256Digest(),
  'SHA384' => SHA384Digest(),
  'SHA512' => SHA512Digest(),
  _ => null,
};

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279 §2.2.3).
///
/// **Lenient about non-minimal INTEGER encodings**: upstream actively
/// repairs signatures whose `r`/`s` carry invalid leading `0x00` octets
/// (OpenSSLUtils.swift:456-520) so malformed-but-fielded documents verify;
/// this decoder simply accepts them. Negative values are rejected: no valid
/// `r`/`s` is negative, and `ECDSA_do_verify` fails them too.
(BigInt, BigInt)? decodeEcdsaDerSignature(List<int> der) {
  final bytes = der is Uint8List ? der : Uint8List.fromList(der);
  final root = parseAsn1(bytes);
  if (root == null ||
      root.tag != Asn1Tag.sequence ||
      root.end != bytes.length ||
      root.childCount != 2) {
    return null;
  }
  final rNode = root.child(0)!;
  final sNode = root.child(1)!;
  if (rNode.tag != Asn1Tag.integer || sNode.tag != Asn1Tag.integer) {
    return null;
  }
  final r = decodeIntegerContent(rNode.content);
  final s = decodeIntegerContent(sNode.content);
  if (r == null || s == null || r.isNegative || s.isNegative) {
    return null;
  }
  return (r, s);
}

/// A `SecureRandom` that is never read (see [_verifyRsaPss]); it exists only
/// to satisfy `ParametersWithSaltConfiguration`'s constructor.
final SecureRandom _unusedRandom = _NeverRandom();

class _NeverRandom implements SecureRandom {
  @override
  String get algorithmName => 'NeverRandom';

  Never _unused() =>
      throw StateError('PSS verification must never draw random bytes');

  @override
  int nextUint8() => _unused();

  @override
  int nextUint16() => _unused();

  @override
  int nextUint32() => _unused();

  @override
  BigInt nextBigInteger(int bitLength) => _unused();

  @override
  Uint8List nextBytes(int count) => _unused();

  @override
  void seed(covariant Object params) {}
}
