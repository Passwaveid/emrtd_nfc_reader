// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/OpenSSLUtils.swift:159-223
//   (`verifyTrustAndGetIssuerCertificate`), its trust-material half. Upstream
//   hands a PEM *file path* to `X509_LOOKUP_file`/`X509_L_FILE_LOAD` and lets
//   OpenSSL own the store; the port models the store explicitly so it can be
//   built once and reused off the NFC path. Path building itself lives in
//   `passive_auth.dart`.
//
//   The signed-`.ml` arm has no upstream analogue at all (upstream reads plain
//   PEM only); it ports the ingest semantics of the server-side verifier
//   this package was built alongside: verify-signature-first, then signer
//   pinning, with an explicit `allowUnpinned` escape hatch mirroring that
//   ingester's own opt-out flag.

/// The CSCA trust store: the anchors DSC->CSCA path building runs against.
///
/// Two ingestion paths:
/// - [CscaTrustStore.fromPem], a PEM concatenation, upstream's format (its
///   720-certificate `masterList.pem` example fixture loads verbatim).
/// - [CscaTrustStore.fromSignedMasterList], an ICAO 9303-12 §9 CSCA master
///   list: a CMS `SignedData` with eContentType `2.23.136.1.1.2` whose
///   eContent is `CscaMasterList ::= SEQUENCE { version, SET OF Certificate }`.
///   Its **own signature is verified first**, then the signer is pinned.
///
/// The package **never bundles a list**: which lists ship, how often they
/// refresh, and what "read OK but unverifiable" means to a user are product
/// decisions. The store ingests what it is given.
///
/// **Cost**: parsing 1.5 MB of PEM or a signed `.ml` plus a signature
/// verify is heavyweight and fully synchronous. Build the store **off the NFC
/// path**, at app startup or in an isolate, and reuse it; lookups
/// afterwards are indexed and cheap.
///
/// Ingestion failures throw ([MasterListException] family) because they are
/// construction-time input errors; *verification* never throws.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/hashes.dart';
import '../logging.dart';
import 'asn1_reader.dart';
import 'cms_signed_data.dart';
import 'signature_verifier.dart';
import 'x509_certificate.dart';

/// Why a trust-store ingestion failed. Construction-time only.
sealed class MasterListException implements Exception {
  const MasterListException(this.reason);

  /// Diagnostic detail: never user-facing copy.
  final String reason;

  /// Stable identifier for telemetry and conformance vectors.
  String get code;

  @override
  String toString() => '$code: $reason';
}

/// The bytes are not a CMS `SignedData`, or its eContent is not a
/// `CscaMasterList`.
final class MasterListParseException extends MasterListException {
  const MasterListParseException(super.reason);

  @override
  String get code => 'MasterListParseError';
}

/// eContentType is not `2.23.136.1.1.2` (id-icao-cscaMasterList).
final class MasterListContentTypeException extends MasterListException {
  const MasterListContentTypeException(super.reason);

  @override
  String get code => 'MasterListContentTypeError';
}

/// The list's own CMS signature did not verify (or its algorithm is not on
/// the signature-algorithm allowlist).
final class MasterListSignatureException extends MasterListException {
  const MasterListSignatureException(super.reason);

  @override
  String get code => 'MasterListSignatureError';
}

/// The signer is not the pinned one and [CscaTrustStore.fromSignedMasterList]
/// was not given `allowUnpinned: true`.
final class MasterListPinningException extends MasterListException {
  const MasterListPinningException(super.reason);

  @override
  String get code => 'MasterListPinningError';
}

/// What a signed `.ml` ingestion learned about the list itself.
class MasterListInfo {
  const MasterListInfo({
    required this.eContentType,
    required this.version,
    required this.signerSubject,
    required this.signerFingerprintSha256,
    required this.signatureVerified,
    required this.pinned,
  });

  /// Always `2.23.136.1.1.2` for an accepted list (the check is a hard gate).
  final String eContentType;

  /// `CscaMasterList.version`.
  final int version;

  /// The Master List Signer certificate's subject DN.
  final String signerSubject;

  /// SHA-256 over the signer certificate's DER, lowercase hex.
  final String signerFingerprintSha256;

  /// Always true for an accepted list: verify-signature-first.
  final bool signatureVerified;

  /// Whether the signer matched `pinnedSignerDer` (directly or by chaining to
  /// it). False only when accepted via `allowUnpinned`.
  final bool pinned;
}

/// A set of trusted CSCA certificates, indexed for path building.
class CscaTrustStore {
  CscaTrustStore._(
    this._certificates,
    this.skippedCertificates,
    this.masterListInfo,
  ) {
    for (final cert in _certificates) {
      final ski = cert.subjectKeyIdentifier;
      if (ski != null) {
        (_bySki[_hex(ski)] ??= []).add(cert);
      }
      (_bySubject[cert.normalizedSubject] ??= []).add(cert);
    }
  }

  final List<X509Certificate> _certificates;
  final Map<String, List<X509Certificate>> _bySki = {};
  final Map<String, List<X509Certificate>> _bySubject = {};

  /// How many certificates in the input could not be parsed and were skipped
  /// (tolerant reader: one bad entry never costs the whole list).
  final int skippedCertificates;

  /// Non-null only for [CscaTrustStore.fromSignedMasterList].
  final MasterListInfo? masterListInfo;

  int get certificateCount => _certificates.length;

  /// The anchors, in ingestion order (deduped).
  List<X509Certificate> get certificates => List.unmodifiable(_certificates);

  /// Upstream's `X509_LOOKUP_file` + `X509_L_FILE_LOAD` path: a PEM
  /// concatenation. Unparseable blocks are skipped and counted; an input with
  /// no certificates at all yields an empty store (which makes every chain
  /// `unknown_csca`) rather than an error.
  factory CscaTrustStore.fromPem(String pem) {
    final (certs, skipped) = _dedupe(_parsePemCertificates(pem));
    passportReaderLog.fine(
      'CscaTrustStore.fromPem - ${certs.length} certificates, '
      '$skipped skipped',
    );
    return CscaTrustStore._(certs, skipped, null);
  }

  /// A DER trust store built straight from certificate DERs: the seam unit
  /// tests and the master-list arm share.
  factory CscaTrustStore.fromCertificates(Iterable<List<int>> derCertificates) {
    final (certs, skipped) = _dedupe([
      for (final der in derCertificates) X509Certificate.tryParse(der),
    ]);
    return CscaTrustStore._(certs, skipped, null);
  }

  /// ICAO 9303-12 §9 signed CSCA master list, with the ingest semantics of
  /// the server-side verifier.
  ///
  /// Order of operations, deliberately: eContentType gate -> **verify the
  /// list's own signature** -> pin the signer -> load `certList`. A list whose
  /// signature does not verify never contributes an anchor, whatever
  /// [allowUnpinned] says.
  ///
  /// [pinnedSignerDer] is the expected Master List Signer certificate. The
  /// signer matches when its DER fingerprint is identical, or when it chains
  /// directly to the pinned certificate (the issuer-rollover case). Passing
  /// `allowUnpinned: true` with no pin is the explicit escape hatch
  /// (`--allow-unpinned` in the server-side ingester) and is recorded as
  /// `masterListInfo.pinned == false`.
  ///
  /// Throws a [MasterListException] on every rejection.
  factory CscaTrustStore.fromSignedMasterList(
    List<int> masterList, {
    List<int>? pinnedSignerDer,
    bool allowUnpinned = false,
  }) {
    final parsed = CmsSignedData.parse(masterList);
    if (parsed is CmsMalformed) {
      throw MasterListParseException(parsed.reason);
    }
    final cms = (parsed as CmsParsed).data;

    if (cms.eContentType != oidCscaMasterList) {
      throw MasterListContentTypeException(
        'eContentType is ${cms.eContentType}, expected $oidCscaMasterList',
      );
    }
    final eContent = cms.eContent;
    if (eContent == null) {
      throw const MasterListParseException('master list carries no eContent');
    }
    if (cms.signerInfos.isEmpty) {
      throw const MasterListParseException('master list has no SignerInfo');
    }
    final signerInfo = cms.signerInfos.first;

    final signerCert = resolveSignerCertificate(cms, signerInfo);
    if (signerCert == null) {
      throw const MasterListParseException(
        'master list carries no usable signer certificate',
      );
    }

    // --- verify the list's own signature first, with the shared CMS check.
    final signatureCheck = verifyCmsSignature(
      cms: cms,
      signerInfo: signerInfo,
      signerCertificate: signerCert,
    );
    if (!signatureCheck.valid) {
      throw MasterListSignatureException(signatureCheck.reason ?? 'invalid');
    }

    // --- signer pinning.
    var pinned = false;
    if (pinnedSignerDer != null) {
      final pin = X509Certificate.tryParse(pinnedSignerDer);
      if (pin == null) {
        throw const MasterListPinningException(
          'pinnedSignerDer is not a parseable certificate',
        );
      }
      pinned =
          pin.fingerprintSha256 == signerCert.fingerprintSha256 ||
          _chainsTo(signerCert, pin);
      if (!pinned && !allowUnpinned) {
        throw MasterListPinningException(
          'master list signer ${signerCert.subjectString} does not match '
          'the pinned signer ${pin.subjectString}',
        );
      }
    } else if (!allowUnpinned) {
      throw const MasterListPinningException(
        'no pinnedSignerDer given; pass allowUnpinned: true to accept an '
        'unpinned master list',
      );
    }

    // --- CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF ... }
    final root = parseAsn1(eContent);
    if (root == null ||
        root.tag != Asn1Tag.sequence ||
        root.childCount < 2 ||
        root.child(1)!.tag != Asn1Tag.set) {
      throw const MasterListParseException(
        'eContent is not a CscaMasterList SEQUENCE { version, SET OF }',
      );
    }
    final version = integerOf(root.child(0));
    if (version == null) {
      throw const MasterListParseException('CscaMasterList.version missing');
    }
    final (certs, skipped) = _dedupe([
      for (final c in root.child(1)!.children ?? const <Asn1Node>[])
        X509Certificate.tryParse(c.encoded),
    ]);

    passportReaderLog.fine(
      'CscaTrustStore.fromSignedMasterList - ${certs.length} certificates, '
      '$skipped skipped, pinned=$pinned',
    );

    return CscaTrustStore._(
      certs,
      skipped,
      MasterListInfo(
        eContentType: cms.eContentType,
        version: version.toInt(),
        signerSubject: signerCert.subjectString,
        signerFingerprintSha256: signerCert.fingerprintSha256,
        signatureVerified: true,
        pinned: pinned,
      ),
    );
  }

  /// Candidate issuers for [cert], SKI-first then issuer-DN (the lookup rule
  /// of the server-side verifier's `DbCscaProvider`). Order is AKI->SKI
  /// matches, then DN matches not already listed.
  List<X509Certificate> candidateIssuers(X509Certificate cert) {
    final out = <X509Certificate>[];
    final seen = <String>{};
    void add(X509Certificate c) {
      if (seen.add(c.fingerprintSha256)) {
        out.add(c);
      }
    }

    final aki = cert.authorityKeyIdentifier;
    if (aki != null) {
      for (final c in _bySki[_hex(aki)] ?? const <X509Certificate>[]) {
        add(c);
      }
    }
    // DN matches: raw-DER equality first, then the normalized fallback
    // (OpenSSL's `X509_NAME_cmp` canonicalizes, so a case-differing DN must
    // still build a chain).
    final byDn = _bySubject[cert.normalizedIssuer] ?? const <X509Certificate>[];
    for (final c in byDn) {
      if (_sameBytes(c.subjectDer, cert.issuerDer)) {
        add(c);
      }
    }
    for (final c in byDn) {
      add(c);
    }
    return out;
  }

  /// Whether [cert] is itself an anchor in this store (by DER fingerprint):
  /// the test that ends path building, and so marks a DSC that is its own
  /// anchor.
  bool contains(X509Certificate cert) =>
      _certificates.any((c) => c.fingerprintSha256 == cert.fingerprintSha256);
}

/// True when [cert] is directly signed by [issuer], the pinning helper's
/// one-hop chain test.
bool _chainsTo(X509Certificate cert, X509Certificate issuer) {
  final key = issuer.publicKey;
  if (key == null) {
    return false;
  }
  final alg = resolveSignatureAlgorithm(
    signatureAlgorithmOid: cert.signatureAlgorithmOid,
    parameters: cert.signatureAlgorithmParameters,
  );
  if (alg == null) {
    return false;
  }
  return verifyPkiSignature(
    key: key,
    algorithm: alg,
    data: cert.tbsDer,
    signature: cert.signature,
  );
}

/// The certificate a `SignerInfo` names.
///
/// Upstream always takes `certs[0]` (`SOD.swift:96`, `X509_get_pubkey`) and
/// crashes when the set is empty. The port resolves the SignerIdentifier
/// properly and falls back to the first certificate, which is the same answer
/// on every Doc 9303-conforming SOD (exactly one DSC) and the *correct* answer
/// on a master list, whose certificate set carries the signer alongside its
/// CSCA.
X509Certificate? resolveSignerCertificate(
  CmsSignedData cms,
  CmsSignerInfo signerInfo,
) {
  final parsed = <X509Certificate>[];
  for (final der in cms.certificates) {
    final cert = X509Certificate.tryParse(der);
    if (cert != null) {
      parsed.add(cert);
    }
  }
  if (parsed.isEmpty) {
    return null; // upstream force-unwraps here and crashes
  }
  switch (signerInfo.signerId) {
    case CmsIssuerAndSerial(:final issuerDer, :final serialNumber):
      for (final c in parsed) {
        if (c.serialNumber == serialNumber &&
            _sameBytes(c.issuerDer, issuerDer)) {
          return c;
        }
      }
    case CmsSubjectKeyIdentifier(:final keyIdentifier):
      for (final c in parsed) {
        final ski = c.subjectKeyIdentifier;
        if (ski != null && _sameBytes(ski, keyIdentifier)) {
          return c;
        }
      }
  }
  return parsed.first;
}

/// The outcome of the shared CMS signature check.
class CmsSignatureCheck {
  const CmsSignatureCheck({required this.valid, this.algorithm, this.reason});

  final bool valid;
  final ResolvedSignatureAlgorithm? algorithm;

  /// Diagnostic reason when [valid] is false; `null` on success.
  final String? reason;
}

/// Verifies one `SignerInfo` against [signerCertificate]: `hash(eContent) ==
/// messageDigest` attribute, then the signature over the `A0`->`31` signed
/// attributes (RFC 5652 §5.4).
///
/// Structural prerequisites (signed attributes present, mandatory attributes
/// present, the content-type attribute matching) are the caller's gate;
/// they map to `malformed_sod`, not to a bad signature.
CmsSignatureCheck verifyCmsSignature({
  required CmsSignedData cms,
  required CmsSignerInfo signerInfo,
  required X509Certificate signerCertificate,
}) {
  final algorithm = resolveSignatureAlgorithm(
    signatureAlgorithmOid: signerInfo.signatureAlgorithmOid,
    parameters: signerInfo.signatureAlgorithmParameters,
    signerDigestOid: signerInfo.digestAlgorithmOid,
  );
  if (algorithm == null) {
    return const CmsSignatureCheck(
      valid: false,
      reason: 'unsupported signature algorithm',
    );
  }
  final digestName = digestOidNames[signerInfo.digestAlgorithmOid];
  final eContent = cms.eContent;
  final messageDigest = signerInfo.messageDigestAttribute;
  final signedAttrs = signerInfo.signedAttributesForVerification;
  if (digestName == null) {
    return CmsSignatureCheck(
      valid: false,
      algorithm: algorithm,
      reason:
          'unsupported digest algorithm '
          '${signerInfo.digestAlgorithmOid}',
    );
  }
  if (eContent == null || messageDigest == null || signedAttrs == null) {
    return CmsSignatureCheck(
      valid: false,
      algorithm: algorithm,
      reason: 'missing eContent, messageDigest attribute or signedAttrs',
    );
  }
  if (!_sameBytes(calcHash(eContent, digestName), messageDigest)) {
    return CmsSignatureCheck(
      valid: false,
      algorithm: algorithm,
      reason: "messageDigest attribute doesn't match hash(eContent)",
    );
  }
  final key = signerCertificate.publicKey;
  if (key == null) {
    return CmsSignatureCheck(
      valid: false,
      algorithm: algorithm,
      reason: 'signer certificate carries an unusable public key',
    );
  }
  final ok = verifyPkiSignature(
    key: key,
    algorithm: algorithm,
    data: signedAttrs,
    signature: signerInfo.signature,
  );
  return CmsSignatureCheck(
    valid: ok,
    algorithm: algorithm,
    reason: ok ? null : 'signature over the signed attributes did not verify',
  );
}

// --- helpers ---------------------------------------------------------------

/// `(kept, skipped)`: deduped by SHA-256 fingerprint, nulls counted skipped.
(List<X509Certificate>, int) _dedupe(List<X509Certificate?> parsed) {
  final out = <X509Certificate>[];
  final seen = <String>{};
  var skipped = 0;
  for (final cert in parsed) {
    if (cert == null) {
      skipped++;
      continue;
    }
    if (seen.add(cert.fingerprintSha256)) {
      out.add(cert);
    }
  }
  return (out, skipped);
}

final RegExp _pemBlock = RegExp(
  r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*?)-----END CERTIFICATE-----',
);

List<X509Certificate?> _parsePemCertificates(String pem) {
  final out = <X509Certificate?>[];
  for (final match in _pemBlock.allMatches(pem)) {
    final body = match.group(1)!.replaceAll(RegExp(r'\s'), '');
    Uint8List der;
    try {
      der = base64.decode(body);
    } on FormatException {
      out.add(null); // unparseable block, skipped and counted
      continue;
    }
    out.add(X509Certificate.tryParse(der));
  }
  return out;
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
