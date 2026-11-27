// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/NFCPassportModel.swift:285-299
//   (`verifyPassport`), :404-426 (`validateAndExtractSigningCertificates`) and
//   the signature half of :431-484 (`ensureReadDataNotBeenTamperedWith`), with
//   `OpenSSLUtils.verifyTrustAndGetIssuerCertificate` (:159-223) and
//   `verifyAndReturnSODEncapsulatedData` (:272-298) folded in, as the PACE,
//   Chip Authentication and Active Authentication ports fold in their OpenSSL
//   helpers. Upstream houses this on `NFCPassportModel`, which the port
//   deliberately does not have; pure functions are the established
//   substitute.
//
//   Not ported: `hasCertBeenRevoked` (:390-402, marked "NOT USED YET"
//   upstream and dead), the `useCMSVerification: true` branch (`CMS_verify`
//   with `CMS_NO_SIGNER_CERT_VERIFY`: the same check by another route), and
//   the hash comparison itself, which lives in `lds/sod_hash_oracle.dart` and
//   is reused verbatim.

/// On-device passive authentication: ICAO 9303-11 §5.1.
///
/// Three halves, composed into one verdict:
/// 1. **hashes**: the SOD hash oracle, reused as it is;
/// 2. **signature**: the SOD's CMS signature under the Document Signing
///    Certificate's key;
/// 3. **trust**: a DSC->CSCA path against a [CscaTrustStore].
///
/// The verdict vocabulary is shared verbatim with the server-side verifier
/// this package was built alongside, so an on-device result and a
/// server-side one are directly comparable:
/// outcomes `verified`/`invalid`/`unverifiable`, causes `dg_hash_mismatch`,
/// `bad_ds_signature`, `malformed_sod`, `unknown_csca`,
/// `expired_chain_element`, `unsupported_algorithm`, and the composable
/// `weak_digest` annotation. Precedence: **tamper > unsupported >
/// bad-signature > chain**.
///
/// **Nothing here throws**: hostile input becomes a verdict, where upstream
/// force-unwraps and crashes or silently swallows the error. Only trust-store
/// *construction* raises.
///
/// Upstream's three booleans stay computable from the result:
/// [PassiveAuthResult.passportDataNotTampered],
/// [PassiveAuthResult.documentSigningCertificateVerified] and
/// [PassiveAuthResult.passportCorrectlySigned].
library;

import '../lds/data_group.dart';
import '../lds/data_group_id.dart';
import '../lds/sod.dart';
import '../lds/sod_hash_oracle.dart';
import '../errors.dart';
import '../logging.dart';
import 'cms_signed_data.dart';
import 'csca_trust_store.dart';
import 'signature_verifier.dart';
import 'x509_certificate.dart';

/// The server-side verifier's outcome vocabulary, verbatim.
enum PassiveAuthOutcome {
  /// Hashes, signature and trust chain all check out.
  verified,

  /// The document is positively wrong: tampered data, a bad signature, or a
  /// structurally invalid SOD.
  invalid,

  /// Nothing is provably wrong, but the verdict cannot be completed: no
  /// anchor, an out-of-window certificate, or an algorithm off the allowlist.
  unverifiable,
}

/// Why the outcome is not [PassiveAuthOutcome.verified].
enum PassiveAuthCause {
  /// A read data group's hash does not match the SOD (or is missing from it):
  /// owned by the SOD hash oracle.
  dgHashMismatch,

  /// The CMS signature over the signed attributes did not verify. Upstream
  /// swallows this entirely.
  badDsSignature,

  /// The SOD is not a usable CMS `SignedData`: unparseable, wrong
  /// eContentType, no SignerInfo, missing/mismatched mandatory attributes, or
  /// no Document Signing Certificate.
  malformedSod,

  /// No path from the DSC to a trusted anchor in the store, including the
  /// preserved quirk that a chain of length 1 does not count.
  unknownCsca,

  /// A certificate on the path is outside its validity window at the
  /// verification time.
  expiredChainElement,

  /// The signature or digest algorithm is not on the allowlist, or the
  /// DSC's public key is one the shared SPKI parser cannot produce.
  unsupportedAlgorithm;

  /// snake_case wire spelling: identical to the server-side verifier's.
  String get wireName => switch (this) {
    PassiveAuthCause.dgHashMismatch => 'dg_hash_mismatch',
    PassiveAuthCause.badDsSignature => 'bad_ds_signature',
    PassiveAuthCause.malformedSod => 'malformed_sod',
    PassiveAuthCause.unknownCsca => 'unknown_csca',
    PassiveAuthCause.expiredChainElement => 'expired_chain_element',
    PassiveAuthCause.unsupportedAlgorithm => 'unsupported_algorithm',
  };
}

/// Composable notes that do **not** change the outcome.
enum PassiveAuthAnnotation {
  /// SHA-1 or SHA-224 appeared as the LDS digest, the CMS message digest, or
  /// the signature digest. Upstream accepts these silently; the
  /// annotation is dart-only surface.
  weakDigest;

  String get wireName => switch (this) {
    PassiveAuthAnnotation.weakDigest => 'weak_digest',
  };
}

/// The signature-only half: [verifySodSignature]'s result.
class SodSignatureCheck {
  const SodSignatureCheck({
    required this.valid,
    this.digestAlgorithm,
    this.signatureScheme,
    this.cause,
    this.annotations = const {},
    this.detail,
  });

  /// Whether `hash(eContent) == messageDigest` **and** the signature over the
  /// `A0`->`31` signed attributes verified under the DSC's key.
  final bool valid;

  /// `SHA1`...`SHA512`: the digest the signature actually used; `null` when
  /// the SOD never got that far.
  final String? digestAlgorithm;

  /// `rsa_pkcs1` | `rsa_pss` | `ecdsa`; `null` as above.
  final String? signatureScheme;

  /// `malformedSod` | `unsupportedAlgorithm` | `badDsSignature`; `null` when
  /// [valid].
  final PassiveAuthCause? cause;

  final Set<PassiveAuthAnnotation> annotations;

  /// Diagnostic detail, never user-facing copy.
  final String? detail;
}

/// The trust half: the built path and its verdict.
class TrustChainCheck {
  const TrustChainCheck({
    required this.trusted,
    required this.chain,
    this.cause,
    this.detail,
  });

  final bool trusted;

  /// `[DSC, ..., anchor]` as far as it could be built; the terminal element is
  /// the reported CSCA (upstream: the last certificate of the built chain).
  final List<X509Certificate> chain;

  /// `unknownCsca` | `expiredChainElement`; `null` when [trusted].
  final PassiveAuthCause? cause;

  final String? detail;
}

/// The full passive-authentication verdict.
class PassiveAuthResult {
  const PassiveAuthResult({
    required this.outcome,
    required this.cause,
    required this.annotations,
    required this.hashCheck,
    required this.signature,
    required this.trust,
    required this.documentSigningCertificate,
    required this.countrySigningCertificate,
  });

  final PassiveAuthOutcome outcome;

  /// `null` iff [outcome] is [PassiveAuthOutcome.verified].
  final PassiveAuthCause? cause;

  final Set<PassiveAuthAnnotation> annotations;

  /// The SOD hash oracle's result: `null` when the hash half was not evaluated
  /// (no data groups supplied, or the SOD was unusable before it ran).
  final SODHashCheckResult? hashCheck;

  final SodSignatureCheck signature;

  /// `null` when no trust store was consulted: upstream's nil-`masterListURL`
  /// equivalence, where Part 1 is skipped entirely.
  final TrustChainCheck? trust;

  /// The DSC the SOD carries, when it parsed.
  final X509CertificateInfo? documentSigningCertificate;

  /// The terminal anchor of the built chain, when one was reached.
  final X509CertificateInfo? countrySigningCertificate;

  /// Upstream `passportDataNotTampered`: the hash half passed. A verdict
  /// computed over zero data groups is vacuously true, exactly as upstream's
  /// model is before any `addDataGroup`.
  bool get passportDataNotTampered => hashCheck?.passed ?? true;

  /// Upstream `documentSigningCertificateVerified`: the CMS signature
  /// verified.
  bool get documentSigningCertificateVerified => signature.valid;

  /// Upstream `passportCorrectlySigned`: a trust chain was built. False when
  /// no store was consulted, matching upstream's nil-`masterListURL` path
  /// where the flag is never set.
  bool get passportCorrectlySigned => trust?.trusted ?? false;
}

/// The signature-only half of passive authentication, computable with no
/// trust store and no data groups, which is upstream's
/// Part-2-without-a-master-list equivalence.
///
/// Never throws.
SodSignatureCheck verifySodSignature(SOD sod) =>
    _evaluate(sod: sod, trustStore: null, dataGroupsRead: const {}).signature;

/// The full verdict.
///
/// [dataGroupsRead] mirrors the reader's read set; an empty map means the hash
/// half is not evaluated and passes vacuously. [verificationTime] defaults to
/// `DateTime.now()` and is injectable so fixtures stay deterministic (the
/// device clock is otherwise trusted).
///
/// Never throws: a store that failed to build is the only exception territory,
/// and that happens at construction.
PassiveAuthResult verifyPassiveAuth({
  required SOD sod,
  required CscaTrustStore trustStore,
  Map<DataGroupId, DataGroup> dataGroupsRead = const {},
  DateTime? verificationTime,
}) => _evaluate(
  sod: sod,
  trustStore: trustStore,
  dataGroupsRead: dataGroupsRead,
  verificationTime: verificationTime,
);

/// The reader's entry point: identical to [verifyPassiveAuth] except
/// that the hash half is **reused** from the oracle step rather than
/// recomputed. Hidden from the barrel: consumers use [verifyPassiveAuth].
PassiveAuthResult verifyPassiveAuthWithHashCheck({
  required SOD sod,
  required CscaTrustStore trustStore,
  required SODHashCheckResult hashCheck,
  DateTime? verificationTime,
}) => _evaluate(
  sod: sod,
  trustStore: trustStore,
  dataGroupsRead: const {},
  precomputedHashCheck: hashCheck,
  verificationTime: verificationTime,
);

// ---------------------------------------------------------------------------

PassiveAuthResult _evaluate({
  required SOD sod,
  required CscaTrustStore? trustStore,
  required Map<DataGroupId, DataGroup> dataGroupsRead,
  SODHashCheckResult? precomputedHashCheck,
  DateTime? verificationTime,
}) {
  final at = (verificationTime ?? DateTime.now()).toUtc();

  // --- the hash half, hoisted: it is independent of the CMS model, so it is
  // computed first and stays attached even on the malformed path (the
  // server-side verifier also always computes both).
  SODHashCheckResult? hashCheck = precomputedHashCheck;
  var hashHalfFailedToRun = false;
  if (hashCheck == null && dataGroupsRead.isNotEmpty) {
    try {
      hashCheck = checkDataGroupHashes(
        sod: sod,
        dataGroupsRead: dataGroupsRead,
      );
    } on EmrtdException catch (e) {
      // An LDS security object that will not parse is a malformed SOD, not a
      // hash mismatch (the oracle throws; this layer must not).
      hashHalfFailedToRun = true;
      passportReaderLog.severe('Passive auth - hash half unavailable: $e');
    }
  }

  // --- CMS parse + the structural gates.
  final parsed = CmsSignedData.parse(sod.pkcs7CertificateData);
  if (parsed is CmsMalformed) {
    return _malformed(hashCheck, parsed.reason);
  }
  final cms = (parsed as CmsParsed).data;

  if (hashHalfFailedToRun) {
    return _malformed(hashCheck, 'LDS security object could not be parsed');
  }
  if (cms.eContentType != oidLdsSecurityObject) {
    // A strictness addition: upstream checks no OIDs anywhere.
    return _malformed(
      hashCheck,
      'eContentType is ${cms.eContentType}, expected $oidLdsSecurityObject',
    );
  }
  if (cms.eContent == null) {
    return _malformed(hashCheck, 'SOD carries no eContent');
  }
  if (cms.signerInfos.isEmpty) {
    return _malformed(hashCheck, 'SOD carries no SignerInfo');
  }
  final signerInfo = cms.signerInfos.first;
  if (signerInfo.signedAttributesDer == null) {
    // Doc 9303 mandates signed attributes; upstream's manual path also
    // effectively requires them; it just lands in the branch that swallows
    // every signature failure.
    return _malformed(hashCheck, 'SignerInfo carries no signedAttrs');
  }
  final contentTypeAttr = signerInfo.contentTypeAttribute;
  if (contentTypeAttr == null) {
    return _malformed(
      hashCheck,
      'contentType signed attribute is absent',
    ); // RFC 5652 §5.3 MUST
  }
  if (contentTypeAttr != cms.eContentType) {
    return _malformed(
      hashCheck,
      'contentType attribute $contentTypeAttr does not match eContentType '
      '${cms.eContentType}',
    );
  }
  if (signerInfo.messageDigestAttribute == null) {
    return _malformed(hashCheck, 'messageDigest signed attribute is absent');
  }
  final dsc = resolveSignerCertificate(cms, signerInfo);
  if (dsc == null) {
    // Upstream force-unwraps `certs[0]` here and crashes the app.
    return _malformed(
      hashCheck,
      'SOD carries no usable Document Signing Certificate',
    );
  }

  // --- algorithm resolution against the allowlist.
  final algorithm = resolveSignatureAlgorithm(
    signatureAlgorithmOid: signerInfo.signatureAlgorithmOid,
    parameters: signerInfo.signatureAlgorithmParameters,
    signerDigestOid: signerInfo.digestAlgorithmOid,
  );
  final cmsDigestName = digestOidNames[signerInfo.digestAlgorithmOid];
  final dscKey = dsc.publicKey;

  final annotations = <PassiveAuthAnnotation>{};
  if (_isWeak(hashCheck?.sodHashAlgorythm) ||
      _isWeak(cmsDigestName) ||
      (algorithm?.weakDigest ?? false)) {
    annotations.add(PassiveAuthAnnotation.weakDigest);
  }

  String? unsupportedDetail;
  if (algorithm == null) {
    unsupportedDetail =
        'signature algorithm '
        '${algorithmDisplayName(signerInfo.signatureAlgorithmOid)} is not on '
        'the allowlist';
  } else if (cmsDigestName == null) {
    unsupportedDetail =
        'digest algorithm '
        '${algorithmDisplayName(signerInfo.digestAlgorithmOid)} is not on the '
        'allowlist';
  } else if (dscKey == null) {
    unsupportedDetail =
        'the DSC public key (${algorithmDisplayName(dsc.publicKeyAlgorithmOid)})'
        ' is not one this port can use';
  }

  // --- the signature half.
  final SodSignatureCheck signature;
  if (unsupportedDetail != null) {
    // Upstream instead falls to its SHA-256 default and reports a bare
    // failure, so a legitimately-signed document can false-negative.
    signature = SodSignatureCheck(
      valid: false,
      digestAlgorithm: algorithm?.digestName ?? cmsDigestName,
      signatureScheme: algorithm?.scheme.wireName,
      cause: PassiveAuthCause.unsupportedAlgorithm,
      annotations: annotations,
      detail: unsupportedDetail,
    );
  } else {
    final check = verifyCmsSignature(
      cms: cms,
      signerInfo: signerInfo,
      signerCertificate: dsc,
    );
    signature = SodSignatureCheck(
      valid: check.valid,
      digestAlgorithm: algorithm!.digestName,
      signatureScheme: algorithm.scheme.wireName,
      cause: check.valid ? null : PassiveAuthCause.badDsSignature,
      annotations: annotations,
      detail: check.reason,
    );
  }

  // --- the trust half (skipped entirely with no store).
  final trust = trustStore == null
      ? null
      : buildTrustChain(dsc: dsc, trustStore: trustStore, at: at);

  // --- the verdict, by precedence: tamper > unsupported > bad-signature >
  // chain.
  final hashPassed = hashCheck?.passed ?? true;
  final PassiveAuthOutcome outcome;
  final PassiveAuthCause? cause;
  if (!hashPassed) {
    outcome = PassiveAuthOutcome.invalid;
    cause = PassiveAuthCause.dgHashMismatch;
  } else if (signature.cause == PassiveAuthCause.unsupportedAlgorithm) {
    outcome = PassiveAuthOutcome.unverifiable;
    cause = PassiveAuthCause.unsupportedAlgorithm;
  } else if (!signature.valid) {
    outcome = PassiveAuthOutcome.invalid;
    cause = PassiveAuthCause.badDsSignature;
  } else if (trust != null && !trust.trusted) {
    outcome = PassiveAuthOutcome.unverifiable;
    cause = trust.cause ?? PassiveAuthCause.unknownCsca;
  } else {
    outcome = PassiveAuthOutcome.verified;
    cause = null;
  }

  passportReaderLog.fine(
    'Passive auth - ${outcome.name}'
    '${cause == null ? '' : '/${cause.wireName}'}',
  );

  return PassiveAuthResult(
    outcome: outcome,
    cause: cause,
    annotations: annotations,
    hashCheck: hashCheck,
    signature: signature,
    trust: trust,
    documentSigningCertificate: dsc.info,
    countrySigningCertificate: (trust != null && trust.trusted)
        ? trust.chain.last.info
        : null,
  );
}

PassiveAuthResult _malformed(SODHashCheckResult? hashCheck, String detail) {
  passportReaderLog.severe('Passive auth - malformed SOD: $detail');
  return PassiveAuthResult(
    outcome: PassiveAuthOutcome.invalid,
    cause: PassiveAuthCause.malformedSod,
    annotations: const {},
    hashCheck: hashCheck,
    signature: SodSignatureCheck(
      valid: false,
      cause: PassiveAuthCause.malformedSod,
      detail: detail,
    ),
    trust: null,
    documentSigningCertificate: null,
    countrySigningCertificate: null,
  );
}

bool _isWeak(String? digestName) =>
    digestName == 'SHA1' || digestName == 'SHA224';

/// Path building = `X509_verify_cert` with `flags = 0`.
///
/// Semantics, each one upstream's:
/// - candidate issuers by AKI->SKI then issuer DN (the trust store's index);
/// - the candidate's key must actually verify the certificate's signature;
/// - the issuer must be a CA (`basicConstraints.cA`) and, when `keyUsage` is
///   present, carry `keyCertSign`;
/// - validity windows are checked on **every** element at [at]: the one
///   OpenSSL default upstream leaves on;
/// - CSCA **link certificates** are walked multi-hop to a self-signed anchor;
/// - the chain must be **longer than one**: a DSC sitting in the store
///   as its own anchor fails, exactly as upstream's `nrCertsInChain > 1`
///   guard makes it fail.
///
/// Not done, matching `flags = 0` exactly: no CRL/OCSP, no partial
/// chains, no name constraints, no policy processing, no purpose check. The
/// anchor's own self-signature is not re-verified either: an anchor is trust
/// material established at store-ingestion time, not evidence.
TrustChainCheck buildTrustChain({
  required X509Certificate dsc,
  required CscaTrustStore trustStore,
  required DateTime at,
}) {
  if (!dsc.isValidAt(at)) {
    return TrustChainCheck(
      trusted: false,
      chain: [dsc],
      cause: PassiveAuthCause.expiredChainElement,
      detail:
          'the DSC is outside its validity window at '
          '${at.toIso8601String()}',
    );
  }

  final chain = <X509Certificate>[dsc];
  var current = dsc;
  var sawOutOfWindowIssuer = false;

  // A CSCA link chain is two hops; the ceiling only bounds a pathological
  // store (a cycle is already impossible: every hop must be a fresh subject).
  for (var depth = 0; depth < 8; depth++) {
    if (current.isSelfIssued && trustStore.contains(current)) {
      break; // a trusted self-signed anchor terminates the path
    }
    X509Certificate? next;
    for (final candidate in trustStore.candidateIssuers(current)) {
      if (chain.any(
        (c) => c.fingerprintSha256 == candidate.fingerprintSha256,
      )) {
        continue; // never revisit: a self-referential store cannot loop
      }
      if (!_signedBy(current, candidate)) {
        continue;
      }
      if (candidate.basicConstraintsCa != true ||
          candidate.keyCertSign == false) {
        continue; // the issuer must be a CA that may sign certificates
      }
      if (!candidate.isValidAt(at)) {
        sawOutOfWindowIssuer = true;
        continue;
      }
      next = candidate;
      break;
    }
    if (next == null) {
      return TrustChainCheck(
        trusted: false,
        chain: chain,
        cause: sawOutOfWindowIssuer
            ? PassiveAuthCause.expiredChainElement
            : PassiveAuthCause.unknownCsca,
        detail: sawOutOfWindowIssuer
            ? 'the only candidate issuer is outside its validity window'
            : 'no trusted issuer for ${current.subjectString}',
      );
    }
    chain.add(next);
    current = next;
  }

  if (chain.length < 2) {
    // Preserved verbatim: upstream requires `nrCertsInChain > 1`, so a DSC
    // that is itself the anchor is reported untrusted.
    return TrustChainCheck(
      trusted: false,
      chain: chain,
      cause: PassiveAuthCause.unknownCsca,
      detail: 'chain length 1: the DSC is its own anchor',
    );
  }
  if (!(current.isSelfIssued && trustStore.contains(current))) {
    return TrustChainCheck(
      trusted: false,
      chain: chain,
      cause: PassiveAuthCause.unknownCsca,
      detail: 'the path did not terminate at a self-signed trusted anchor',
    );
  }
  return TrustChainCheck(trusted: true, chain: chain);
}

/// Whether [issuer]'s key verifies [cert]'s signature under an allowlisted
/// algorithm (the allowlist applies to certificate signatures too: an anchor
/// signing with DSA is `unknown_csca`, not a silent pass).
bool _signedBy(X509Certificate cert, X509Certificate issuer) {
  final key = issuer.publicKey;
  if (key == null) {
    return false;
  }
  final algorithm = resolveSignatureAlgorithm(
    signatureAlgorithmOid: cert.signatureAlgorithmOid,
    parameters: cert.signatureAlgorithmParameters,
  );
  if (algorithm == null) {
    return false;
  }
  return verifyPkiSignature(
    key: key,
    algorithm: algorithm,
    data: cert.tbsDer,
    signature: cert.signature,
  );
}
