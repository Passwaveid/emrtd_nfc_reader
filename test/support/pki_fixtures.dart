/// The concrete passive-authentication fixture set: every certificate, SOD
/// and master list the conformance vectors and the `test/pki/` unit suites
/// use, composed once from the deterministic builders in
/// `emrtd_test_pki.dart`.
///
/// Everything is lazily built and memoized, so a test that touches one SOD
/// does not pay for the whole PKI. Building the full set costs a few hundred
/// milliseconds (RSA-2048 signing dominates).
///
/// Validity strategy: every certificate on a **valid** path runs to 2126,
/// so the Swift oracle, which has no time injection, stays green on a real
/// clock; the expired fixtures are expired on any real clock (2018-2019).
///
/// Document data is the ICAO specimen (UTOPIA / ERIKSSON) reused from
/// `emrtd_fixtures.dart`, so the SODs here hash exactly the DG files the
/// hash-oracle suite already pins.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/pki/cms_signed_data.dart';

import 'emrtd_chip_sim.dart' show hx;
import 'emrtd_fixtures.dart';
import 'emrtd_test_pki.dart';

/// The instant every time-sensitive vector is evaluated at.
final DateTime pkiVerificationTime = DateTime.utc(2026, 7, 25, 12);

/// Long-lived certificates start in 2015 so the DSC that is expired on any
/// real clock (2018-2019) still sits inside its issuer's window, which is
/// what makes the injected-time tests exercise the DSC's own validity check.
final DateTime _longFrom = DateTime.utc(2015, 1, 1);
final DateTime _longTo = DateTime.utc(2126, 1, 1);
final DateTime _expiredFrom = DateTime.utc(2018, 1, 1);
final DateTime _expiredTo = DateTime.utc(2019, 1, 1);

Uint8List _dn(String cn) => testDn(
  country: 'UT',
  organisation: 'Utopia Ministry of Interior',
  commonName: cn,
);

// --- distinguished names ----------------------------------------------------

final Uint8List dnCscaRsa = _dn('UTOPIA CSCA RSA');
final Uint8List dnCscaRsaLowercase = testDn(
  country: 'UT',
  organisation: 'utopia ministry of interior',
  commonName: 'utopia csca rsa',
);
final Uint8List dnCscaEc = _dn('UTOPIA CSCA EC');
final Uint8List dnCscaOld = _dn('UTOPIA CSCA 2018');
final Uint8List dnCscaNew = _dn('UTOPIA CSCA 2024');
final Uint8List dnDscRsa = _dn('UTOPIA DS RSA 001');
final Uint8List dnDscRsaExpired = _dn('UTOPIA DS RSA EXPIRED');
final Uint8List dnDscRsa4096 = _dn('UTOPIA DS RSA 4096');
final Uint8List dnDscEc = _dn('UTOPIA DS EC 001');
final Uint8List dnDscEcExplicit = _dn('UTOPIA DS EC EXPLICIT');
final Uint8List dnDscBrainpool = _dn('UTOPIA DS BP 001');
final Uint8List dnDscUnderNew = _dn('UTOPIA DS RSA 002');
final Uint8List dnDscCaseDiff = _dn('UTOPIA DS RSA 003');
final Uint8List dnDscSelfSigned = _dn('UTOPIA DS SELF SIGNED');
final Uint8List dnMlSigner = _dn('UTOPIA MASTER LIST SIGNER');

// --- certificates -----------------------------------------------------------

/// The primary RSA anchor.
final Uint8List cscaRsaCert = buildCertificate(
  subject: dnCscaRsa,
  issuer: dnCscaRsa,
  serial: 0x1001,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: cscaRsaKey,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  isCa: true,
  includeAki: false,
  randomSeed: 'csca-rsa',
);

/// The Document Signing Certificate for the RSA SODs.
final Uint8List dscRsaCert = buildCertificate(
  subject: dnDscRsa,
  issuer: dnCscaRsa,
  serial: 0x2001,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscRsaKey,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  randomSeed: 'dsc-rsa',
);

/// An RSA-4096 DSC under the RSA anchor. Only the `x509.parse` surface
/// reads it; it signs no SOD and sits on no trust path.
final Uint8List dscRsa4096Cert = buildCertificate(
  subject: dnDscRsa4096,
  issuer: dnCscaRsa,
  serial: 0x2006,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscRsa4096Key,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  randomSeed: 'dsc-rsa-4096',
);

/// A DSC expired on any real clock (2018-2019): the `expired_chain_element`
/// input.
final Uint8List dscRsaExpiredCert = buildCertificate(
  subject: dnDscRsaExpired,
  issuer: dnCscaRsa,
  serial: 0x2002,
  notBefore: _expiredFrom,
  notAfter: _expiredTo,
  subjectKey: dscRsaKey,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  randomSeed: 'dsc-rsa-expired',
);

/// A DSC whose issuer DN differs from the anchor's subject **only in case**
/// and whitespace, with no AKI, so the chain can only be built through the
/// normalized comparison.
final Uint8List dscCaseDiffCert = buildCertificate(
  subject: dnDscCaseDiff,
  issuer: dnCscaRsaLowercase,
  serial: 0x2003,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscRsaKey,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  includeAki: false,
  randomSeed: 'dsc-case',
);

/// A self-signed certificate used as a DSC: the own-anchor check's input
/// when it is also the only thing in the trust store.
final Uint8List dscSelfSignedCert = buildCertificate(
  subject: dnDscSelfSigned,
  issuer: dnDscSelfSigned,
  serial: 0x2004,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscRsaKey,
  issuerKey: dscRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  isCa: true,
  includeAki: false,
  randomSeed: 'dsc-self',
);

/// The EC anchor.
final Uint8List cscaEcCert = buildCertificate(
  subject: dnCscaEc,
  issuer: dnCscaEc,
  serial: 0x1002,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: cscaEcKey,
  issuerKey: cscaEcKey,
  signatureAlgorithmOid: sigEcdsaSha256,
  isCa: true,
  includeAki: false,
  randomSeed: 'csca-ec',
);

final Uint8List dscEcCert = buildCertificate(
  subject: dnDscEc,
  issuer: dnCscaEc,
  serial: 0x2101,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscEcKey,
  issuerKey: cscaEcKey,
  signatureAlgorithmOid: sigEcdsaSha256,
  randomSeed: 'dsc-ec',
);

/// A DSC whose SPKI carries **explicit** `ECParameters`.
final Uint8List dscEcExplicitCert = buildCertificate(
  subject: dnDscEcExplicit,
  issuer: dnCscaEc,
  serial: 0x2102,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscEcExplicitKey,
  issuerKey: cscaEcKey,
  signatureAlgorithmOid: sigEcdsaSha256,
  randomSeed: 'dsc-ec-explicit',
);

final Uint8List dscBrainpoolCert = buildCertificate(
  subject: dnDscBrainpool,
  issuer: dnCscaEc,
  serial: 0x2103,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscBrainpoolKey,
  issuerKey: cscaEcKey,
  signatureAlgorithmOid: sigEcdsaSha256,
  randomSeed: 'dsc-bp',
);

// --- the CSCA link-certificate rollover -------------------------------------

/// The superseded self-signed anchor.
final Uint8List cscaOldCert = buildCertificate(
  subject: dnCscaOld,
  issuer: dnCscaOld,
  serial: 0x1003,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: cscaRsaOldKey,
  issuerKey: cscaRsaOldKey,
  signatureAlgorithmOid: sigSha256Rsa,
  isCa: true,
  includeAki: false,
  randomSeed: 'csca-old',
);

/// The **link certificate**: the new CSCA key, signed by the old one.
final Uint8List cscaLinkCert = buildCertificate(
  subject: dnCscaNew,
  issuer: dnCscaOld,
  serial: 0x1004,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: cscaRsaNewKey,
  issuerKey: cscaRsaOldKey,
  signatureAlgorithmOid: sigSha256Rsa,
  isCa: true,
  randomSeed: 'csca-link',
);

/// A DSC issued under the *new* CSCA key, reachable only through the link.
final Uint8List dscUnderNewCert = buildCertificate(
  subject: dnDscUnderNew,
  issuer: dnCscaNew,
  serial: 0x2005,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: dscRsaKey,
  issuerKey: cscaRsaNewKey,
  signatureAlgorithmOid: sigSha256Rsa,
  randomSeed: 'dsc-under-new',
);

/// The Master List Signer, chaining to [cscaRsaCert].
final Uint8List mlSignerCert = buildCertificate(
  subject: dnMlSigner,
  issuer: dnCscaRsa,
  serial: 0x3001,
  notBefore: _longFrom,
  notAfter: _longTo,
  subjectKey: mlSignerRsaKey,
  issuerKey: cscaRsaKey,
  signatureAlgorithmOid: sigSha256Rsa,
  randomSeed: 'ml-signer',
);

// --- trust stores (PEM, upstream's format) ----------------------------------

String _pem(List<Uint8List> certs) => certs.map(certificateToPem).join();

/// The everyday anchor set: the RSA and EC CSCAs.
final String trustPemDefault = _pem([cscaRsaCert, cscaEcCert]);

/// The link-rollover store: the old anchor plus the link certificate.
final String trustPemLink = _pem([cscaOldCert, cscaLinkCert]);

/// The own-anchor store: the self-signed DSC is its own (only) anchor.
final String trustPemDscAsAnchor = _pem([dscSelfSignedCert]);

/// An empty store: every chain is `unknown_csca`.
const String trustPemEmpty = '';

// --- data-group files -------------------------------------------------------

/// The two files every SOD below attests, byte-identical to the vector
/// fixtures.
Map<int, List<int>> get pkiDataGroupFiles => {1: hx(dg1GoodHex), 2: hx(dg2Hex)};

// --- SODs -------------------------------------------------------------------

Uint8List _sod({
  required List<Uint8List> certificates,
  required TestKeyPair signerKey,
  required Uint8List signerIssuer,
  required int signerSerial,
  String ldsDigestOid = digestSha256,
  String cmsDigestOid = digestSha256,
  String signatureAlgorithmOid = sigSha256Rsa,
  Uint8List? pssParams,
  String eContentType = oidLdsSecurityObject,
  String? contentTypeAttributeOid,
  bool includeSignedAttributes = true,
  bool corruptSignature = false,
  bool indefiniteLengths = false,
  Uint8List Function(Uint8List)? signatureTransform,
  String? signerInfoAlgorithmOverride,
  required String seed,
}) => buildSignedSod(
  dataGroupFiles: pkiDataGroupFiles,
  certificates: certificates,
  signerKey: signerKey,
  signerIssuer: signerIssuer,
  signerSerial: signerSerial,
  ldsDigestOid: ldsDigestOid,
  cmsDigestOid: cmsDigestOid,
  signatureAlgorithmOid: signatureAlgorithmOid,
  pssParams: pssParams,
  eContentType: eContentType,
  contentTypeAttributeOid: contentTypeAttributeOid,
  includeSignedAttributes: includeSignedAttributes,
  corruptSignature: corruptSignature,
  indefiniteLengths: indefiniteLengths,
  signatureTransform: signatureTransform,
  signerInfoAlgorithmOverride: signerInfoAlgorithmOverride,
  randomSeed: seed,
);

/// RSA-2048 PKCS#1 v1.5, `sha256WithRSAEncryption`: the baseline valid SOD.
final Uint8List sodRsaSha256 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  seed: 'sod-rsa-sha256',
);

/// The plain-`rsaEncryption` SignerInfo form (RFC 3370 §3.2) at SHA-256: the
/// one form upstream's SHA-256 default also verifies.
final Uint8List sodRsaEncryptionSha256 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  signatureAlgorithmOid: sigRsaEncryption,
  seed: 'sod-rsa-plain-256',
);

/// The same form at SHA-512: dart verifies, upstream false-negatives.
final Uint8List sodRsaEncryptionSha512 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  ldsDigestOid: digestSha512,
  cmsDigestOid: digestSha512,
  signatureAlgorithmOid: sigRsaEncryption,
  seed: 'sod-rsa-plain-512',
);

/// RSASSA-PSS with SHA-256 parameters.
final Uint8List sodRsaPssSha256 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  signatureAlgorithmOid: sigRsassaPss,
  pssParams: pssParameters('SHA256'),
  seed: 'sod-pss-256',
);

/// RSASSA-PSS with SHA-384 parameters: dart verifies it, upstream verifies
/// every PSS SOD with SHA-256 and so fails this one.
final Uint8List sodRsaPssSha384 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  ldsDigestOid: digestSha384,
  cmsDigestOid: digestSha384,
  signatureAlgorithmOid: sigRsassaPss,
  pssParams: pssParameters('SHA384'),
  seed: 'sod-pss-384',
);

/// ECDSA over NIST P-256.
final Uint8List sodEcdsaP256 = _sod(
  certificates: [dscEcCert],
  signerKey: dscEcKey,
  signerIssuer: dnCscaEc,
  signerSerial: 0x2101,
  signatureAlgorithmOid: sigEcdsaSha256,
  seed: 'sod-ec',
);

/// The same signature with a **non-minimal** leading zero octet spliced into
/// `r` (upstream repairs these in place; the port accepts them).
final Uint8List sodEcdsaLeadingZero = _sod(
  certificates: [dscEcCert],
  signerKey: dscEcKey,
  signerIssuer: dnCscaEc,
  signerSerial: 0x2101,
  signatureAlgorithmOid: sigEcdsaSha256,
  signatureTransform: _padEcdsaIntegers,
  seed: 'sod-ec',
);

/// ECDSA over brainpoolP256r1.
final Uint8List sodEcdsaBrainpool = _sod(
  certificates: [dscBrainpoolCert],
  signerKey: dscBrainpoolKey,
  signerIssuer: dnCscaEc,
  signerSerial: 0x2103,
  signatureAlgorithmOid: sigEcdsaSha256,
  seed: 'sod-bp',
);

/// A DSC whose SPKI carries explicit EC parameters.
final Uint8List sodEcdsaExplicitParams = _sod(
  certificates: [dscEcExplicitCert],
  signerKey: dscEcExplicitKey,
  signerIssuer: dnCscaEc,
  signerSerial: 0x2102,
  signatureAlgorithmOid: sigEcdsaSha256,
  seed: 'sod-ec-explicit',
);

/// SHA-1 everywhere: verifies on both runners, annotated `weak_digest`
/// dart-side only.
final Uint8List sodRsaSha1 = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  ldsDigestOid: digestSha1,
  cmsDigestOid: digestSha1,
  signatureAlgorithmOid: sigSha1Rsa,
  seed: 'sod-sha1',
);

/// The baseline SOD with its last signature octet flipped.
final Uint8List sodCorruptSignature = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  corruptSignature: true,
  seed: 'sod-rsa-sha256',
);

/// A SignerInfo declaring `dsaWithSHA1`: an algorithm the allowlist rejects.
/// The bytes are still an RSA signature: resolution fails before any verify
/// runs, which is exactly what the case pins.
final Uint8List sodDsaAlgorithm = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  signerInfoAlgorithmOverride: sigDsaWithSha1,
  seed: 'sod-dsa',
);

/// eContentType `2.23.136.1.1.2` (a master list's) instead of `.1`.
final Uint8List sodWrongEContentType = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  eContentType: oidCscaMasterList,
  seed: 'sod-wrong-econtent',
);

/// A content-type attribute that does not match the eContentType.
final Uint8List sodContentTypeAttrMismatch = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  contentTypeAttributeOid: oidCscaMasterList,
  seed: 'sod-ct-mismatch',
);

/// No signed attributes at all: Doc 9303 mandates them.
final Uint8List sodNoSignedAttributes = _sod(
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  includeSignedAttributes: false,
  seed: 'sod-no-attrs',
);

/// A CMS with an **empty certificate set**: upstream force-unwraps and
/// crashes here.
final Uint8List sodCertless = _sod(
  certificates: const [],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  seed: 'sod-certless',
);

/// The baseline SOD's **CMS blob** re-encoded with BER indefinite lengths at
/// the outer levels.
///
/// Deliberately not an EF.SOD *file*: the shipped `SOD` constructor walks
/// with `TlvRecord`, which rejects indefinite lengths by design (as
/// upstream's does), so a BER-encoded SOD never reaches the pki layer at
/// all: an inherited constraint passive authentication does not change. BER
/// tolerance is what the **master-list** path needs, and that is where the
/// vector cases live; this blob pins the CMS model directly.
final Uint8List cmsIndefiniteLengths = buildSignedSod(
  dataGroupFiles: pkiDataGroupFiles,
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  indefiniteLengths: true,
  wrapInFileTag: false,
  randomSeed: 'sod-rsa-sha256',
);

/// The same CMS blob in plain DER: the comparand for the BER model test.
final Uint8List cmsRsaSha256 = buildSignedSod(
  dataGroupFiles: pkiDataGroupFiles,
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  wrapInFileTag: false,
  randomSeed: 'sod-rsa-sha256',
);

/// Signed by the DSC that is expired on any real clock.
final Uint8List sodExpiredDsc = _sod(
  certificates: [dscRsaExpiredCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2002,
  seed: 'sod-expired',
);

/// Signed by the self-signed DSC.
final Uint8List sodDscAsAnchor = _sod(
  certificates: [dscSelfSignedCert],
  signerKey: dscRsaKey,
  signerIssuer: dnDscSelfSigned,
  signerSerial: 0x2004,
  seed: 'sod-self',
);

/// Signed by a DSC under the rolled-over CSCA: needs the link certificate.
final Uint8List sodLinkChain = _sod(
  certificates: [dscUnderNewCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaNew,
  signerSerial: 0x2005,
  seed: 'sod-link',
);

/// Signed by the case-differing-DN DSC (DN normalization).
final Uint8List sodCaseDifferingDn = _sod(
  certificates: [dscCaseDiffCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsaLowercase,
  signerSerial: 0x2003,
  seed: 'sod-case',
);

// --- master lists -----------------------------------------------------------

/// A valid signed master list carrying both anchors.
final Uint8List masterListValid = buildMasterList(
  cscaCertificates: [cscaRsaCert, cscaEcCert],
  signerCertificates: [mlSignerCert],
  signerKey: mlSignerRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x3001,
  randomSeed: 'ml-valid',
);

/// The same list re-encoded with BER **indefinite** lengths: the shape real
/// `.ml` files carry in the wild, and the reason the pki layer needed its own
/// ASN.1 substrate.
final Uint8List masterListIndefiniteLengths = buildMasterList(
  cscaCertificates: [cscaRsaCert, cscaEcCert],
  signerCertificates: [mlSignerCert],
  signerKey: mlSignerRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x3001,
  indefiniteLengths: true,
  randomSeed: 'ml-valid',
);

/// The same list with the wrong eContentType (`.1` instead of `.2`).
final Uint8List masterListWrongEContentType = buildMasterList(
  cscaCertificates: [cscaRsaCert],
  signerCertificates: [mlSignerCert],
  signerKey: mlSignerRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x3001,
  eContentType: oidLdsSecurityObject,
  randomSeed: 'ml-wrong-ct',
);

/// A list whose own signature does not verify.
final Uint8List masterListBadSignature = buildMasterList(
  cscaCertificates: [cscaRsaCert],
  signerCertificates: [mlSignerCert],
  signerKey: mlSignerRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x3001,
  corruptSignature: true,
  randomSeed: 'ml-valid',
);

/// A list carrying one unparseable entry beside two good ones: the tolerant
/// reader's `skippedCertificates` case.
final Uint8List masterListWithGarbageEntry = buildMasterList(
  cscaCertificates: [
    cscaRsaCert,
    Der.seq([
      Der.int32(1),
      Der.octetString(const [0xDE, 0xAD, 0xBE, 0xEF]),
    ]),
    cscaEcCert,
  ],
  signerCertificates: [mlSignerCert],
  signerKey: mlSignerRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x3001,
  randomSeed: 'ml-garbage',
);

// --- chip-sim file sets ----------------------------------------------------

/// The three-file specimen chip with a **properly signed** SOD (the vectors'
/// fixture SOD carries a dummy SignerInfo, which is fine for the hash oracle
/// and unusable for passive authentication).
Map<int, Uint8List> pkiSpecimenFiles({
  Uint8List? sod,
  bool tamperedDg1 = false,
}) => {
  0x0101: hx(tamperedDg1 ? dg1TamperedHex : dg1GoodHex),
  0x0102: hx(dg2Hex),
  0x011D: sod ?? sodRsaSha256,
};

/// A SOD over the **tampered** DG1, so the chip is internally consistent and
/// only the served DG1 differs from the authentic one, the oracle-negative
/// shape, rebuilt for the passive-authentication chain.
final Uint8List sodOverTamperedDg1 = buildSignedSod(
  dataGroupFiles: {1: hx(dg1TamperedHex), 2: hx(dg2Hex)},
  certificates: [dscRsaCert],
  signerKey: dscRsaKey,
  signerIssuer: dnCscaRsa,
  signerSerial: 0x2001,
  randomSeed: 'sod-tampered',
);

// --- hostile / structural inputs -------------------------------------------

/// A valid CMS blob truncated to two thirds: the walk must answer
/// `malformed_sod`, never throw.
final Uint8List cmsTruncated = Uint8List.sublistView(
  cmsRsaSha256,
  0,
  (cmsRsaSha256.length * 2) ~/ 3,
);

/// A crafted BER blob with a **zero-length TLV inside an indefinite-length
/// region**: the exact shape that throws in pointycastle's `asn1_utils.dart`
/// and that this port's vendored walker handles.
Uint8List get zeroLengthInsideIndefinite => Der.indefinite(0x30, [
  ...Der.nul(), // 05 00: the zero-length child
  ...Der.int32(42),
]);

// --- small helpers ----------------------------------------------------------

/// Splices an extra leading `0x00` into both `r` and `s` of a DER ECDSA
/// signature, producing the non-minimal INTEGERs upstream repairs.
Uint8List _padEcdsaIntegers(Uint8List der) {
  // SEQUENCE { INTEGER r, INTEGER s }: short-form lengths throughout at
  // P-256 sizes, so the walk below is enough for fixture purposes.
  var i = 2;
  final out = <int>[];
  for (var n = 0; n < 2; n++) {
    final len = der[i + 1];
    out.addAll([0x02, len + 1, 0x00, ...der.sublist(i + 2, i + 2 + len)]);
    i += 2 + len;
  }
  return Uint8List.fromList([0x30, out.length, ...out]);
}
