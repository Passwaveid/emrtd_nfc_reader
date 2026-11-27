// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: no single upstream declaration; upstream outsources the whole
//   SubjectPublicKeyInfo parse to OpenSSL's `d2i_PUBKEY`
//   (SecurityInfo.swift:97) and, for DG15, to `d2i_EC_PUBKEY` /
//   `d2i_RSA_PUBKEY` (OpenSSLUtils.swift:330-350/382-402 via
//   DataGroup15.swift:32-45). This is the Dart replacement, written to the
//   same nil-on-anything-unusable contract.

/// X.509 `SubjectPublicKeyInfo` parsing for `ChipAuthenticationPublicKeyInfo`
/// and [DataGroup15]: the one new piece the CA and AA ports need.
///
/// ```asn1
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm         AlgorithmIdentifier,
///   subjectPublicKey  BIT STRING }
/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm   OBJECT IDENTIFIER,
///   parameters  ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Five algorithm families are accepted, the three `d2i_PUBKEY` resolves to
/// an `EVP_PKEY` the CA handshake can use, plus the RSA arm DG15 needs
/// (`d2i_PUBKEY` parses RSA too, so this is upstream parity for the CA call
/// site as well; a CA-pubkey entry carrying an RSA key yields an info the
/// handshake cannot use, exactly as upstream's does, and fails that key
/// rather than skipping the entry) and the BSI
/// `standardizedDomainParameters` form:
/// - `id-ecPublicKey` (1.2.840.10045.2.1) with either a **named curve** OID
///   or **explicit prime-field `ECParameters`** -> [SpkiEcPublicKey]. The
///   point is decoded through `ecPointDecode`, so it is validated on-curve
///   and in-range (TR-03111 §3.2.1), deliberately stricter than
///   `EC_POINT_oct2point`, which also accepts the hybrid `06`/`07` forms (a
///   dart-only guard).
/// - `dhpublicnumber` (1.2.840.10046.2.1, X9.42 `{p, g, q, ...}`) and
///   `dhKeyAgreement` (1.2.840.113549.1.3.1, PKCS#3 `{p, g, l?}`) ->
///   [SpkiDhPublicKey]. `d2i_PUBKEY` accepts both (`EVP_PKEY_DHX` /
///   `EVP_PKEY_DH`) and `computeSharedSecret` handles both, so both are
///   parity.
/// - `rsaEncryption` (1.2.840.113549.1.1.1, PKCS#1 `RSAPublicKey {n, e}`;
///   `parameters` NULL or absent both accepted, as `d2i_RSA_PUBKEY` does) ->
///   [SpkiRsaPublicKey], consumed by the Active Authentication verifier.
/// - `standardizedDomainParameters` (0.4.0.127.0.7.1.2, BSI TR-03110-3
///   §A.2.1.1: the AlgorithmIdentifier is the OID plus an INTEGER
///   `parameterId` naming a P11 §9.5.1 Table 12 domain) -> [SpkiEcPublicKey],
///   resolved through PACE's own table. This is the form ICAO
///   9303 P11 App I's PACE-CAM `ChipAuthenticationPublicKeyInfo` uses.
///   **Dart-only divergence:** OpenSSL does not know the BSI OID, so
///   upstream's `d2i_PUBKEY` nil-returns and skips such an entry entirely,
///   pinned by the `dg14.json` split case. DH parameterIds (0-2)
///   are rejected: this arm carries an EC point, and a DH public value in a
///   BIT STRING has no defined encoding here.
///
/// Anything else (unknown algorithm OID, malformed structure, undecodable
/// point, non-prime field) yields `null`, which
/// `SecurityInfo.getInstance` turns into a skipped entry, exactly as
/// upstream's `d2i_PUBKEY`-nil path does, and which
/// [DataGroup15] turns into "AA unsupported" (upstream's
/// both-readers-returned-nil path).
library;

import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import '../crypto/ec_dh.dart';
import '../errors.dart';
import 'pace_info.dart';
import 'tlv.dart';

/// A parsed `SubjectPublicKeyInfo`: the port's stand-in for upstream's
/// `EVP_PKEY` `OpaquePointer`.
sealed class SubjectPublicKey {
  const SubjectPublicKey(this.spkiDer);

  /// The original SubjectPublicKeyInfo DER, kept verbatim.
  final Uint8List spkiDer;
}

/// An EC public key: its domain (named or explicit) and the decoded point.
final class SpkiEcPublicKey extends SubjectPublicKey {
  SpkiEcPublicKey(super.spkiDer, {required this.domain, required this.point});

  final ECDomainParameters domain;
  final ECPoint point;
}

/// A DH public key: the group `(p, g, q?)` and the public value `y`.
final class SpkiDhPublicKey extends SubjectPublicKey {
  SpkiDhPublicKey(
    super.spkiDer, {
    required this.p,
    required this.g,
    this.q,
    required this.y,
  });

  final BigInt p;
  final BigInt g;

  /// The subgroup order: present for X9.42 `dhpublicnumber`, absent for
  /// PKCS#3 `dhKeyAgreement`.
  final BigInt? q;

  final BigInt y;
}

/// An RSA public key: the PKCS#1 `RSAPublicKey` pair. The Active
/// Authentication verifier feeds it to `rsaPublicDecryptRaw`; Chip
/// Authentication has no use for it (upstream's `getPublicKeyData` falls
/// through both of its branches for an RSA `EVP_PKEY` and yields `[]`).
final class SpkiRsaPublicKey extends SubjectPublicKey {
  SpkiRsaPublicKey(
    super.spkiDer, {
    required this.modulus,
    required this.exponent,
  });

  final BigInt modulus;
  final BigInt exponent;
}

// --- algorithm OIDs ---------------------------------------------------------

const String _idEcPublicKey = '1.2.840.10045.2.1';
const String _idPrimeField = '1.2.840.10045.1.1';
const String _idDhPublicNumber = '1.2.840.10046.2.1'; // X9.42
const String _idDhKeyAgreement = '1.2.840.113549.1.3.1'; // PKCS#3
const String _idRsaEncryption = '1.2.840.113549.1.1.1'; // PKCS#1
/// BSI TR-03110-3 §A.2.1.1 `standardizedDomainParameters`.
const String _idStandardizedDomainParameters = '0.4.0.127.0.7.1.2';

/// The `domainName` of an [SpkiEcPublicKey] built from explicit
/// `ECParameters`: a placeholder, not a registry curve name.
const String explicitEcDomainName = 'spki-explicit';

/// Named-curve OIDs -> pointycastle registry names. The eleven curves
/// `PACEInfo`'s standardized-domain table can name (P11 Table 6), which are
/// also the curves real DG14 keys use; the ANSI X9.62 `prime192v1`/
/// `prime256v1` names share their OIDs with `secp192r1`/`secp256r1`.
const Map<String, String> _namedCurves = {
  '1.2.840.10045.3.1.1': 'secp192r1', // prime192v1
  '1.2.840.10045.3.1.7': 'secp256r1', // prime256v1
  '1.3.132.0.33': 'secp224r1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '1.3.36.3.3.2.8.1.1.3': 'brainpoolp192r1',
  '1.3.36.3.3.2.8.1.1.5': 'brainpoolp224r1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolp256r1',
  '1.3.36.3.3.2.8.1.1.9': 'brainpoolp320r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolp384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolp512r1',
};

/// Parses a `SubjectPublicKeyInfo` DER blob. Returns `null` for anything the
/// CA handshake could not use; see the library doc for the contract.
SubjectPublicKey? parseSubjectPublicKeyInfo(List<int> der) {
  try {
    return _parse(der);
  } on EmrtdException {
    return null; // malformed OID / undecodable point / non-prime field
  } on ArgumentError {
    return null; // includes RangeError from a truncated structure
  } on FormatException {
    return null;
  } on StateError {
    return null; // unknown pointycastle domain name
  }
}

SubjectPublicKey? _parse(List<int> der) {
  final root = TlvRecord.parse(der);
  if (root == null || root.tag != 0x30) {
    return null;
  }
  final children = TlvRecord.sequenceOfRecords(root.value);
  if (children == null || children.length != 2) {
    return null;
  }
  final algId = children[0];
  final bitString = children[1];
  if (algId.tag != 0x30 || bitString.tag != 0x03) {
    return null;
  }
  final algChildren = TlvRecord.sequenceOfRecords(algId.value);
  if (algChildren == null ||
      algChildren.isEmpty ||
      algChildren[0].tag != 0x06) {
    return null;
  }
  final algOid = asn1DecodeOid(algChildren[0].data);
  final params = algChildren.length >= 2 ? algChildren[1] : null;

  // BIT STRING content: leading octet = number of unused bits. A key encoding
  // is whole-octet, so anything but 0 is malformed.
  if (bitString.value.isEmpty || bitString.value[0] != 0x00) {
    return null;
  }
  final keyBits = bitString.value.sublist(1);

  switch (algOid) {
    case _idEcPublicKey:
      return _parseEc(der, params, keyBits);
    case _idDhPublicNumber:
      return _parseDh(der, params, keyBits, x942: true);
    case _idDhKeyAgreement:
      return _parseDh(der, params, keyBits, x942: false);
    case _idRsaEncryption:
      return _parseRsa(der, params, keyBits);
    case _idStandardizedDomainParameters:
      return _parseStandardizedEc(der, params, keyBits);
    default:
      return null;
  }
}

/// `AlgorithmIdentifier ::= SEQUENCE { standardizedDomainParameters OBJECT
/// IDENTIFIER, INTEGER parameterId }`, the BIT STRING carrying the
/// uncompressed EC point. The id resolves through PACE's own P11 §9.5.1
/// Table 12 table; DH ids (0-2) and unknown ids yield null -> the entry is
/// skipped, the same nil contract every other arm honours.
SubjectPublicKey? _parseStandardizedEc(
  List<int> der,
  TlvRecord? params,
  Uint8List keyBits,
) {
  if (params == null || params.tag != 0x02) {
    return null;
  }
  final id = _derUnsigned(params.value);
  // Table 12 tops out at 18; anything wider is not an id, and `toInt()` on a
  // multi-word BigInt would silently truncate.
  if (id == null || id > BigInt.from(0xFFFF)) {
    return null;
  }
  final PACEParameterSpec spec;
  try {
    spec = paceParameterSpecForId(id.toInt());
  } on InvalidDataPassed {
    return null; // an id the standardized-domain table does not know
  }
  if (spec is! ECStandardizedDomain) {
    return null; // DH group ids 0-2: no EC point to decode
  }
  // Validated decode (on-curve, in-range), as the `id-ecPublicKey` arm
  // does.
  return SpkiEcPublicKey(
    Uint8List.fromList(der),
    domain: spec.domain,
    point: ecPointDecode(spec.domain, keyBits),
  );
}

/// ```asn1
/// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
/// ```
/// carried in the BIT STRING. `d2i_RSA_PUBKEY` ignores the algorithm
/// parameters, so both the conventional explicit NULL and an absent field are
/// accepted.
SubjectPublicKey? _parseRsa(
  List<int> der,
  TlvRecord? params,
  Uint8List keyBits,
) {
  if (params != null && !(params.tag == 0x05 && params.value.isEmpty)) {
    return null; // anything other than NULL/absent is not rsaEncryption
  }
  final key = TlvRecord.parse(keyBits);
  if (key == null || key.tag != 0x30 || key.data.length != keyBits.length) {
    return null;
  }
  final fields = TlvRecord.sequenceOfRecords(key.value);
  if (fields == null ||
      fields.length != 2 ||
      fields[0].tag != 0x02 ||
      fields[1].tag != 0x02) {
    return null;
  }
  final n = _derUnsigned(fields[0].value);
  final e = _derUnsigned(fields[1].value);
  if (n == null || e == null || n <= BigInt.zero || e <= BigInt.zero) {
    return null;
  }
  return SpkiRsaPublicKey(Uint8List.fromList(der), modulus: n, exponent: e);
}

SubjectPublicKey? _parseEc(
  List<int> der,
  TlvRecord? params,
  Uint8List keyBits,
) {
  if (params == null) {
    return null; // absent parameters (implicitCurve) leave no domain to use
  }
  final ECDomainParameters domain;
  if (params.tag == 0x06) {
    final name = _namedCurves[asn1DecodeOid(params.data)];
    if (name == null) {
      return null;
    }
    domain = ECDomainParameters(name);
  } else if (params.tag == 0x30) {
    final explicit = _parseExplicitEcParameters(params.value);
    if (explicit == null) {
      return null;
    }
    domain = explicit;
  } else {
    return null;
  }
  // Validated decode (on-curve, in-range).
  return SpkiEcPublicKey(
    Uint8List.fromList(der),
    domain: domain,
    point: ecPointDecode(domain, keyBits),
  );
}

/// ```asn1
/// ECParameters ::= SEQUENCE {
///   version   INTEGER { ecpVer1(1) },
///   fieldID   SEQUENCE { fieldType OBJECT IDENTIFIER, parameters ANY },
///   curve     SEQUENCE { a OCTET STRING, b OCTET STRING, seed BIT STRING OPTIONAL },
///   base      OCTET STRING,
///   order     INTEGER,
///   cofactor  INTEGER OPTIONAL }
/// ```
/// Only the prime-field form is accepted (`id-prime-Field`): the same
/// restriction [ecPointDecode] already imposes. The result is a custom
/// [ECDomainParameters], built the way PACE's mapping builds its mapped
/// domain.
ECDomainParameters? _parseExplicitEcParameters(List<int> value) {
  final f = TlvRecord.sequenceOfRecords(value);
  if (f == null || f.length < 5) {
    return null;
  }
  if (f[0].tag != 0x02 || _derUnsigned(f[0].value) != BigInt.one) {
    return null; // version must be ecpVer1
  }
  if (f[1].tag != 0x30) {
    return null;
  }
  final fieldId = TlvRecord.sequenceOfRecords(f[1].value);
  if (fieldId == null ||
      fieldId.length != 2 ||
      fieldId[0].tag != 0x06 ||
      fieldId[1].tag != 0x02) {
    return null;
  }
  if (asn1DecodeOid(fieldId[0].data) != _idPrimeField) {
    return null; // characteristic-two fields are out of scope
  }
  final p = _derUnsigned(fieldId[1].value);
  if (p == null || p <= BigInt.zero) {
    return null;
  }
  if (f[2].tag != 0x30) {
    return null;
  }
  final curve = TlvRecord.sequenceOfRecords(f[2].value);
  if (curve == null ||
      curve.length < 2 ||
      curve[0].tag != 0x04 ||
      curve[1].tag != 0x04) {
    return null;
  }
  // a and b are field elements (FE2OS), i.e. unsigned fixed-width octets.
  final a = bytesToBigInt(curve[0].value);
  final b = bytesToBigInt(curve[1].value);
  if (f[3].tag != 0x04 || f[4].tag != 0x02) {
    return null;
  }
  final n = _derUnsigned(f[4].value);
  if (n == null || n <= BigInt.zero) {
    return null;
  }
  final h = f.length >= 6 && f[5].tag == 0x02
      ? _derUnsigned(f[5].value)
      : BigInt.one;
  if (h == null || h <= BigInt.zero) {
    return null;
  }
  final ecCurve = fp.ECCurve(p, a, b);
  final infinity = ecCurve.infinity;
  if (infinity == null) {
    return null;
  }
  // ecPointDecode reads only `domain.curve`, so a placeholder generator is
  // enough to decode the real one; the returned domain carries it properly.
  final probe = ECDomainParametersImpl(
    explicitEcDomainName,
    ecCurve,
    infinity,
    n,
    h,
  );
  final g = ecPointDecode(probe, f[3].value);
  return ECDomainParametersImpl(explicitEcDomainName, ecCurve, g, n, h);
}

/// X9.42 `DomainParameters ::= SEQUENCE { p, g, q, j OPTIONAL, ... }` or
/// PKCS#3 `DHParameter ::= SEQUENCE { prime, base, privateValueLength
/// OPTIONAL }`; the BIT STRING carries the DER INTEGER `y`.
SubjectPublicKey? _parseDh(
  List<int> der,
  TlvRecord? params,
  Uint8List keyBits, {
  required bool x942,
}) {
  if (params == null || params.tag != 0x30) {
    return null;
  }
  final dp = TlvRecord.sequenceOfRecords(params.value);
  final minChildren = x942 ? 3 : 2;
  if (dp == null || dp.length < minChildren) {
    return null;
  }
  for (var i = 0; i < minChildren; i++) {
    if (dp[i].tag != 0x02) {
      return null;
    }
  }
  final p = _derUnsigned(dp[0].value);
  final g = _derUnsigned(dp[1].value);
  final q = x942 ? _derUnsigned(dp[2].value) : null;
  if (p == null || g == null || p <= BigInt.zero) {
    return null;
  }
  if (x942 && q == null) {
    return null;
  }
  final yRec = TlvRecord.parse(keyBits);
  if (yRec == null || yRec.tag != 0x02) {
    return null;
  }
  final y = _derUnsigned(yRec.value);
  if (y == null) {
    return null;
  }
  return SpkiDhPublicKey(Uint8List.fromList(der), p: p, g: g, q: q, y: y);
}

/// A DER INTEGER's content octets as a non-negative [BigInt]; `null` when the
/// encoding is empty or negative (no CA/domain quantity is ever negative).
BigInt? _derUnsigned(List<int> content) {
  if (content.isEmpty || (content[0] & 0x80) != 0) {
    return null;
  }
  return bytesToBigInt(content);
}
