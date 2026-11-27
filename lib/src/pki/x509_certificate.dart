// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/X509Wrapper.swift @ 8fc6eed (2.3.2 fork)
//   in full (the display accessors, `getItemsAsDict`, fingerprint, issuer/
//   subject, serial, algorithms, validity), plus the structural fields
//   upstream never names because `X509_verify_cert` reads them inside OpenSSL
//   (SKI/AKI/basicConstraints/keyUsage, the TBS slice, the DN raw DER).
//   `certToPEM` is realized as [X509Certificate.toPem].
//
//   Deliberate format divergences (display-only, dart-only conformance op):
//   validity as ISO-8601 rather than OpenSSL's `ASN1_TIME_print` text, and a
//   `fingerprintSha256` beside upstream's SHA-1 one (the server-side
//   verifier's audit format). Serial numbers wider than 64 bits
//   render in full here where `ASN1_INTEGER_get` gives up and returns -1.

/// The X.509 slice passive authentication needs, a certificate parser sized
/// to `X509Wrapper` plus DSC->CSCA path building, not X.509 in general.
///
/// Everything is **total**: [X509Certificate.tryParse] answers `null` on any
/// malformed input, and no accessor throws.
///
/// Not modeled, deliberately (inherited from upstream's `flags=0` posture):
/// CRL distribution points, policies, name constraints, extended key usage,
/// extension **criticality** (unknown critical extensions are ignored,
/// exactly as OpenSSL's defaults let them be).
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/hashes.dart';
import '../lds/subject_public_key_info.dart';
import '../utils.dart';
import 'asn1_reader.dart';

/// Extension OIDs this layer reads (RFC 5280 §4.2.1).
const String _oidSubjectKeyIdentifier = '2.5.29.14';
const String _oidKeyUsage = '2.5.29.15';
const String _oidBasicConstraints = '2.5.29.19';
const String _oidAuthorityKeyIdentifier = '2.5.29.35';

/// A parsed X.509 certificate. Construct with [tryParse].
class X509Certificate {
  X509Certificate._({
    required this.der,
    required this.tbsDer,
    required this.serialNumber,
    required this.signatureAlgorithmOid,
    required this.signatureAlgorithmParameters,
    required this.signature,
    required this.issuerDer,
    required this.subjectDer,
    required this.notBefore,
    required this.notAfter,
    required this.subjectPublicKeyInfoDer,
    required this.publicKeyAlgorithmOid,
    required this.subjectKeyIdentifier,
    required this.authorityKeyIdentifier,
    required this.basicConstraintsCa,
    required this.keyUsage,
  });

  /// The certificate's own DER, verbatim: what a trust store stores and what
  /// the fingerprints are taken over.
  final Uint8List der;

  /// The `tbsCertificate` element's DER, verbatim: the signature input.
  final Uint8List tbsDer;

  final BigInt serialNumber;

  /// The **outer** `signatureAlgorithm` OID (RFC 5280 requires it to equal
  /// the inner `tbsCertificate.signature`; this layer does not enforce the
  /// equality: OpenSSL's default verify does not either).
  final String signatureAlgorithmOid;

  /// The raw DER of the signature algorithm's `parameters` field, or `null`
  /// when absent. RSASSA-PSS carries its whole configuration here.
  final Uint8List? signatureAlgorithmParameters;

  /// `signatureValue` payload, unused-bits octet removed.
  final Uint8List signature;

  /// The `issuer`/`subject` `Name` elements' DER, verbatim, the primary
  /// comparands for path building (raw byte-compare first).
  final Uint8List issuerDer;
  final Uint8List subjectDer;

  final DateTime notBefore;
  final DateTime notAfter;

  /// The `subjectPublicKeyInfo` element's DER, verbatim: fed to the shared
  /// SPKI parser by [publicKey].
  final Uint8List subjectPublicKeyInfoDer;

  /// The SPKI algorithm OID (`1.2.840.113549.1.1.1`, `1.2.840.10045.2.1`, ...).
  final String publicKeyAlgorithmOid;

  /// `2.5.29.14` subjectKeyIdentifier, or `null` when the extension is absent.
  final Uint8List? subjectKeyIdentifier;

  /// `2.5.29.35` authorityKeyIdentifier's `keyIdentifier` field (`[0]`), or
  /// `null` when the extension (or that field) is absent.
  final Uint8List? authorityKeyIdentifier;

  /// `2.5.29.19` basicConstraints `cA`, or `null` when the extension is
  /// absent (RFC 5280's DEFAULT FALSE is *not* applied here: "absent" and
  /// "present and false" are different inputs to the path builder's CA
  /// check).
  final bool? basicConstraintsCa;

  /// `2.5.29.15` keyUsage bits in RFC 5280 order, or `null` when the
  /// extension is absent (path building checks `keyCertSign` only when
  /// present).
  final List<bool>? keyUsage;

  SubjectPublicKey? _publicKey;
  bool _publicKeyResolved = false;

  /// The parsed public key, via the SPKI parser **shared** with Chip and
  /// Active Authentication: `null` for an SPKI that parser cannot produce a
  /// key from (unknown algorithm OID, malformed structure, non-prime-field EC
  /// parameters), which the verdict layer maps to `unsupported_algorithm`.
  SubjectPublicKey? get publicKey {
    if (!_publicKeyResolved) {
      _publicKeyResolved = true;
      _publicKey = parseSubjectPublicKeyInfo(subjectPublicKeyInfoDer);
    }
    return _publicKey;
  }

  /// `keyUsage.keyCertSign` (bit 5), or `null` when keyUsage is absent.
  bool? get keyCertSign {
    final ku = keyUsage;
    if (ku == null) {
      return null;
    }
    return ku.length > 5 && ku[5];
  }

  /// Subject == issuer by raw DER: the cheap half of "is this an anchor".
  bool get isSelfIssued => _sameBytes(subjectDer, issuerDer);

  /// Upstream `getFingerprint()`: SHA-1 over the whole DER, colon-separated
  /// uppercase hex (`binToHexRep` joined by `":"`).
  String get fingerprintSha1 => _colonHex(calcSHA1Hash(der));

  /// SHA-256 over the whole DER, plain lowercase hex, the server-side
  /// verifier's audit format (dart-only surface). This is the trust store's
  /// dedup key.
  String get fingerprintSha256 =>
      binToHexRep(calcSHA256Hash(der)).toLowerCase();

  /// Upstream `getSubjectName()`/`getIssuerName()`: an RFC 2253-style string
  /// with short attribute names, most-specific RDN first, comma-separated
  /// (`X509_NAME_print_ex` with `XN_FLAG_DN_REV | XN_FLAG_FN_SN |
  /// XN_FLAG_SEP_COMMA_PLUS`). Escaping follows RFC 2253; unknown attribute
  /// types render as their dotted OID (upstream dumps them as hex: a display
  /// divergence).
  String get subjectString => formatDistinguishedName(subjectDer);
  String get issuerString => formatDistinguishedName(issuerDer);

  /// The DN with case folded and internal whitespace collapsed: the fallback
  /// comparand when raw DER differs (OpenSSL's `X509_NAME_cmp`
  /// canonicalizes, so a case-differing chain must still build).
  String get normalizedSubject => _normalizeDn(subjectDer);
  String get normalizedIssuer => _normalizeDn(issuerDer);

  /// Upstream `getSerialNumber()`: uppercase hex (no `0x`, no padding).
  String get serialNumberHex {
    final s = serialNumber.abs().toRadixString(16).toUpperCase();
    return serialNumber.isNegative ? '-$s' : s;
  }

  /// Upstream `certToPEM()`.
  String toPem() {
    final b64 = _base64(der);
    final lines = <String>[];
    for (var i = 0; i < b64.length; i += 64) {
      lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
    }
    return '-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n'
        '-----END CERTIFICATE-----\n';
  }

  /// Whether [at] falls inside `[notBefore, notAfter]`: the one check
  /// upstream leaves ON (`X509_STORE_set_flags(ctx, 0)`).
  bool isValidAt(DateTime at) {
    final t = at.toUtc();
    return !t.isBefore(notBefore) && !t.isAfter(notAfter);
  }

  /// Upstream `getItemsAsDict()`, as a typed object.
  X509CertificateInfo get info {
    final (publicKeyBits, publicKeyCurve) = switch (publicKey) {
      SpkiRsaPublicKey(:final modulus) => (modulus.bitLength, null),
      SpkiEcPublicKey(:final domain) => (
        domain.curve.fieldSize,
        domain.domainName == explicitEcDomainName ? null : domain.domainName,
      ),
      SpkiDhPublicKey(:final p) => (p.bitLength, null),
      null => (null, null),
    };
    return X509CertificateInfo(
      fingerprintSha1: fingerprintSha1,
      fingerprintSha256: fingerprintSha256,
      subject: subjectString,
      issuer: issuerString,
      serialNumber: serialNumberHex,
      signatureAlgorithm: algorithmDisplayName(signatureAlgorithmOid),
      publicKeyAlgorithm: algorithmDisplayName(publicKeyAlgorithmOid),
      publicKeyBits: publicKeyBits,
      publicKeyCurve: publicKeyCurve,
      notBefore: notBefore.toIso8601String(),
      notAfter: notAfter.toIso8601String(),
      subjectKeyIdentifier: subjectKeyIdentifier == null
          ? null
          : binToHexRep(subjectKeyIdentifier!).toLowerCase(),
      authorityKeyIdentifier: authorityKeyIdentifier == null
          ? null
          : binToHexRep(authorityKeyIdentifier!).toLowerCase(),
      isCa: basicConstraintsCa,
      keyCertSign: keyCertSign,
    );
  }

  /// Parses one DER certificate. `null` on anything malformed, including a
  /// trailing-garbage encoding, which a tolerant store counts as skipped
  /// rather than accepting half of.
  static X509Certificate? tryParse(List<int> der) {
    final bytes = der is Uint8List ? der : Uint8List.fromList(der);
    final root = parseAsn1(bytes);
    if (root == null ||
        root.tag != Asn1Tag.sequence ||
        root.end != bytes.length ||
        root.childCount < 3) {
      return null;
    }
    final tbs = root.child(0)!;
    final sigAlg = root.child(1)!;
    final sigValue = root.child(2)!;
    if (tbs.tag != Asn1Tag.sequence || sigAlg.tag != Asn1Tag.sequence) {
      return null;
    }
    final signature = bitStringBytes(sigValue);
    if (signature == null) {
      return null;
    }
    final sigAlgOid = oidOf(sigAlg.child(0));
    if (sigAlgOid == null) {
      return null;
    }
    final sigAlgParams = sigAlg.childCount >= 2
        ? sigAlg.child(1)!.encoded
        : null;

    // --- TBSCertificate fields, walked positionally around the optional
    // [0] EXPLICIT version.
    final fields = tbs.children;
    if (fields == null || fields.isEmpty) {
      return null;
    }
    var i = 0;
    if (fields[i].tag == 0xA0) {
      i++; // version [0] EXPLICIT: value unused (v1/v2/v3 all parse alike)
    }
    if (i + 5 >= fields.length) {
      return null; // serial, sigAlg, issuer, validity, subject, spki
    }
    final serial = integerOf(fields[i++]);
    if (serial == null) {
      return null;
    }
    final innerSigAlg = fields[i++];
    if (innerSigAlg.tag != Asn1Tag.sequence) {
      return null;
    }
    final issuer = fields[i++];
    final validity = fields[i++];
    final subject = fields[i++];
    final spki = fields[i++];
    if (issuer.tag != Asn1Tag.sequence ||
        subject.tag != Asn1Tag.sequence ||
        validity.tag != Asn1Tag.sequence ||
        validity.childCount < 2 ||
        spki.tag != Asn1Tag.sequence ||
        spki.childCount < 2) {
      return null;
    }
    final notBefore = decodeAsn1Time(validity.child(0));
    final notAfter = decodeAsn1Time(validity.child(1));
    if (notBefore == null || notAfter == null) {
      return null;
    }
    final spkiAlg = spki.child(0)!;
    final pubKeyAlgOid = spkiAlg.tag == Asn1Tag.sequence
        ? oidOf(spkiAlg.child(0))
        : null;
    if (pubKeyAlgOid == null) {
      return null;
    }

    // --- extensions [3] EXPLICIT (v3 only; [1]/[2] unique ids skipped).
    Uint8List? ski;
    Uint8List? aki;
    bool? ca;
    List<bool>? keyUsage;
    for (; i < fields.length; i++) {
      if (fields[i].tag != 0xA3) {
        continue;
      }
      final seq = fields[i].child(0);
      if (seq == null || seq.tag != Asn1Tag.sequence) {
        return null;
      }
      for (final ext in seq.children ?? const <Asn1Node>[]) {
        if (ext.tag != Asn1Tag.sequence || ext.childCount < 2) {
          return null;
        }
        final oid = oidOf(ext.child(0));
        final value = ext.children!.last;
        if (oid == null || value.tag != Asn1Tag.octetString) {
          return null;
        }
        // Tolerant reader: an extension whose `extnValue` does not hold the
        // encoding RFC 5280 specifies is **ignored**, not fatal. Fielded CSCA
        // certificates carry such defects (three of the 720 in upstream's
        // `masterList.pem` encode subjectKeyIdentifier as a bare key id with
        // no inner `OCTET STRING` wrapper) and OpenSSL parses those
        // certificates too; it only fails when the extension is *asked for*.
        // The field simply stays null, and path building falls back to the DN
        // comparison.
        final inner = parseAsn1Inside(value);
        if (inner == null) {
          continue;
        }
        switch (oid) {
          case _oidSubjectKeyIdentifier:
            if (inner.tag == Asn1Tag.octetString) {
              ski = Uint8List.fromList(inner.content);
            }
          case _oidAuthorityKeyIdentifier:
            if (inner.tag == Asn1Tag.sequence) {
              for (final f in inner.children ?? const <Asn1Node>[]) {
                if (f.tag == 0x80) {
                  aki = Uint8List.fromList(f.content); // keyIdentifier [0]
                }
              }
            }
          case _oidBasicConstraints:
            if (inner.tag == Asn1Tag.sequence) {
              final first = inner.child(0);
              ca = first != null && first.tag == Asn1Tag.boolean
                  ? booleanOf(first) ?? false
                  : false; // cA DEFAULT FALSE
            }
          case _oidKeyUsage:
            keyUsage = bitStringFlags(inner);
        }
      }
    }

    return X509Certificate._(
      der: bytes,
      tbsDer: Uint8List.fromList(tbs.encoded),
      serialNumber: serial,
      signatureAlgorithmOid: sigAlgOid,
      signatureAlgorithmParameters: sigAlgParams == null
          ? null
          : Uint8List.fromList(sigAlgParams),
      signature: Uint8List.fromList(signature),
      issuerDer: Uint8List.fromList(issuer.encoded),
      subjectDer: Uint8List.fromList(subject.encoded),
      notBefore: notBefore,
      notAfter: notAfter,
      subjectPublicKeyInfoDer: Uint8List.fromList(spki.encoded),
      publicKeyAlgorithmOid: pubKeyAlgOid,
      subjectKeyIdentifier: ski,
      authorityKeyIdentifier: aki,
      basicConstraintsCa: ca,
      keyUsage: keyUsage,
    );
  }
}

/// Upstream `getItemsAsDict()`'s payload as a value object. Purely a
/// display/diagnostic surface: no verification reads it.
class X509CertificateInfo {
  const X509CertificateInfo({
    required this.fingerprintSha1,
    required this.fingerprintSha256,
    required this.subject,
    required this.issuer,
    required this.serialNumber,
    required this.signatureAlgorithm,
    required this.publicKeyAlgorithm,
    required this.notBefore,
    required this.notAfter,
    this.publicKeyBits,
    this.publicKeyCurve,
    this.subjectKeyIdentifier,
    this.authorityKeyIdentifier,
    this.isCa,
    this.keyCertSign,
  });

  /// Upstream's `CertificateItem.fingerprint`: SHA-1, colon-hex.
  final String fingerprintSha1;

  /// SHA-256, plain lowercase hex, no upstream analogue.
  final String fingerprintSha256;

  final String subject;
  final String issuer;

  /// Uppercase hex (upstream format).
  final String serialNumber;

  /// OpenSSL long names where known (`sha256WithRSAEncryption`,
  /// `id-ecPublicKey`, ...), else the dotted OID.
  final String signatureAlgorithm;
  final String publicKeyAlgorithm;

  /// The public key's width in bits, on the one axis OpenSSL's
  /// `EVP_PKEY_bits` uses: the modulus bit length for RSA (2048, 3072,
  /// 4096), the prime field's bit length for EC (256 for P-256, 521 for
  /// P-521), the group prime's for DH. Null when the SPKI is one
  /// `parseSubjectPublicKeyInfo` rejects (no upstream analogue).
  /// Derived from the parsed key, never from the encoded key's length.
  final int? publicKeyBits;

  /// The EC key's curve, in the parser's registry vocabulary (`secp256r1`,
  /// `brainpoolp256r1`, ...). Null for RSA and DH keys, for an unusable SPKI,
  /// and for an EC key with explicit `ECParameters`, which name no curve.
  final String? publicKeyCurve;

  /// ISO-8601 UTC: upstream renders `ASN1_TIME_print` text instead.
  final String notBefore;
  final String notAfter;

  final String? subjectKeyIdentifier;
  final String? authorityKeyIdentifier;

  /// basicConstraints `cA`; `null` when the extension is absent.
  final bool? isCa;

  /// keyUsage `keyCertSign`; `null` when the extension is absent.
  final bool? keyCertSign;
}

// --- distinguished names ----------------------------------------------------

/// Attribute-type OIDs -> OpenSSL short names (`XN_FLAG_FN_SN`).
const Map<String, String> _dnShortNames = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'street',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.13': 'description',
  '2.5.4.42': 'GN',
  '2.5.4.43': 'initials',
  '2.5.4.44': 'generationQualifier',
  '2.5.4.45': 'x500UniqueIdentifier',
  '2.5.4.46': 'dnQualifier',
  '2.5.4.65': 'pseudonym',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

/// A `Name` element's DER rendered the way `X509_NAME_print_ex` does under
/// upstream's flag set: RDNs most-specific first (`XN_FLAG_DN_REV`), short
/// type names, `,` between RDNs and `+` inside a multi-valued one.
String formatDistinguishedName(List<int> nameDer) {
  final avas = _parseDn(nameDer);
  if (avas == null) {
    return '';
  }
  return avas.reversed
      .map(
        (rdn) => rdn
            .map((ava) => '${ava.type}=${_escapeDnValue(ava.value)}')
            .join('+'),
      )
      .join(',');
}

class _Ava {
  const _Ava(this.type, this.value);
  final String type;
  final String value;
}

/// `Name ::= RDNSequence`; `RelativeDistinguishedName ::= SET OF
/// AttributeTypeAndValue`. Returns RDNs in encoding order, each a list of
/// AVAs. `null` on a malformed name.
List<List<_Ava>>? _parseDn(List<int> nameDer) {
  final bytes = nameDer is Uint8List ? nameDer : Uint8List.fromList(nameDer);
  final root = parseAsn1(bytes);
  if (root == null || root.tag != Asn1Tag.sequence) {
    return null;
  }
  final out = <List<_Ava>>[];
  for (final rdn in root.children ?? const <Asn1Node>[]) {
    if (rdn.tag != Asn1Tag.set) {
      return null;
    }
    final avas = <_Ava>[];
    for (final ava in rdn.children ?? const <Asn1Node>[]) {
      if (ava.tag != Asn1Tag.sequence || ava.childCount < 2) {
        return null;
      }
      final oid = oidOf(ava.child(0));
      if (oid == null) {
        return null;
      }
      final value =
          decodeAsn1String(ava.child(1)) ??
          binToHexRep(ava.child(1)!.encoded); // DUMP_UNKNOWN fallback
      avas.add(_Ava(_dnShortNames[oid] ?? oid, value));
    }
    out.add(avas);
  }
  return out;
}

/// RFC 2253 §2.4 escaping (`ASN1_STRFLGS_ESC_2253`).
String _escapeDnValue(String value) {
  final buf = StringBuffer();
  for (var i = 0; i < value.length; i++) {
    final ch = value[i];
    final leadingOrTrailing =
        (i == 0 && (ch == ' ' || ch == '#')) ||
        (i == value.length - 1 && ch == ' ');
    if (leadingOrTrailing || ',+"\\<>;'.contains(ch)) {
      buf.write('\\');
    }
    final code = value.codeUnitAt(i);
    if (code < 0x20 || code == 0x7F) {
      buf.write('\\${code.toRadixString(16).padLeft(2, '0').toUpperCase()}');
      continue;
    }
    buf.write(ch);
  }
  return buf.toString();
}

/// The normalized comparand: type names plus case-folded, whitespace-
/// collapsed values, in **encoding** order (so it is a pure function of the
/// name, independent of display reversal).
String _normalizeDn(List<int> nameDer) {
  final rdns = _parseDn(nameDer);
  if (rdns == null) {
    return '';
  }
  return rdns
      .map(
        (rdn) =>
            (rdn
                    .map(
                      (ava) =>
                          '${ava.type.toLowerCase()}=${_normalizeDnValue(ava.value)}',
                    )
                    .toList()
                  ..sort()) // a SET is unordered: sort so encoding order cannot matter
                .join('+'),
      )
      .join(',');
}

String _normalizeDnValue(String value) =>
    value.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();

// --- algorithm display names ------------------------------------------------

/// OpenSSL `OBJ_nid2ln` long names for the algorithm OIDs this subsystem can
/// meet; anything else renders as its dotted OID (upstream would print the
/// numeric form too, via `OBJ_obj2nid` -> `NID_undef` -> nil).
const Map<String, String> _algorithmLongNames = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.14': 'sha224WithRSAEncryption',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.1': 'ecdsa-with-SHA224',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10040.4.1': 'dsaEncryption',
  '1.2.840.10040.4.3': 'dsaWithSHA1',
  '2.16.840.1.101.3.4.3.2': 'dsa_with_SHA256',
  '1.3.101.112': 'ED25519',
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '2.16.840.1.101.3.4.2.4': 'sha224',
};

/// The OpenSSL long name for [oid], or [oid] itself when unknown.
String algorithmDisplayName(String oid) => _algorithmLongNames[oid] ?? oid;

// --- small helpers ----------------------------------------------------------

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

String _colonHex(List<int> bytes) => bytes
    .map((b) => b.toRadixString(16).padLeft(2, '0').toUpperCase())
    .join(':');

String _base64(List<int> bytes) => base64.encode(bytes);
