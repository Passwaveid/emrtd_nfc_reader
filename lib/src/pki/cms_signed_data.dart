// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/SOD.swift @ 8fc6eed (2.3.2
//   fork), the passive-auth getters the port's `SOD` deliberately leaves out
//   (`getPublicKey`, `getEncapsulatedContentDigestAlgorithm`,
//   `getSignedAttributes`, `getMessageDigestFromSignedAttributes`,
//   `getSignature`, `getSignatureAlgorithm`), realized here as a structured
//   CMS model rather than added to `SOD`, whose surface stays as it is.
//   Certificate extraction ports `OpenSSLUtils.getX509CertificatesFromPKCS7`
//   (:112-151).
//
//   The `0xA0`->`0x31` signed-attributes re-tag (SOD.swift:156-158) is carried
//   over byte-for-byte; it is also what the server-side verifier this
//   package was built alongside does.

/// RFC 5652 `SignedData`: the CMS model passive authentication verifies over.
///
/// Deliberately narrow: only what the SOD and the CSCA master list need. No
/// enveloped/digested/encrypted content types, no CRLs, no unsigned
/// attributes, no counter-signatures, none of which appear in either
/// container and none of which upstream reads either.
///
/// **Total** ([CmsSignedData.parse] never throws): hostile input becomes a
/// [CmsMalformed] the verdict layer maps to `malformed_sod`, where upstream
/// force-unwraps and crashes.
///
/// Strictness *checks* live one layer up (`passive_auth.dart` / the trust
/// store) so this file stays a parser: it models `eContentType` and the
/// attributes, it does not decide which values are acceptable.
library;

import 'dart:typed_data';

import 'asn1_reader.dart';

/// `id-signedData`: the ContentInfo type of both the SOD and a master list.
const String oidSignedData = '1.2.840.113549.1.7.2';

/// `id-icao-ldsSecurityObject`: the SOD's eContentType (P10 SignedData
/// profile).
const String oidLdsSecurityObject = '2.23.136.1.1.1';

/// `id-icao-cscaMasterList`: a CSCA master list's eContentType (P12 §9).
const String oidCscaMasterList = '2.23.136.1.1.2';

/// `id-contentType` signed attribute (RFC 5652 §11.1).
const String oidContentTypeAttribute = '1.2.840.113549.1.9.3';

/// `id-messageDigest` signed attribute (RFC 5652 §11.2).
const String oidMessageDigestAttribute = '1.2.840.113549.1.9.4';

/// Outcome of [CmsSignedData.parse]: a model, or the reason it is not one.
sealed class CmsParseOutcome {
  const CmsParseOutcome();
}

/// A successfully modeled `SignedData`.
final class CmsParsed extends CmsParseOutcome {
  const CmsParsed(this.data);
  final CmsSignedData data;
}

/// Structurally unusable input; [reason] is diagnostic, never user copy.
final class CmsMalformed extends CmsParseOutcome {
  const CmsMalformed(this.reason);
  final String reason;
}

/// How a `SignerInfo` names its certificate.
sealed class CmsSignerId {
  const CmsSignerId();
}

/// `IssuerAndSerialNumber`: the form every fielded SOD uses.
final class CmsIssuerAndSerial extends CmsSignerId {
  const CmsIssuerAndSerial({
    required this.issuerDer,
    required this.serialNumber,
  });

  /// The issuer `Name` element's DER, verbatim.
  final Uint8List issuerDer;
  final BigInt serialNumber;
}

/// `subjectKeyIdentifier [0]`: the CMS v3 form.
final class CmsSubjectKeyIdentifier extends CmsSignerId {
  const CmsSubjectKeyIdentifier(this.keyIdentifier);
  final Uint8List keyIdentifier;
}

/// One `SignerInfo`.
class CmsSignerInfo {
  const CmsSignerInfo({
    required this.version,
    required this.signerId,
    required this.digestAlgorithmOid,
    required this.signedAttributesDer,
    required this.signedAttributes,
    required this.signatureAlgorithmOid,
    required this.signatureAlgorithmParameters,
    required this.signature,
  });

  final int version;
  final CmsSignerId signerId;

  /// The `digestAlgorithm` OID: the digest the `messageDigest` attribute is
  /// taken with, and (for a plain-`rsaEncryption` signature algorithm) the
  /// digest the signature itself uses (the RFC 3370 §3.2 form).
  final String digestAlgorithmOid;

  /// The `signedAttrs [0] IMPLICIT` element's **original** DER, verbatim, or
  /// `null` when the field is absent.
  final Uint8List? signedAttributesDer;

  /// The parsed attributes, in encoding order.
  final List<CmsAttribute> signedAttributes;

  final String signatureAlgorithmOid;

  /// Raw DER of the signature algorithm's `parameters`, or `null` when
  /// absent. RSASSA-PSS carries hash/MGF/salt here.
  final Uint8List? signatureAlgorithmParameters;

  /// The `signature` OCTET STRING's content.
  final Uint8List signature;

  /// RFC 5652 §5.4's signature input: the signed attributes re-tagged from
  /// `[0] IMPLICIT` (`0xA0`) to `SET OF` (`0x31`).
  ///
  /// For the definite-length encoding every real SOD uses this is upstream's
  /// literal byte-swap (SOD.swift:156-158); the bytes are otherwise
  /// untouched, so no re-encode can reorder or re-length anything.
  /// A BER **indefinite**-length `signedAttrs` cannot be fixed by a byte
  /// swap (the `0x80` length would survive into the digest input), so it is
  /// re-headered as a definite-length `SET` over the attributes' original
  /// encodings, in their original order, the same bytes upstream would have
  /// hashed had the encoder used definite lengths.
  Uint8List? get signedAttributesForVerification {
    final raw = signedAttributesDer;
    if (raw == null) {
      return null;
    }
    if (raw.length >= 2 && raw[1] == 0x80) {
      final body = <int>[for (final a in signedAttributes) ...a.encoded];
      return Uint8List.fromList([0x31, ..._derLength(body.length), ...body]);
    }
    final out = Uint8List.fromList(raw);
    if (out.isNotEmpty && out[0] == 0xA0) {
      out[0] = 0x31;
    }
    return out;
  }

  /// The first attribute with [oid], or `null`.
  CmsAttribute? attribute(String oid) {
    for (final a in signedAttributes) {
      if (a.oid == oid) {
        return a;
      }
    }
    return null;
  }

  /// The `contentType` signed attribute's OID value (RFC 5652 §11.1); `null`
  /// when the attribute is absent or not a single OID.
  String? get contentTypeAttribute {
    final values = attribute(oidContentTypeAttribute)?.values;
    if (values == null || values.length != 1) {
      return null;
    }
    return oidOf(values.single);
  }

  /// The `messageDigest` signed attribute's OCTET STRING value (RFC 5652
  /// §11.2); `null` when absent or not a single OCTET STRING.
  Uint8List? get messageDigestAttribute {
    final values = attribute(oidMessageDigestAttribute)?.values;
    if (values == null ||
        values.length != 1 ||
        values.single.tag != Asn1Tag.octetString) {
      return null;
    }
    return Uint8List.fromList(values.single.content);
  }
}

/// One `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }`.
class CmsAttribute {
  const CmsAttribute({
    required this.oid,
    required this.values,
    required this.encoded,
  });

  final String oid;

  /// The `attrValues` SET members, unparsed.
  final List<Asn1Node> values;

  /// The attribute's own DER, verbatim.
  final Uint8List encoded;
}

/// A parsed CMS `SignedData`.
class CmsSignedData {
  const CmsSignedData._({
    required this.version,
    required this.digestAlgorithmOids,
    required this.eContentType,
    required this.eContent,
    required this.certificates,
    required this.signerInfos,
  });

  final int version;

  /// The SignedData-level `digestAlgorithms` OIDs. Upstream's
  /// `getEncapsulatedContentDigestAlgorithm` reads `[0]` of this set; the
  /// port takes the message-digest algorithm from the SignerInfo instead
  /// (RFC 5652 §5.4; see UPSTREAM.md, Divergences), a difference invisible
  /// on any well-formed SOD, where the two agree.
  final List<String> digestAlgorithmOids;

  final String eContentType;

  /// The encapsulated content octets, with a BER-segmented OCTET STRING
  /// reassembled; `null` when `eContent` is absent (a detached signature:
  /// legal CMS, never a valid SOD).
  final Uint8List? eContent;

  /// `certificates [0] IMPLICIT`, each verbatim DER, in encoding order.
  /// Upstream takes `.first!` here; the port's callers handle empty.
  final List<Uint8List> certificates;

  final List<CmsSignerInfo> signerInfos;

  /// Parses a `ContentInfo` wrapping `SignedData`: for the SOD this is
  /// `SOD.pkcs7CertificateData` (the CMS blob, `77` wrapper already stripped
  /// by `SOD`). A bare `SignedData` SEQUENCE is also accepted, mirroring
  /// `d2i_PKCS7_bio`'s tolerance of both shapes.
  static CmsParseOutcome parse(List<int> der) {
    final bytes = der is Uint8List ? der : Uint8List.fromList(der);
    final root = parseAsn1(bytes);
    if (root == null || root.tag != Asn1Tag.sequence) {
      return const CmsMalformed('not a DER/BER SEQUENCE');
    }

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    Asn1Node signedData;
    final first = root.child(0);
    if (first != null && first.tag == Asn1Tag.oid) {
      if (oidOf(first) != oidSignedData) {
        return CmsMalformed(
          'ContentInfo type is not id-signedData '
          '(${oidOf(first)})',
        );
      }
      final wrapper = root.child(1);
      final inner = wrapper?.child(0);
      if (wrapper == null || wrapper.tag != 0xA0 || inner == null) {
        return const CmsMalformed('ContentInfo carries no [0] content');
      }
      signedData = inner;
    } else {
      signedData = root; // bare SignedData
    }
    if (signedData.tag != Asn1Tag.sequence || signedData.childCount < 4) {
      return const CmsMalformed('SignedData is not a 4+ element SEQUENCE');
    }

    final fields = signedData.children!;
    final version = integerOf(fields[0]);
    if (version == null) {
      return const CmsMalformed('SignedData.version is not an INTEGER');
    }
    if (fields[1].tag != Asn1Tag.set) {
      return const CmsMalformed('SignedData.digestAlgorithms is not a SET');
    }
    final digestOids = <String>[];
    for (final alg in fields[1].children ?? const <Asn1Node>[]) {
      final oid = alg.tag == Asn1Tag.sequence ? oidOf(alg.child(0)) : null;
      if (oid == null) {
        return const CmsMalformed('malformed digestAlgorithms entry');
      }
      digestOids.add(oid);
    }

    // EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] }
    final encap = fields[2];
    if (encap.tag != Asn1Tag.sequence || encap.childCount < 1) {
      return const CmsMalformed('malformed encapContentInfo');
    }
    final eContentType = oidOf(encap.child(0));
    if (eContentType == null) {
      return const CmsMalformed('encapContentInfo has no eContentType OID');
    }
    Uint8List? eContent;
    if (encap.childCount >= 2) {
      final wrapper = encap.child(1)!;
      if (wrapper.tag != 0xA0 || wrapper.childCount < 1) {
        return const CmsMalformed('malformed eContent [0] wrapper');
      }
      final octets = _octetStringBytes(wrapper.child(0)!);
      if (octets == null) {
        return const CmsMalformed('eContent is not an OCTET STRING');
      }
      eContent = octets;
    }

    // certificates [0] IMPLICIT / crls [1] IMPLICIT / signerInfos SET.
    final certificates = <Uint8List>[];
    Asn1Node? signerInfoSet;
    for (var i = 3; i < fields.length; i++) {
      final f = fields[i];
      if (f.tag == 0xA0) {
        for (final c in f.children ?? const <Asn1Node>[]) {
          certificates.add(Uint8List.fromList(c.encoded));
        }
      } else if (f.tag == 0xA1) {
        // crls: never read (no revocation anywhere).
      } else if (f.tag == Asn1Tag.set) {
        signerInfoSet = f;
      } else {
        return CmsMalformed(
          'unexpected SignedData field tag 0x'
          '${f.tag.toRadixString(16)}',
        );
      }
    }
    if (signerInfoSet == null) {
      return const CmsMalformed('SignedData carries no signerInfos SET');
    }

    final signerInfos = <CmsSignerInfo>[];
    for (final si in signerInfoSet.children ?? const <Asn1Node>[]) {
      final (signer, reason) = _parseSignerInfo(si);
      if (signer == null) {
        return CmsMalformed(reason ?? 'malformed SignerInfo');
      }
      signerInfos.add(signer);
    }

    return CmsParsed(
      CmsSignedData._(
        version: version.toInt(),
        digestAlgorithmOids: digestOids,
        eContentType: eContentType,
        eContent: eContent,
        certificates: certificates,
        signerInfos: signerInfos,
      ),
    );
  }

  /// Convenience wrapper: `null` where [parse] gives a reason.
  static CmsSignedData? tryParse(List<int> der) => switch (parse(der)) {
    CmsParsed(:final data) => data,
    CmsMalformed() => null,
  };
}

/// `(signer, null)` on success, `(null, reason)` on a malformed encoding.
(CmsSignerInfo?, String?) _parseSignerInfo(Asn1Node si) {
  if (si.tag != Asn1Tag.sequence || si.childCount < 5) {
    return (null, 'SignerInfo is not a 5+ element SEQUENCE');
  }
  final f = si.children!;
  final version = integerOf(f[0]);
  if (version == null) {
    return (null, 'SignerInfo.version is not an INTEGER');
  }

  final CmsSignerId sid;
  final sidNode = f[1];
  if (sidNode.tag == Asn1Tag.sequence && sidNode.childCount >= 2) {
    final serial = integerOf(sidNode.child(1));
    if (serial == null) {
      return (null, 'IssuerAndSerialNumber has no serial INTEGER');
    }
    sid = CmsIssuerAndSerial(
      issuerDer: Uint8List.fromList(sidNode.child(0)!.encoded),
      serialNumber: serial,
    );
  } else if (sidNode.tag == 0x80) {
    sid = CmsSubjectKeyIdentifier(Uint8List.fromList(sidNode.content));
  } else {
    return (null, 'unrecognized SignerIdentifier');
  }

  if (f[2].tag != Asn1Tag.sequence) {
    return (null, 'SignerInfo.digestAlgorithm is not a SEQUENCE');
  }
  final digestOid = oidOf(f[2].child(0));
  if (digestOid == null) {
    return (null, 'SignerInfo.digestAlgorithm has no OID');
  }

  var i = 3;
  Uint8List? signedAttrsDer;
  final attributes = <CmsAttribute>[];
  if (f[i].tag == 0xA0) {
    signedAttrsDer = Uint8List.fromList(f[i].encoded);
    for (final attr in f[i].children ?? const <Asn1Node>[]) {
      if (attr.tag != Asn1Tag.sequence || attr.childCount < 2) {
        return (null, 'malformed signed attribute');
      }
      final oid = oidOf(attr.child(0));
      final valueSet = attr.child(1)!;
      if (oid == null || valueSet.tag != Asn1Tag.set) {
        return (null, 'malformed signed attribute');
      }
      attributes.add(
        CmsAttribute(
          oid: oid,
          values: valueSet.children ?? const <Asn1Node>[],
          encoded: Uint8List.fromList(attr.encoded),
        ),
      );
    }
    i++;
  }

  if (i + 1 >= f.length) {
    return (null, 'SignerInfo is missing signature fields');
  }
  final sigAlg = f[i++];
  if (sigAlg.tag != Asn1Tag.sequence) {
    return (null, 'SignerInfo.signatureAlgorithm is not a SEQUENCE');
  }
  final sigAlgOid = oidOf(sigAlg.child(0));
  if (sigAlgOid == null) {
    return (null, 'SignerInfo.signatureAlgorithm has no OID');
  }
  final sigAlgParams = sigAlg.childCount >= 2
      ? Uint8List.fromList(sigAlg.child(1)!.encoded)
      : null;

  final sigNode = f[i];
  final signature = _octetStringBytes(sigNode);
  if (signature == null) {
    return (null, 'SignerInfo.signature is not an OCTET STRING');
  }

  return (
    CmsSignerInfo(
      version: version.toInt(),
      signerId: sid,
      digestAlgorithmOid: digestOid,
      signedAttributesDer: signedAttrsDer,
      signedAttributes: attributes,
      signatureAlgorithmOid: sigAlgOid,
      signatureAlgorithmParameters: sigAlgParams,
      signature: signature,
    ),
    null,
  );
}

/// An OCTET STRING's octets, reassembling the BER constructed (segmented)
/// form real master lists carry; `null` when the node is not one.
Uint8List? _octetStringBytes(Asn1Node node) {
  if (node.tag == Asn1Tag.octetString) {
    return Uint8List.fromList(node.content);
  }
  if (node.tag == (Asn1Tag.octetString | 0x20)) {
    final out = <int>[];
    for (final seg in node.children ?? const <Asn1Node>[]) {
      final part = _octetStringBytes(seg);
      if (part == null) {
        return null;
      }
      out.addAll(part);
    }
    return Uint8List.fromList(out);
  }
  return null;
}

/// Minimal definite-form DER length, used only to re-header an indefinite
/// `signedAttrs` (the one place this layer emits bytes at all).
List<int> _derLength(int length) {
  if (length < 0x80) {
    return [length];
  }
  final bytes = <int>[];
  var rest = length;
  while (rest > 0) {
    bytes.insert(0, rest & 0xFF);
    rest >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
