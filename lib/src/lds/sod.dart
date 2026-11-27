// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/SOD.swift @ 3bf5456 (2.3.2)
//   Of SOD.swift's 240 lines roughly 45 survive: `init`/`parse`,
//   `pkcs7CertificateData`, `getEncapsulatedContent`, and the RFC 5652
//   layout comment. The OpenSSL PKCS7/passive-auth machinery (`asn1` as
//   `ASN1Item`, `pubKey`/`deinit`, `getPublicKey`,
//   `getEncapsulatedContentDigestAlgorithm`, `getSignedAttributes`,
//   `getMessageDigestFromSignedAttributes`, `getSignature`,
//   `getSignatureAlgorithm`) serves dropped passive-auth getters.

/// EF.SOD: raw CMS bytes + encapsulated-content extraction for the hash
/// oracle, over a `TlvRecord` tree replacing the OpenSSL
/// `ASN1_parse_dump`-to-text hack, as `CardAccess` does.
///
/// Format of SOD: ASN1 - Signed Data (taken from rfc5652 -
/// https://tools.ietf.org/html/rfc5652): the SOD is a CMS container of type
/// Signed-data.
/// ```text
/// Sequence
///   Object ID: signedData
///   Content: SignedData
///       SignedData ::= SEQUENCE {
///           INTEGER version CMSVersion,
///           SET digestAlgorithms DigestAlgorithmIdentifiers,
///           SEQUENCE encapContentInfo EncapsulatedContentInfo,
///           certificates [0] IMPLICIT CertificateSet OPTIONAL,
///           crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///           SET signerInfos SignerInfos }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///    eContentType ContentType,
///    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
///
/// As upstream, CMS navigation is purely positional, with no OID checks
/// anywhere: a file with wrong content-type OIDs still parses. Unlike
/// upstream, a constructor parse failure throws [InvalidASN1Value] (upstream:
/// `OpenSSLError.UnableToParseASN1`), and walk failures throw
/// [InvalidDataPassed] with upstream's `UnableToExtractSignedDataFromPKCS7`
/// reason strings verbatim; the raw value bytes are returned directly and a
/// constructed `0x24` OCTET STRING is rejected, so upstream's hex-text
/// round-trip artifacts are not reproduced.
library;

import 'dart:typed_data';

import '../errors.dart';
import 'data_group.dart';
import 'data_group_id.dart';
import 'tlv.dart';

/// Upstream `SOD`.
class SOD extends DataGroup {
  /// Upstream `init(_:)`: the eager full-tree validation runs from the base
  /// constructor via [parse], so `SOD(garbage)` throws at
  /// construction, as upstream's `SimpleASN1DumpParser` did.
  SOD(super.data) {
    pkcs7CertificateData = body;
  }

  /// Upstream `pkcs7CertificateData`: the full CMS blob (== [body]).
  late final Uint8List pkcs7CertificateData;

  late final _Asn1Node _asn1;

  @override
  DataGroupId get datagroupType => DataGroupId.SOD;

  @override
  void parse(List<int> data) {
    // Eager recursive parse of the whole CMS tree (upstream:
    // `ASN1_parse_dump` over body -> OpenSSLError.UnableToParseASN1, mapped
    // to InvalidASN1Value, as CardAccess maps it).
    final root = TlvRecord.parse(body);
    if (root == null) {
      throw const InvalidASN1Value();
    }
    _asn1 = _Asn1Node.parse(root);
  }

  /// Upstream `getEncapsulatedContent()`: extracts the encapsulated
  /// content section from a SignedData PKCS7 container (if present).
  ///
  /// The same index-only navigation as upstream: root child 1 (`[0]`
  /// content) -> child 0 (SignedData) -> child 2 (EncapsulatedContentInfo)
  /// -> child 1 (`[0]` eContent wrapper) -> child 0, with no OID checks
  /// anywhere. The final node must be a primitive OCTET STRING (`0x04`); its
  /// raw value bytes are returned (replacing upstream's hex-dump-text
  /// round-trip; a constructed `0x24` is rejected).
  Uint8List getEncapsulatedContent() {
    final signedData = _asn1.getChild(1)?.getChild(0);
    final encContent = signedData?.getChild(2)?.getChild(1);
    final content = encContent?.getChild(0);
    if (content == null) {
      throw const InvalidDataPassed('Data in invalid format');
    }
    if (content.record.tag != 0x04) {
      throw const InvalidDataPassed('noDataReturned');
    }
    return content.record.value;
  }
}

/// Eagerly-parsed ASN.1 tree node: the `TlvRecord` replacement for
/// upstream's `ASN1Item`. Children exist for constructed tags only;
/// any malformed nesting throws [InvalidASN1Value] at construction.
class _Asn1Node {
  _Asn1Node._(this.record, this.children);

  final TlvRecord record;
  final List<_Asn1Node>? children;

  static _Asn1Node parse(TlvRecord record) {
    if (!_isConstructed(record.tag)) {
      return _Asn1Node._(record, null);
    }
    final kids = TlvRecord.sequenceOfRecords(record.value);
    if (kids == null) {
      throw const InvalidASN1Value(); // eager whole-tree validation
    }
    return _Asn1Node._(record, [for (final k in kids) parse(k)]);
  }

  /// Upstream `ASN1Item.getChild(_:)`: nil out of range or on a primitive.
  _Asn1Node? getChild(int i) {
    final c = children;
    if (c == null || i < 0 || i >= c.length) {
      return null;
    }
    return c[i];
  }

  /// BER constructed bit (0x20) of the first tag byte.
  static bool _isConstructed(int tag) {
    var t = tag;
    while (t > 0xFF) {
      t >>= 8;
    }
    return t & 0x20 != 0;
  }
}
