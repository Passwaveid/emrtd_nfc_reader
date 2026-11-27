// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/CardAccess.swift @ 3bf5456 (2.3.2)
//   The internal `asn1 : ASN1Item` field and the `SimpleASN1DumpParser`
//   dependency are dropped: the OpenSSL `ASN1_parse_dump`-to-text hack is
//   replaced by a `TlvRecord` walk.

/// EF.CardAccess parsing over `TlvRecord`. `SecurityInfos ::= SET OF
/// SecurityInfo`; each `SecurityInfo ::= SEQUENCE { protocol OID, requiredData,
/// optionalData OPTIONAL }`.
///
/// As upstream, the first `PACEInfo` in file order wins, with no suite
/// preference. An unparseable file throws [InvalidASN1Value], where upstream
/// threw the dropped `OpenSSLError.UnableToParseASN1`. The 3-child rule and
/// the skipping of malformed entries live in [SecurityInfo.getInstance].
library;

import '../errors.dart';
import 'pace_info.dart';
import 'security_info.dart';
import 'tlv.dart';

/// Upstream `CardAccess`.
class CardAccess {
  /// Upstream `init(_ data:)`. Throws [InvalidASN1Value] on an unparseable
  /// file.
  CardAccess(List<int> data) {
    // Root is `SecurityInfos ::= SET OF SecurityInfo`. TlvRecord.parse reads
    // the outer SET; its value is a back-to-back sequence of SecurityInfo
    // SEQUENCEs.
    final root = TlvRecord.parse(data);
    if (root == null) {
      throw const InvalidASN1Value();
    }
    final children = TlvRecord.sequenceOfRecords(root.value);
    if (children == null) {
      throw const InvalidASN1Value();
    }
    for (final child in children) {
      final secInfo = SecurityInfo.getInstance(object: child, body: data);
      if (secInfo != null) {
        _securityInfos.add(secInfo);
      }
    }
  }

  final List<SecurityInfo> _securityInfos = [];

  /// Upstream `securityInfos`.
  List<SecurityInfo> get securityInfos => List.unmodifiable(_securityInfos);

  /// Upstream `paceInfo` getter. The first [PACEInfo] in file order (DER SET
  /// ordering decides; no suite preference).
  PACEInfo? get paceInfo {
    for (final info in _securityInfos) {
      if (info is PACEInfo) {
        return info;
      }
    }
    return null;
  }
}
