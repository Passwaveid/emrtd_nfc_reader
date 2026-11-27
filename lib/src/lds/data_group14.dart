// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup14.swift @ 3bf5456 (2.3.2)
//   The internal `asn1 : ASN1Item` field and the `SimpleASN1DumpParser`
//   dependency are dropped: the OpenSSL `ASN1_parse_dump`-to-text hack is
//   replaced by a `TlvRecord` walk, exactly as [CardAccess] does.

/// DG14 (EF.DG14): the chip's security infos.
///
/// ```asn1
/// SecurityInfos ::= SET OF SecurityInfo
/// SecurityInfo  ::= SEQUENCE {
///   protocol      OBJECT IDENTIFIER,
///   requiredData  ANY DEFINED BY protocol,
///   optionalData  ANY DEFINED BY protocol OPTIONAL }
/// ```
///
/// Same structure as EF.CardAccess, so the same walk: parse the outer SET,
/// hand each child SEQUENCE to [SecurityInfo.getInstance], keep what it
/// recognizes (every branch upstream has, AA included).
/// Entries it does not are skipped, upstream's nil-return contract.
///
/// As in [CardAccess], an unparseable file throws [InvalidASN1Value]
/// (upstream threw the dropped `OpenSSLError.UnableToParseASN1`).
library;

import '../errors.dart';
import 'data_group.dart';
import 'data_group_id.dart';
import 'security_info.dart';
import 'tlv.dart';

/// Upstream `DataGroup14`.
class DataGroup14 extends DataGroup {
  DataGroup14(super.data);

  final List<SecurityInfo> _securityInfos = [];

  @override
  DataGroupId get datagroupType => DataGroupId.DG14;

  /// Upstream `securityInfos`.
  List<SecurityInfo> get securityInfos => List.unmodifiable(_securityInfos);

  @override
  void parse(List<int> data) {
    final root = TlvRecord.parse(body);
    if (root == null) {
      throw const InvalidASN1Value();
    }
    final children = TlvRecord.sequenceOfRecords(root.value);
    if (children == null) {
      throw const InvalidASN1Value();
    }
    for (final child in children) {
      final secInfo = SecurityInfo.getInstance(object: child, body: body);
      if (secInfo != null) {
        _securityInfos.add(secInfo);
      }
    }
  }
}
