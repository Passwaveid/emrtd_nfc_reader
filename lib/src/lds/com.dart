// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/COM.swift @ 3bf5456 (2.3.2)

/// EF.COM parsing.
///
/// Two upstream behaviours are kept. Version parsing reproduces Swift's
/// `Int(String(cString:))` semantics: leading zeros collapse, interior NULs
/// terminate the component, and any non-numeric component or wrong byte
/// count leaves `"Unknown"`. Bytes in the `5C` list matching no
/// `DataGroupParser.tags` entry are silently skipped, and names come from the
/// parser's table (`"Common"`/`"SecurityData"`), not `DataGroupId.getName`.
library;

import 'dart:convert';

import '../logging.dart';
import 'data_group.dart';
import 'data_group_id.dart';
import 'data_group_parser.dart';

/// Upstream `COM`.
class COM extends DataGroup {
  COM(super.data);

  /// Upstream `version`: `"a.b"` from 4 ASCII digits, else `"Unknown"`.
  String version = 'Unknown';

  /// Upstream `unicodeVersion`: `"a.b.c"` from 6 ASCII digits.
  String unicodeVersion = 'Unknown';

  /// Upstream `dataGroupsPresent`: names via the [DataGroupParser] tables.
  final List<String> dataGroupsPresent = [];

  @override
  DataGroupId get datagroupType => DataGroupId.COM;

  /// Swift `Int(String(cString: bytes + [0]))`: bytes up to the first NUL
  /// decoded as (lossy) UTF-8, then integer-parsed; `null` where Swift's
  /// `Int()` gives nil.
  static int? _cStringInt(List<int> bytes) {
    final nul = bytes.indexOf(0);
    final terminated = nul == -1 ? bytes : bytes.sublist(0, nul);
    return int.tryParse(utf8.decode(terminated, allowMalformed: true));
  }

  @override
  void parse(List<int> data) {
    var tag = getNextTag();
    verifyTag(tag, equals: 0x5F01);

    // Version is 4 bytes (ascii) - AABB
    // AA is major number, BB is minor number
    // e.g.  48 49 48 55 -> 01 07 -> 1.7  (upstream comment)
    var versionBytes = getNextValue();
    if (versionBytes.length == 4) {
      final aa = _cStringInt(versionBytes.sublist(0, 2));
      final bb = _cStringInt(versionBytes.sublist(2));
      if (aa != null && bb != null) {
        version = '$aa.$bb';
      }
    }
    tag = getNextTag();
    verifyTag(tag, equals: 0x5F36);

    versionBytes = getNextValue();
    if (versionBytes.length == 6) {
      final aa = _cStringInt(versionBytes.sublist(0, 2));
      final bb = _cStringInt(versionBytes.sublist(2, 4));
      final cc = _cStringInt(versionBytes.sublist(4));
      if (aa != null && bb != null && cc != null) {
        unicodeVersion = '$aa.$bb.$cc';
      }
    }

    tag = getNextTag();
    verifyTag(tag, equals: 0x5C);

    final vals = getNextValue();
    for (final v in vals) {
      final index = DataGroupParser.tags.indexOf(v);
      if (index != -1) {
        dataGroupsPresent.add(DataGroupParser.dataGroupNames[index]);
      }
    }
    passportReaderLog.fine(
      'DG Found - [${dataGroupsPresent.map((n) => '"$n"').join(', ')}]',
    );
  }
}
