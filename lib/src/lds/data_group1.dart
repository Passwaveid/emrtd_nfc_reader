// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup1.swift @ 3bf5456 (2.3.2)

/// DG1 (MRZ) parsing.
///
/// As upstream, the layout is chosen by body length: `0x5A` -> TD1, `0x48`
/// -> TD2, anything else the TD3-shaped [DataGroup1.parseOther], including
/// lengths 89/91+, which parse at fixed offsets regardless. Elements whose
/// bytes are not valid UTF-8 are absent from [DataGroup1.elements], mirroring
/// Swift's nil-assignment, and TD1's `"53"` concatenates optional-data I+II
/// with empty-string fallbacks. Unlike upstream, TD3-shaped bodies shorter
/// than 88 throw [InvalidDataPassed] where upstream index-crashes.
library;

import 'dart:convert';

import '../errors.dart';
import 'data_group.dart';
import 'data_group_id.dart';

// Upstream case names kept verbatim, so ported call sites diff line by line
// against the Swift.
// ignore_for_file: constant_identifier_names

/// Upstream `DocTypeEnum`.
enum DocTypeEnum {
  TD1,
  TD2,
  OTHER;

  /// Upstream `desc`: the raw value.
  String get desc => name;
}

/// Upstream `DataGroup1`.
class DataGroup1 extends DataGroup {
  DataGroup1(super.data);

  /// Upstream `elements`: `"5F1F"` holds the full MRZ, per-field keys per
  /// layout. A field whose bytes are not valid UTF-8 is absent.
  final Map<String, String> elements = {};

  @override
  DataGroupId get datagroupType => DataGroupId.DG1;

  /// Swift `String(bytes:encoding:.utf8)` dictionary assignment: invalid
  /// UTF-8 yields nil, which never creates the key.
  void _setElement(String key, List<int> bytes) {
    try {
      elements[key] = utf8.decode(bytes);
    } on FormatException {
      // key stays absent
    }
  }

  /// Swift `String(bytes:encoding:.utf8) ?? ""` (the TD1 `"53"` halves).
  static String _decodeOrEmpty(List<int> bytes) {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      return '';
    }
  }

  @override
  void parse(List<int> data) {
    final tag = getNextTag();
    verifyTag(tag, equals: 0x5F1F);
    final body = getNextValue();
    final docType = _getMRZType(body.length);

    switch (docType) {
      case DocTypeEnum.TD1:
        parseTd1(body);
      case DocTypeEnum.TD2:
        parseTd2(body);
      case DocTypeEnum.OTHER:
        parseOther(body);
    }

    // Store MRZ data (upstream comment).
    _setElement('5F1F', body);
  }

  /// Upstream `parseTd1(_:)`: body is exactly 90 bytes (chosen by length).
  void parseTd1(List<int> data) {
    _setElement('5F03', data.sublist(0, 2));
    _setElement('5F28', data.sublist(2, 5));
    _setElement('5A', data.sublist(5, 14));
    _setElement('5F04', data.sublist(14, 15));
    elements['53'] =
        _decodeOrEmpty(data.sublist(15, 30)) +
        _decodeOrEmpty(data.sublist(48, 59));
    _setElement('5F57', data.sublist(30, 36));
    _setElement('5F05', data.sublist(36, 37));
    _setElement('5F35', data.sublist(37, 38));
    _setElement('59', data.sublist(38, 44));
    _setElement('5F06', data.sublist(44, 45));
    _setElement('5F2C', data.sublist(45, 48));
    _setElement('5F07', data.sublist(59, 60));
    _setElement('5B', data.sublist(60));
  }

  /// Upstream `parseTd2(_:)`: body is exactly 72 bytes (chosen by length).
  void parseTd2(List<int> data) {
    _setElement('5F03', data.sublist(0, 2));
    _setElement('5F28', data.sublist(2, 5));
    _setElement('5B', data.sublist(5, 36));
    _setElement('5A', data.sublist(36, 45));
    _setElement('5F04', data.sublist(45, 46));
    _setElement('5F2C', data.sublist(46, 49));
    _setElement('5F57', data.sublist(49, 55));
    _setElement('5F05', data.sublist(55, 56));
    _setElement('5F35', data.sublist(56, 57));
    _setElement('59', data.sublist(57, 63));
    _setElement('5F06', data.sublist(63, 64));
    _setElement('53', data.sublist(64, 71));
    _setElement('5F07', data.sublist(71, 72));
  }

  /// Upstream `parseOther(_:)`: the TD3-shaped fixed-offset layout,
  /// applied to any body length other than 90/72.
  ///
  /// Bodies shorter than 88 bytes throw [InvalidDataPassed] (upstream: index
  /// crash at up to `data[87]`).
  void parseOther(List<int> data) {
    if (data.length < 88) {
      throw const InvalidDataPassed('DG1 MRZ data too short');
    }
    _setElement('5F03', data.sublist(0, 2));
    _setElement('5F28', data.sublist(2, 5));
    _setElement('5B', data.sublist(5, 44));
    _setElement('5A', data.sublist(44, 53));
    _setElement('5F04', [data[53]]);
    _setElement('5F2C', data.sublist(54, 57));
    _setElement('5F57', data.sublist(57, 63));
    _setElement('5F05', [data[63]]);
    _setElement('5F35', [data[64]]);
    _setElement('59', data.sublist(65, 71));
    _setElement('5F06', [data[71]]);
    _setElement('53', data.sublist(72, 86));
    _setElement('5F02', [data[86]]);
    _setElement('5F07', [data[87]]);
  }

  DocTypeEnum _getMRZType(int length) {
    if (length == 0x5A) {
      return DocTypeEnum.TD1;
    }
    if (length == 0x48) {
      return DocTypeEnum.TD2;
    }
    return DocTypeEnum.OTHER;
  }
}
