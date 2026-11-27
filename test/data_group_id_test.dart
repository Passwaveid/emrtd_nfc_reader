/// Unit tests for the DataGroupId mappings (below conformance granularity;
/// plain Dart tests, upstream `DataGroupId.swift` is the reference).
library;

import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const expectedIds = {
    DataGroupId.COM: 0x60,
    DataGroupId.DG1: 0x61,
    DataGroupId.DG2: 0x75,
    DataGroupId.DG3: 0x63,
    DataGroupId.DG4: 0x76,
    DataGroupId.DG5: 0x65,
    DataGroupId.DG6: 0x66,
    DataGroupId.DG7: 0x67,
    DataGroupId.DG8: 0x68,
    DataGroupId.DG9: 0x69,
    DataGroupId.DG10: 0x6A,
    DataGroupId.DG11: 0x6B,
    DataGroupId.DG12: 0x6C,
    DataGroupId.DG13: 0x6D,
    DataGroupId.DG14: 0x6E,
    DataGroupId.DG15: 0x6F,
    DataGroupId.DG16: 0x70,
    DataGroupId.SOD: 0x77,
    DataGroupId.Unknown: 0x00,
  };

  const expectedFileIdTags = {
    DataGroupId.COM: [0x01, 0x1E],
    DataGroupId.DG1: [0x01, 0x01],
    DataGroupId.DG2: [0x01, 0x02],
    DataGroupId.DG3: [0x01, 0x03],
    DataGroupId.DG4: [0x01, 0x04],
    DataGroupId.DG5: [0x01, 0x05],
    DataGroupId.DG6: [0x01, 0x06],
    DataGroupId.DG7: [0x01, 0x07],
    DataGroupId.DG8: [0x01, 0x08],
    DataGroupId.DG9: [0x01, 0x09],
    DataGroupId.DG10: [0x01, 0x0A],
    DataGroupId.DG11: [0x01, 0x0B],
    DataGroupId.DG12: [0x01, 0x0C],
    DataGroupId.DG13: [0x01, 0x0D],
    DataGroupId.DG14: [0x01, 0x0E],
    DataGroupId.DG15: [0x01, 0x0F],
    DataGroupId.DG16: [0x01, 0x10],
    DataGroupId.SOD: [0x01, 0x1D],
  };

  test('covers every enum value exactly once', () {
    expect(expectedIds.keys, containsAll(DataGroupId.values));
    expect(DataGroupId.values, hasLength(expectedIds.length));
  });

  test('id bytes match upstream raw values', () {
    expectedIds.forEach((dg, id) => expect(dg.id, id, reason: '$dg'));
  });

  test('getName matches upstream strings', () {
    for (final dg in DataGroupId.values) {
      // Dart enum identifiers are the upstream names verbatim.
      expect(dg.getName(), dg.name);
    }
    expect(DataGroupId.COM.getName(), 'COM');
    expect(DataGroupId.Unknown.getName(), 'Unknown');
  });

  test('getIDFromName round-trips every name', () {
    for (final dg in DataGroupId.values) {
      expect(DataGroupId.getIDFromName(dg.getName()), dg);
    }
  });

  test('getIDFromName supports the DataGroupParser aliases', () {
    expect(DataGroupId.getIDFromName('Common'), DataGroupId.COM);
    expect(DataGroupId.getIDFromName('SecurityData'), DataGroupId.SOD);
  });

  test('getIDFromName defaults to Unknown', () {
    expect(DataGroupId.getIDFromName('DG17'), DataGroupId.Unknown);
    expect(DataGroupId.getIDFromName(''), DataGroupId.Unknown);
  });

  test('getFileIDTag matches upstream, null for Unknown', () {
    expectedFileIdTags.forEach(
      (dg, tag) => expect(dg.getFileIDTag(), tag, reason: '$dg'),
    );
    expect(DataGroupId.Unknown.getFileIDTag(), isNull);
  });
}
