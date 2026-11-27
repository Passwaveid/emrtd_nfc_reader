// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroupParser.swift @ 3bf5456 (2.3.2)
//   (top level upstream, not under DataGroups/)

/// `DataGroupParser`: file-tag dispatch to the DG classes.
///
/// The three parallel arrays are kept verbatim in upstream's shape for
/// diffability; their alignment is pinned by a unit test (they are aligned
/// 18/18 upstream: a maintenance hazard rather than a defect). Every DG
/// upstream has a parser for dispatches to it. The [NotImplementedDG] rows
/// are the DGs **upstream also has no parser for** (DG3/4/5/6/8/9/10/13/16:
/// parity holds); unknown tags throw [UnknownTag] exactly as upstream.
library;

import '../errors.dart';
import 'com.dart';
import 'data_group.dart';
import 'data_group1.dart';
import 'data_group11.dart';
import 'data_group12.dart';
import 'data_group14.dart';
import 'data_group15.dart';
import 'data_group2.dart';
import 'data_group7.dart';
import 'not_implemented_dg.dart';
import 'sod.dart';

/// Upstream `DataGroupParser`.
class DataGroupParser {
  /// Upstream `dataGroupNames` (verbatim, incl. `"Common"`/`"SecurityData"`).
  static const List<String> dataGroupNames = [
    'Common', 'DG1', 'DG2', 'DG3', 'DG4', 'DG5', 'DG6', 'DG7', 'DG8', 'DG9', //
    'DG10', 'DG11', 'DG12', 'DG13', 'DG14', 'DG15', 'DG16', 'SecurityData',
  ];

  /// Upstream `tags` (verbatim).
  static const List<int> tags = [
    0x60, 0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68, 0x69, //
    0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x77,
  ];

  /// Upstream `classes`: Swift metatype dispatch becomes constructor
  /// tear-offs; every row matches upstream's. DG7/DG11/DG12 dispatch to
  /// [DataGroup7]/[DataGroup11]/[DataGroup12], DG14 to [DataGroup14], DG15 to
  /// [DataGroup15]. The rows on [NotImplementedDG] are exactly the ones
  /// upstream leaves there too.
  static final List<DataGroup Function(List<int>)> classes = [
    COM.new, DataGroup1.new, DataGroup2.new,
    NotImplementedDG.new, NotImplementedDG.new, NotImplementedDG.new,
    NotImplementedDG.new, DataGroup7.new,
    NotImplementedDG.new, // DG7 -> DataGroup7
    NotImplementedDG.new, NotImplementedDG.new,
    DataGroup11.new, // DG11 -> DataGroup11
    DataGroup12.new, NotImplementedDG.new,
    DataGroup14.new, // DG12 -> DataGroup12; DG14 -> DataGroup14
    DataGroup15.new, NotImplementedDG.new, // DG15 -> DataGroup15
    SOD.new,
  ];

  /// Upstream `parseDG(data:)`.
  ///
  /// Upstream slices `data[0..<4]` before dispatch (crashing on any blob
  /// under 4 bytes) only to read byte 0. The port dispatches on byte 0
  /// directly: empty input throws [UnknownTag]; 1-3-byte blobs dispatch and
  /// fail inside the constructor with the base walk's typed errors.
  DataGroup parseDG({required List<int> data}) {
    if (data.isEmpty) {
      throw const UnknownTag(); // upstream: slice crash
    }
    final dg = tagToDG(data[0]);
    return dg(data);
  }

  /// Upstream `tagToDG(_:)`: unknown tags throw [UnknownTag].
  DataGroup Function(List<int>) tagToDG(int tag) {
    final index = tags.indexOf(tag);
    if (index == -1) {
      throw const UnknownTag();
    }
    return classes[index];
  }
}
