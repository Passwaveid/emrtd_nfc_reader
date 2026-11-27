// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroupId.swift @ 3bf5456 (2.3.2)

/// LDS data-group identifiers: pure data (id byte <-> name <-> file-ID tag),
/// which [InvalidResponse] also carries.
library;

import 'dart:typed_data';

// Upstream case names kept verbatim, so ported call sites diff line by line
// against the Swift.
// ignore_for_file: constant_identifier_names

enum DataGroupId {
  COM(0x60),
  DG1(0x61),
  DG2(0x75),
  DG3(0x63),
  DG4(0x76),
  DG5(0x65),
  DG6(0x66),
  DG7(0x67),
  DG8(0x68),
  DG9(0x69),
  DG10(0x6A),
  DG11(0x6B),
  DG12(0x6C),
  DG13(0x6D),
  DG14(0x6E),
  DG15(0x6F),
  DG16(0x70),
  SOD(0x77),

  /// Upstream `Unknown = 0x00`: the [getIDFromName] default.
  Unknown(0x00);

  const DataGroupId(this.id);

  /// Upstream's raw enum value (the DG's LDS tag byte; 0x00 for [Unknown]).
  final int id;

  /// Upstream `getName()`: the enum identifiers match the upstream strings
  /// exactly, so this is the Dart enum name.
  String getName() => name;

  /// Upstream `getIDFromName(name:)`, including the `"Common"` /
  /// `"SecurityData"` aliases used by DataGroupParser; unrecognized names
  /// return [Unknown].
  static DataGroupId getIDFromName(String name) {
    switch (name) {
      // Name in DataGroupParser is "Common", not "COM". Supporting both so
      // ID is added correctly (upstream comment).
      case 'COM' || 'Common':
        return COM;
      case 'DG1':
        return DG1;
      case 'DG2':
        return DG2;
      case 'DG3':
        return DG3;
      case 'DG4':
        return DG4;
      case 'DG5':
        return DG5;
      case 'DG6':
        return DG6;
      case 'DG7':
        return DG7;
      case 'DG8':
        return DG8;
      case 'DG9':
        return DG9;
      case 'DG10':
        return DG10;
      case 'DG11':
        return DG11;
      case 'DG12':
        return DG12;
      case 'DG13':
        return DG13;
      case 'DG14':
        return DG14;
      case 'DG15':
        return DG15;
      case 'DG16':
        return DG16;
      // Name in DataGroupParser is "SecurityData", not "SOD". Supporting
      // both so ID is added correctly (upstream comment).
      case 'SOD' || 'SecurityData':
        return SOD;
      default:
        return Unknown;
    }
  }

  /// Upstream `getFileIDTag()`: the two-byte elementary-file ID; `null`
  /// for [Unknown], matching upstream's optional return.
  Uint8List? getFileIDTag() {
    return switch (this) {
      COM => Uint8List.fromList([0x01, 0x1E]),
      DG1 => Uint8List.fromList([0x01, 0x01]),
      DG2 => Uint8List.fromList([0x01, 0x02]),
      DG3 => Uint8List.fromList([0x01, 0x03]),
      DG4 => Uint8List.fromList([0x01, 0x04]),
      DG5 => Uint8List.fromList([0x01, 0x05]),
      DG6 => Uint8List.fromList([0x01, 0x06]),
      DG7 => Uint8List.fromList([0x01, 0x07]),
      DG8 => Uint8List.fromList([0x01, 0x08]),
      DG9 => Uint8List.fromList([0x01, 0x09]),
      DG10 => Uint8List.fromList([0x01, 0x0A]),
      DG11 => Uint8List.fromList([0x01, 0x0B]),
      DG12 => Uint8List.fromList([0x01, 0x0C]),
      DG13 => Uint8List.fromList([0x01, 0x0D]),
      DG14 => Uint8List.fromList([0x01, 0x0E]),
      DG15 => Uint8List.fromList([0x01, 0x0F]),
      DG16 => Uint8List.fromList([0x01, 0x10]),
      SOD => Uint8List.fromList([0x01, 0x1D]),
      Unknown => null,
    };
  }
}
