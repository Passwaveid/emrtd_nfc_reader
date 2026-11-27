// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/ResponseAPDU.swift @ 3bf5456 (2.3.2)

/// Response APDU. Ported verbatim: mutable `data`/`sw1`/`sw2`, matching
/// upstream's `var` struct fields (`sendGeneralAuthenticate` reassigns
/// `data` after unwrapping).
library;

import 'dart:typed_data';

import '../errors.dart';

class ResponseAPDU {
  ResponseAPDU(this.data, this.sw1, this.sw2);

  /// Splits a raw transceiver response (data‖SW1‖SW2, the
  /// `NfcTransceiver.transceive` contract) into fields.
  ///
  /// Dart-only guard: CoreNFC handed upstream a pre-split tuple, so a
  /// response too short to carry a status word could not occur there; on
  /// this side it can (empty APDU responses exist in the field) and
  /// throws [InvalidDataPassed].
  factory ResponseAPDU.fromBytes(List<int> raw) {
    if (raw.length < 2) {
      throw InvalidDataPassed(
        'response APDU too short for SW1/SW2 (${raw.length} byte(s))',
      );
    }
    return ResponseAPDU(
      Uint8List.fromList(raw.sublist(0, raw.length - 2)),
      raw[raw.length - 2],
      raw[raw.length - 1],
    );
  }

  Uint8List data;
  int sw1;
  int sw2;
}
