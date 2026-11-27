// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: re-implements CoreNFC's implicit `NFCISO7816APDU`, structured
//   fields + ISO 7816-4 wire encoder + raw-bytes parser.

/// Command APDU. CoreNFC serialized APDUs internally and unobservably; this
/// port owns the wire encoding explicitly, targeting ISO 7816-4 **canonical
/// minimal form**: short Lc/Le whenever the values fit (Lc ≤ 255,
/// Le ≤ 256), extended only when required, never mixed. One consequence,
/// pinned by a conformance vector: upstream's raw extended-Le header read
/// re-emits as short form here.
library;

import 'dart:typed_data';

import '../errors.dart';

class CommandAPDU {
  /// [expectedResponseLength] mirrors CoreNFC's documented semantics:
  /// `-1` -> no Le field; 1..256 -> short Le (256 encodes `00`);
  /// 257..65536 -> extended Le (65536 encodes `0000`). `0` is invalid.
  CommandAPDU({
    required this.instructionClass,
    required this.instructionCode,
    required this.p1Parameter,
    required this.p2Parameter,
    required List<int> data,
    required this.expectedResponseLength,
  }) : data = Uint8List.fromList(data) {
    for (final (name, value) in [
      ('instructionClass', instructionClass),
      ('instructionCode', instructionCode),
      ('p1Parameter', p1Parameter),
      ('p2Parameter', p2Parameter),
    ]) {
      if (value < 0 || value > 0xFF) {
        throw InvalidDataPassed('$name must be one byte, got $value');
      }
    }
    if (this.data.length > 0xFFFF) {
      throw InvalidDataPassed(
        'command data exceeds extended-length Lc ceiling '
        '(${this.data.length} > 65535)',
      );
    }
    if (expectedResponseLength != -1 &&
        (expectedResponseLength < 1 || expectedResponseLength > 0x10000)) {
      throw InvalidDataPassed(
        'expectedResponseLength must be -1 (absent) or 1..65536, got '
        '$expectedResponseLength',
      );
    }
  }

  /// `NFCISO7816APDU(data:)` equivalent: parses raw wire bytes into fields.
  /// Malformed input throws [UnexpectedError], the code upstream call
  /// sites produced from the initializer's nil return.
  factory CommandAPDU.parse(List<int> raw) {
    EmrtdException malformed() => const UnexpectedError();

    if (raw.length < 4 || raw.any((b) => b < 0 || b > 0xFF)) {
      throw malformed();
    }
    final body = raw.sublist(4);
    List<int> data = const [];
    var le = -1;
    if (body.isNotEmpty) {
      if (body.length == 1) {
        // Case 2 short.
        le = body[0] == 0 ? 256 : body[0];
      } else if (body[0] != 0) {
        // Short form with Lc.
        final lc = body[0];
        if (body.length == 1 + lc) {
          data = body.sublist(1); // case 3 short
        } else if (body.length == 2 + lc) {
          data = body.sublist(1, 1 + lc); // case 4 short
          final leByte = body[body.length - 1];
          le = leByte == 0 ? 256 : leByte;
        } else {
          throw malformed();
        }
      } else {
        // Extended form (body[0] == 0 with more bytes following).
        if (body.length == 3) {
          // Case 2 extended.
          final leWord = (body[1] << 8) | body[2];
          le = leWord == 0 ? 0x10000 : leWord;
        } else if (body.length >= 4) {
          final lc = (body[1] << 8) | body[2];
          if (lc == 0) {
            throw malformed(); // extended Lc of zero is not encodable
          }
          if (body.length == 3 + lc) {
            data = body.sublist(3); // case 3 extended
          } else if (body.length == 5 + lc) {
            data = body.sublist(3, 3 + lc); // case 4 extended
            final leWord = (body[3 + lc] << 8) | body[4 + lc];
            le = leWord == 0 ? 0x10000 : leWord;
          } else {
            throw malformed();
          }
        } else {
          throw malformed();
        }
      }
    }
    return CommandAPDU(
      instructionClass: raw[0],
      instructionCode: raw[1],
      p1Parameter: raw[2],
      p2Parameter: raw[3],
      data: data,
      expectedResponseLength: le,
    );
  }

  final int instructionClass;
  final int instructionCode;
  final int p1Parameter;
  final int p2Parameter;
  final Uint8List data;
  final int expectedResponseLength;

  /// True when canonical minimal form needs extended length: Lc > 255 or
  /// Le > 256. The transceiver capability gate keys on this.
  bool get requiresExtendedLength =>
      data.length > 0xFF || expectedResponseLength > 0x100;

  /// Canonical minimal-form wire bytes. Short Lc/Le whenever both
  /// fit; otherwise the whole APDU switches to extended form (ISO 7816-4
  /// forbids mixing short and extended fields in one command).
  Uint8List encode() {
    final out = BytesBuilder()
      ..add([instructionClass, instructionCode, p1Parameter, p2Parameter]);
    final le = expectedResponseLength;
    if (!requiresExtendedLength) {
      if (data.isNotEmpty) {
        out
          ..addByte(data.length)
          ..add(data);
      }
      if (le != -1) {
        out.addByte(le == 0x100 ? 0x00 : le);
      }
    } else {
      if (data.isNotEmpty) {
        out
          ..addByte(0x00)
          ..addByte(data.length >> 8)
          ..addByte(data.length & 0xFF)
          ..add(data);
      }
      if (le != -1) {
        if (data.isEmpty) {
          out.addByte(0x00); // extended-length indicator carried by Le
        }
        final leWord = le == 0x10000 ? 0 : le;
        out
          ..addByte(leWord >> 8)
          ..addByte(leWord & 0xFF);
      }
    }
    return out.toBytes();
  }

  /// Same command with a different [expectedResponseLength]: the `6C XX`
  /// exact-length retry and the `67 00` resend build these.
  CommandAPDU withExpectedResponseLength(int expectedResponseLength) =>
      CommandAPDU(
        instructionClass: instructionClass,
        instructionCode: instructionCode,
        p1Parameter: p1Parameter,
        p2Parameter: p2Parameter,
        data: data,
        expectedResponseLength: expectedResponseLength,
      );

  @override
  String toString() {
    String h(int v) => v.toRadixString(16).padLeft(2, '0');
    final dataHex = data.map(h).join();
    return 'CommandAPDU(cla=${h(instructionClass)} ins=${h(instructionCode)} '
        'p1=${h(p1Parameter)} p2=${h(p2Parameter)} lc=${data.length} '
        'data=$dataHex le=$expectedResponseLength)';
  }
}
