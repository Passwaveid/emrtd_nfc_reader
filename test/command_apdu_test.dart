/// CommandAPDU encoder/parser unit tests and the ResponseAPDU.fromBytes
/// guard. The conformance suite (`apdu.json`) carries the cross-runner
/// cases; these cover Dart-side constructor validation and edge shapes not
/// worth a vector.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/response_apdu.dart';
import 'package:flutter_test/flutter_test.dart';

CommandAPDU _cmd({
  int cla = 0x00,
  int ins = 0xB0,
  int p1 = 0x00,
  int p2 = 0x00,
  List<int> data = const [],
  int le = -1,
}) => CommandAPDU(
  instructionClass: cla,
  instructionCode: ins,
  p1Parameter: p1,
  p2Parameter: p2,
  data: data,
  expectedResponseLength: le,
);

void main() {
  group('CommandAPDU constructor validation', () {
    test('rejects out-of-range header bytes', () {
      expect(() => _cmd(cla: 0x100), throwsA(isA<InvalidDataPassed>()));
      expect(() => _cmd(ins: -1), throwsA(isA<InvalidDataPassed>()));
    });

    test('rejects expectedResponseLength 0 and out-of-range values', () {
      expect(() => _cmd(le: 0), throwsA(isA<InvalidDataPassed>()));
      expect(() => _cmd(le: -2), throwsA(isA<InvalidDataPassed>()));
      expect(() => _cmd(le: 0x10001), throwsA(isA<InvalidDataPassed>()));
    });

    test('rejects data above the extended Lc ceiling', () {
      expect(
        () => _cmd(data: Uint8List(0x10000)),
        throwsA(isA<InvalidDataPassed>()),
      );
    });

    test('data is copied defensively', () {
      final source = [1, 2, 3];
      final cmd = _cmd(data: source);
      source[0] = 0xFF;
      expect(cmd.data, [1, 2, 3]);
    });
  });

  group('requiresExtendedLength (extended-length capability gate input)', () {
    test('short forms', () {
      expect(_cmd(le: 256).requiresExtendedLength, isFalse);
      expect(
        _cmd(data: Uint8List(255), le: 256).requiresExtendedLength,
        isFalse,
      );
    });

    test('extended forms', () {
      expect(_cmd(le: 257).requiresExtendedLength, isTrue);
      expect(_cmd(data: Uint8List(256)).requiresExtendedLength, isTrue);
    });
  });

  group('parse/encode round-trips', () {
    test('upstream header-read raw re-encodes minimal', () {
      final cmd = CommandAPDU.parse(const [
        0x00,
        0xB0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x04,
      ]);
      expect(cmd.expectedResponseLength, 4);
      expect(cmd.encode(), [0x00, 0xB0, 0x00, 0x00, 0x04]);
    });

    test('canonical wires survive parse -> encode', () {
      final wires = [
        [0x00, 0x84, 0x00, 0x00],
        [0x00, 0x84, 0x00, 0x00, 0x08],
        [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E],
        [0x00, 0x82, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x00],
        [0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x2C],
      ];
      for (final wire in wires) {
        expect(
          CommandAPDU.parse(wire).encode(),
          wire,
          reason: 'wire ${wire.map((b) => b.toRadixString(16)).join()}',
        );
      }
    });

    test('extended case-4 parses and re-encodes', () {
      final data = List<int>.generate(300, (i) => i & 0xFF);
      final wire = _cmd(ins: 0x86, data: data, le: 512).encode();
      final parsed = CommandAPDU.parse(wire);
      expect(parsed.data, data);
      expect(parsed.expectedResponseLength, 512);
      expect(parsed.encode(), wire);
    });
  });

  group('parse malformed input', () {
    for (final raw in [
      <int>[],
      [0x00, 0xA4, 0x02],
      [0x00, 0xA4, 0x02, 0x0C, 0x05, 0x01, 0x1E],
      [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00],
      [0x00, 0xB0, 0x00, 0x00, 0x100], // not a byte
    ]) {
      test('throws UnexpectedError on $raw', () {
        expect(() => CommandAPDU.parse(raw), throwsA(isA<UnexpectedError>()));
      });
    }
  });

  group('ResponseAPDU.fromBytes', () {
    test('splits data and SW', () {
      final r = ResponseAPDU.fromBytes(const [0xAA, 0xBB, 0x90, 0x00]);
      expect(r.data, [0xAA, 0xBB]);
      expect(r.sw1, 0x90);
      expect(r.sw2, 0x00);
    });

    test('SW-only response has empty data', () {
      final r = ResponseAPDU.fromBytes(const [0x6A, 0x82]);
      expect(r.data, isEmpty);
      expect(r.sw1, 0x6A);
      expect(r.sw2, 0x82);
    });

    test('shorter than a status word throws (a shape seen in the field)', () {
      expect(
        () => ResponseAPDU.fromBytes(const [0x90]),
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(
        () => ResponseAPDU.fromBytes(const []),
        throwsA(isA<InvalidDataPassed>()),
      );
    });
  });
}
