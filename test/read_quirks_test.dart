/// ReadQuirks seam tests + the version-const pin.
///
/// The core invariant is the zero-entry policy: `ReadQuirks.none` must be
/// behaviorally identical to a quirk-less `TagReader` (the wider default
/// behavior is pinned by the conformance transcripts; here we pin the seam's
/// dispatch itself).
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/read_quirks.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/version.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/scripted_transceiver.dart';

CommandAPDU _cmd({
  int cla = 0x00,
  required int ins,
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

Uint8List _sw(int sw1, int sw2) => Uint8List.fromList([sw1, sw2]);

/// The EF.CardAccess select + header-read + body-read tail shared by every
/// variant: SELECT 011C, 4-byte header read, then the 2 declared body bytes
/// re-read from offset 2. Serves a minimal 4-byte file `31 02 30 00`.
List<ScriptedStep> _cardAccessReadTail() => [
  ScriptedStep(
    cmd: _cmd(ins: 0xA4, p1: 0x02, p2: 0x0C, data: const [0x01, 0x1C]),
    response: _sw(0x90, 0x00),
  ),
  ScriptedStep(
    cmd: CommandAPDU.parse(const [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04]),
    response: Uint8List.fromList([0x31, 0x02, 0x30, 0x00, 0x90, 0x00]),
  ),
  ScriptedStep(
    cmd: _cmd(ins: 0xB0, p1: 0x00, p2: 0x02, le: 2),
    response: Uint8List.fromList([0x30, 0x00, 0x90, 0x00]),
  ),
];

void main() {
  group('version const', () {
    test('emrtdCoreVersion matches pubspec.yaml', () {
      final pubspec = File('pubspec.yaml').readAsStringSync();
      final version = RegExp(
        r'^version:\s*(\S+)',
        multiLine: true,
      ).firstMatch(pubspec)!.group(1);
      expect(emrtdCoreVersion, version);
    });

    test('sdk id follows the emrtd_core-<version> format', () {
      expect(emrtdCoreSdkId, 'emrtd_core-$emrtdCoreVersion');
    });
  });

  group('select variants', () {
    test(
      'default (iso3F00) sends upstream\'s MF select with data 3F00',
      () async {
        final transceiver = ScriptedTransceiver([
          ScriptedStep(
            cmd: _cmd(ins: 0xA4, p2: 0x0C, data: const [0x3F, 0x00]),
            response: _sw(0x90, 0x00),
          ),
          ..._cardAccessReadTail(),
        ]);
        final data = await TagReader(transceiver).readCardAccess();
        expect(data, [0x31, 0x02, 0x30, 0x00]);
        expect(transceiver.exhausted, isTrue);
      },
    );

    test('fid3F003004 sends the Danish MF select form', () async {
      final transceiver = ScriptedTransceiver([
        ScriptedStep(
          cmd: _cmd(ins: 0xA4, p2: 0x0C, data: const [0x3F, 0x00, 0x30, 0x04]),
          response: _sw(0x90, 0x00),
        ),
        ..._cardAccessReadTail(),
      ]);
      final reader = TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.fid3F003004,
        ),
      );
      await reader.readCardAccess();
      expect(transceiver.exhausted, isTrue);
    });

    test('fid3F003004 keeps the MF-select refusal fallback', () async {
      final transceiver = ScriptedTransceiver([
        ScriptedStep(
          cmd: _cmd(ins: 0xA4, p2: 0x0C, data: const [0x3F, 0x00, 0x30, 0x04]),
          response: _sw(0x67, 0x00),
        ),
        ..._cardAccessReadTail(),
      ]);
      final reader = TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.fid3F003004,
        ),
      );
      await reader.readCardAccess();
      expect(transceiver.exhausted, isTrue);
    });

    test('directFid skips the MF select entirely', () async {
      final transceiver = ScriptedTransceiver(_cardAccessReadTail());
      final reader = TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.directFid,
        ),
      );
      await reader.readCardAccess();
      expect(transceiver.exhausted, isTrue);
    });
  });

  group('maxReadLength', () {
    test('overrides maxDataLengthToRead at construction', () {
      final reader = TagReader(
        ScriptedTransceiver([]),
        quirks: const ReadQuirks(maxReadLength: 0xE7),
      );
      expect(reader.maxDataLengthToRead, 0xE7);
    });

    test('override is stored as given; the transport fit is read-time', () {
      final reader = TagReader(
        ScriptedTransceiver([], maxTransceiveLength: 100),
        quirks: const ReadQuirks(maxReadLength: 0xE7),
      );
      expect(reader.maxDataLengthToRead, 0xE7);
    });

    test('override wins over the readChunk knob', () {
      final reader = TagReader(
        ScriptedTransceiver([]),
        readChunk: 0xDF,
        quirks: const ReadQuirks(maxReadLength: 0xE7),
      );
      expect(reader.maxDataLengthToRead, 0xE7);
    });

    test('null override keeps the upstream default', () {
      expect(TagReader(ScriptedTransceiver([])).maxDataLengthToRead, 0xA0);
    });
  });

  test('ReadQuirks.none is the zero-entry default', () {
    const q = ReadQuirks.none;
    expect(q.selectVariant, MasterFileSelectVariant.iso3F00);
    expect(q.maxReadLength, isNull);
    expect(q.timeoutMultiplier, 1.0);
  });
}
