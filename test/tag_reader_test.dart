/// TagReader unit tests for behavior the transcripts/vectors don't already
/// pin: the read-time chunk fit (`fitReadLength`) + extended-length
/// refusal, the `readChunk` knob and `lastRead` accounting, the EF.ATR/INFO
/// read, the offset guard, header hardening, the 6C 00 -> Le 256 retry
/// mapping, progress reporting, and error propagation from the transceiver
/// seam.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/mac.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/read_quirks.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/scripted_transceiver.dart';

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

ScriptedStep _select(List<int> tag, {String sw = '9000'}) => ScriptedStep(
  cmd: _cmd(ins: 0xA4, p1: 0x02, p2: 0x0C, data: tag),
  response: Uint8List.fromList([
    int.parse(sw.substring(0, 2), radix: 16),
    int.parse(sw.substring(2), radix: 16),
  ]),
);

ScriptedStep _header(List<int> resp4) => ScriptedStep(
  cmd: _cmd(le: 4),
  response: Uint8List.fromList([...resp4, 0x90, 0x00]),
);

/// Serves a header declaring a 0x8FFF-byte body and answers every chunk in
/// full, so the read loop runs until the 32767 offset ceiling.
class _EndlessReadTransceiver implements NfcTransceiver {
  @override
  int get maxTransceiveLength => 261;

  @override
  bool get isExtendedLengthApduSupported => false;

  @override
  Uint8List? get historicalBytes => null;

  @override
  TagCapabilities? get tagCapabilities => null;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    final cmd = CommandAPDU.parse(capdu);
    if (cmd.instructionCode == 0xA4) {
      return Uint8List.fromList([0x90, 0x00]);
    }
    if (cmd.p1Parameter == 0 &&
        cmd.p2Parameter == 0 &&
        cmd.expectedResponseLength == 4) {
      return Uint8List.fromList([0x60, 0x82, 0x8F, 0xFF, 0x90, 0x00]);
    }
    return Uint8List.fromList([
      ...List.filled(cmd.expectedResponseLength, 0xAA),
      0x90,
      0x00,
    ]);
  }
}

class _ThrowingTransceiver implements NfcTransceiver {
  @override
  int get maxTransceiveLength => 261;

  @override
  bool get isExtendedLengthApduSupported => false;

  @override
  Uint8List? get historicalBytes => null;

  @override
  TagCapabilities? get tagCapabilities => null;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async =>
      throw const ConnectionError();
}

/// SELECT + header + one full-body read of a [bodyLength]-byte file (tag
/// `60`, two-byte length form), expecting the body chunk at [le].
List<ScriptedStep> _wholeFileRead(
  List<int> fid, {
  required int bodyLength,
  required int le,
}) {
  final body = List<int>.generate(bodyLength, (i) => i & 0xFF);
  return [
    _select(fid),
    _header([0x60, 0x81, bodyLength, body[0]]),
    ScriptedStep(
      cmd: _cmd(p2: 0x03, le: le),
      response: Uint8List.fromList([...body, 0x90, 0x00]),
    ),
  ];
}

ScriptedStep _mfSelect({String sw = '9000'}) => ScriptedStep(
  cmd: _cmd(ins: 0xA4, p1: 0x00, p2: 0x0C, data: const [0x3F, 0x00]),
  response: Uint8List.fromList([
    int.parse(sw.substring(0, 2), radix: 16),
    int.parse(sw.substring(2), radix: 16),
  ]),
);

SecureMessaging _session(SecureMessagingSupportedAlgorithms algo) =>
    SecureMessaging(
      encryptionAlgorithm: algo,
      ksenc: List.filled(
        algo == SecureMessagingSupportedAlgorithms.des ? 16 : 16,
        0x11,
      ),
      ksmac: List.filled(16, 0x22),
      ssc: List.filled(8, 0),
    );

void main() {
  group('fitReadLength (the read-time, SM-aware chunk fit)', () {
    /// (requested, cap, block) -> N for every row of the chunk-fit table.
    const rows = <(int, int, int?, int)>[
      // no SM: data + SW
      (160, 261, null, 160),
      (256, 261, null, 256),
      (0x200, 261, null, 259),
      (223, 100, null, 98),
      // 3DES (block 8) at the 261-byte constant
      (160, 261, 8, 160),
      (223, 261, 8, 223),
      (224, 261, 8, 224),
      (231, 261, 8, 231),
      (239, 261, 8, 239),
      (240, 261, 8, 239),
      (256, 261, 8, 239),
      // AES (block 16) at 261
      (160, 261, 16, 160),
      (223, 261, 16, 223),
      (224, 261, 16, 224),
      (239, 261, 16, 239),
      (240, 261, 16, 239),
      (256, 261, 16, 239),
      // the 253-byte Broadcom-era figure
      (223, 253, 8, 223),
      (223, 253, 16, 223),
      (256, 253, 8, 231),
      (256, 253, 16, 223),
      (224, 253, 16, 223),
      // extended-length shapes (L = 3 falls out of the formula)
      (1024, 1061, 16, 1024),
      (1024, 1060, 16, 1023),
      (1024, 4096, 8, 1024),
      // total: never below 1
      (223, 10, 16, 1),
      (1, 2, null, 1),
    ];
    for (final (requested, cap, block, expected) in rows) {
      test('requested $requested, cap $cap, block $block -> $expected', () {
        expect(
          fitReadLength(
            requested: requested,
            maxTransceiveLength: cap,
            smBlockSize: block,
          ),
          expected,
        );
      });
    }

    test(
      'padLength of a real SecureMessaging feeds the fit for both ciphers',
      () {
        final des = _session(SecureMessagingSupportedAlgorithms.des);
        final aes = _session(SecureMessagingSupportedAlgorithms.aes);
        expect(des.padLength, 8);
        expect(aes.padLength, 16);
        for (final sm in [des, aes]) {
          expect(
            fitReadLength(
              requested: 223,
              maxTransceiveLength: 253,
              smBlockSize: sm.padLength,
            ),
            223,
          );
        }
        // The frame the fit reasons about is the one protect() would produce:
        // a 223-byte plaintext response is 244 bytes under either cipher.
        expect(
          fitReadLength(
            requested: 256,
            maxTransceiveLength: 244,
            smBlockSize: des.padLength,
          ),
          223,
        );
        expect(
          fitReadLength(
            requested: 256,
            maxTransceiveLength: 244,
            smBlockSize: aes.padLength,
          ),
          223,
        );
      },
    );

    test('nothing is clamped at construction or override', () {
      final reader = TagReader(
        ScriptedTransceiver([], maxTransceiveLength: 100),
      );
      expect(reader.maxDataLengthToRead, 0xA0);
      reader.overrideDataAmountToRead(0x200);
      expect(reader.maxDataLengthToRead, 0x200);
    });

    test('reduce floors at 0xA0 and never raises', () {
      final reader = TagReader(ScriptedTransceiver([]));
      reader.overrideDataAmountToRead(256);
      reader.reduceDataReadingAmount();
      expect(reader.maxDataLengthToRead, 0xA0);
      reader.reduceDataReadingAmount();
      expect(reader.maxDataLengthToRead, 0xA0);
      reader.overrideDataAmountToRead(0x50);
      reader.reduceDataReadingAmount();
      expect(
        reader.maxDataLengthToRead,
        0x50,
        reason: 'reduce only lowers values above 0xA0',
      );
    });

    test(
      'the read loop asks for the fitted chunk, not the requested one',
      () async {
        // 223 requested over a 100-byte transport without SM fits 98.
        final transceiver = ScriptedTransceiver(
          _wholeFileRead(const [0x01, 0x1E], bodyLength: 98, le: 98),
          maxTransceiveLength: 100,
        );
        final reader = TagReader(transceiver, readChunk: 223);
        await reader.selectFileAndRead(const [0x01, 0x1E]);
        expect(transceiver.exhausted, isTrue);
        expect(reader.lastRead?.chunkSize, 98);
      },
    );
  });

  group('readChunk', () {
    test('defaults to upstream 0xA0', () {
      expect(TagReader(ScriptedTransceiver([])).maxDataLengthToRead, 0xA0);
    });

    test('is stored as given', () {
      expect(
        TagReader(ScriptedTransceiver([]), readChunk: 0xDF).maxDataLengthToRead,
        0xDF,
      );
    });

    test('ReadQuirks.maxReadLength wins over it', () {
      final reader = TagReader(
        ScriptedTransceiver([]),
        readChunk: 0xDF,
        quirks: const ReadQuirks(maxReadLength: 0xE7),
      );
      expect(reader.maxDataLengthToRead, 0xE7);
    });
  });

  group('lastRead accounting', () {
    test('null before any read, then chunk size / chunks / bytes', () async {
      final reader = TagReader(
        ScriptedTransceiver(
          _wholeFileRead(const [0x01, 0x1E], bodyLength: 0x40, le: 0x40),
        ),
        readChunk: 0xDF,
      );
      expect(reader.lastRead, isNull);
      final data = await reader.selectFileAndRead(const [0x01, 0x1E]);
      expect(
        reader.lastRead,
        (chunkSize: 0xDF, chunks: 2, bytes: data.length),
        reason: 'the header read counts; the body needed one chunk',
      );
    });

    test('multi-chunk: one command per chunk, bytes = whole file', () async {
      const bodyLength = 200;
      final body = List<int>.generate(bodyLength, (i) => i & 0xFF);
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E]),
          _header([0x60, 0x81, bodyLength, body[0]]),
          ScriptedStep(
            cmd: _cmd(p2: 0x03, le: 0xA0),
            response: Uint8List.fromList([
              ...body.sublist(0, 0xA0),
              0x90,
              0x00,
            ]),
          ),
          ScriptedStep(
            cmd: _cmd(p2: 0x03 + 0xA0, le: bodyLength - 0xA0),
            response: Uint8List.fromList([...body.sublist(0xA0), 0x90, 0x00]),
          ),
        ]),
      );
      final data = await reader.selectFileAndRead(const [0x01, 0x1E]);
      expect(data.length, 3 + bodyLength);
      expect(reader.lastRead, (chunkSize: 0xA0, chunks: 3, bytes: 203));
    });

    test('a throw mid-read leaves the partial count visible', () async {
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E]),
          _header([0x60, 0x81, 200, 0x00]),
          ScriptedStep(
            cmd: _cmd(p2: 0x03, le: 0xA0),
            response: Uint8List.fromList([0x6B, 0x00]),
          ),
        ]),
      );
      await expectLater(
        reader.selectFileAndRead(const [0x01, 0x1E]),
        throwsA(isA<ResponseError>()),
      );
      expect(reader.lastRead, (chunkSize: 0xA0, chunks: 2, bytes: 3));
    });

    test('a refused SELECT leaves lastRead null', () async {
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E], sw: '6a82'),
        ]),
      );
      await expectLater(
        reader.selectFileAndRead(const [0x01, 0x1E]),
        throwsA(isA<ResponseError>()),
      );
      expect(reader.lastRead, isNull);
    });
  });

  group('readAtrInfo', () {
    /// A 14-byte EF.ATR/INFO: card-service DO + the 7F66 template.
    final atrInfo = [
      0x43, 0x01, 0x00, //
      0x7F, 0x66, 0x08, 0x02, 0x02, 0x08, 0x00, 0x02, 0x02, 0x08, 0x00,
    ];

    /// A short answer ends the read: no header walk, one chunk-sized read.
    List<ScriptedStep> atrInfoRead(List<int> file, {int le = 0xA0}) => [
      _select(const [0x2F, 0x01]),
      ScriptedStep(
        cmd: _cmd(le: le),
        response: Uint8List.fromList([...file, 0x90, 0x00]),
      ),
    ];

    test(
      'MF select, SELECT 2F01, one read ended by the short answer',
      () async {
        final transceiver = ScriptedTransceiver([
          _mfSelect(),
          ...atrInfoRead(atrInfo),
        ]);
        final data = await TagReader(transceiver).readAtrInfo();
        expect(data, atrInfo);
        expect(transceiver.exhausted, isTrue);
      },
    );

    test('reads in fitted chunks; 6B 00 past the last byte ends it', () async {
      // A 16-byte file over 8-byte chunks: two full reads, then the chip
      // refuses offset 16.
      final file = List<int>.generate(16, (i) => i);
      final transceiver = ScriptedTransceiver([
        _mfSelect(),
        _select(const [0x2F, 0x01]),
        ScriptedStep(
          cmd: _cmd(le: 8),
          response: Uint8List.fromList([...file.sublist(0, 8), 0x90, 0x00]),
        ),
        ScriptedStep(
          cmd: _cmd(p2: 0x08, le: 8),
          response: Uint8List.fromList([...file.sublist(8), 0x90, 0x00]),
        ),
        ScriptedStep(
          cmd: _cmd(p2: 0x10, le: 8),
          response: Uint8List.fromList([0x6B, 0x00]),
        ),
      ]);
      final data = await TagReader(transceiver, readChunk: 8).readAtrInfo();
      expect(data, file);
      expect(transceiver.exhausted, isTrue);
    });

    test('62 82 with partial data ends it', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(),
        _select(const [0x2F, 0x01]),
        ScriptedStep(
          cmd: _cmd(le: 8),
          response: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 0x90, 0x00]),
        ),
        ScriptedStep(
          cmd: _cmd(p2: 0x08, le: 8),
          response: Uint8List.fromList([9, 10, 0x62, 0x82]),
        ),
      ]);
      final data = await TagReader(transceiver, readChunk: 8).readAtrInfo();
      expect(data, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      expect(transceiver.exhausted, isTrue);
    });

    test('6B 00 on the first read is an error, not an empty file', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(),
        _select(const [0x2F, 0x01]),
        ScriptedStep(
          cmd: _cmd(le: 0xA0),
          response: Uint8List.fromList([0x6B, 0x00]),
        ),
      ]);
      await expectLater(
        TagReader(transceiver).readAtrInfo(),
        throwsA(
          predicate(
            (e) => e is ResponseError && e.sw1 == 0x6B && e.sw2 == 0x00,
          ),
        ),
      );
    });

    test('absent file: the SELECT refusal propagates', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(),
        _select(const [0x2F, 0x01], sw: '6a82'),
      ]);
      await expectLater(
        TagReader(transceiver).readAtrInfo(),
        throwsA(
          predicate(
            (e) => e is ResponseError && e.sw1 == 0x6A && e.sw2 == 0x82,
          ),
        ),
      );
      expect(transceiver.exhausted, isTrue);
    });

    test('an MF-select refusal falls through to SELECT-by-FID', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(sw: '6a86'),
        ...atrInfoRead(atrInfo),
      ]);
      expect(await TagReader(transceiver).readAtrInfo(), atrInfo);
      expect(transceiver.exhausted, isTrue);
    });

    test('directFid quirk skips the MF select', () async {
      final transceiver = ScriptedTransceiver(atrInfoRead(atrInfo));
      await TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.directFid,
        ),
      ).readAtrInfo();
      expect(transceiver.exhausted, isTrue);
    });
  });

  group('selectCardAccess', () {
    test(
      'selects the master file, then EF.CardAccess, and reads nothing',
      () async {
        final transceiver = ScriptedTransceiver([
          _mfSelect(),
          _select(const [0x01, 0x1C]),
        ]);
        await TagReader(transceiver).selectCardAccess();
        expect(transceiver.exhausted, isTrue);
      },
    );

    test('an MF-select refusal falls through to SELECT-by-FID', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(sw: '6a86'),
        _select(const [0x01, 0x1C]),
      ]);
      await TagReader(transceiver).selectCardAccess();
      expect(transceiver.exhausted, isTrue);
    });

    test('directFid quirk skips the MF select', () async {
      final transceiver = ScriptedTransceiver([
        _select(const [0x01, 0x1C]),
      ]);
      await TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.directFid,
        ),
      ).selectCardAccess();
      expect(transceiver.exhausted, isTrue);
    });

    test('fid3F003004 quirk selects the master file in that dialect', () async {
      final transceiver = ScriptedTransceiver([
        ScriptedStep(
          cmd: _cmd(
            ins: 0xA4,
            p1: 0x00,
            p2: 0x0C,
            data: const [0x3F, 0x00, 0x30, 0x04],
          ),
          response: Uint8List.fromList([0x90, 0x00]),
        ),
        _select(const [0x01, 0x1C]),
      ]);
      await TagReader(
        transceiver,
        quirks: const ReadQuirks(
          selectVariant: MasterFileSelectVariant.fid3F003004,
        ),
      ).selectCardAccess();
      expect(transceiver.exhausted, isTrue);
    });

    test('a refused SELECT 011C propagates', () async {
      final transceiver = ScriptedTransceiver([
        _mfSelect(),
        _select(const [0x01, 0x1C], sw: '6a82'),
      ]);
      await expectLater(
        TagReader(transceiver).selectCardAccess(),
        throwsA(
          predicate(
            (e) => e is ResponseError && e.sw1 == 0x6A && e.sw2 == 0x82,
          ),
        ),
      );
      expect(transceiver.exhausted, isTrue);
    });
  });

  group('extended-length gate', () {
    test('send refuses an extended-length APDU when unsupported', () async {
      final reader = TagReader(ScriptedTransceiver([]));
      await expectLater(
        reader.send(_cmd(le: 300)),
        throwsA(
          predicate(
            (e) =>
                e is InvalidDataPassed &&
                e.message.contains('extended-length APDU not supported'),
          ),
        ),
      );
      expect(reader.lastRefusal, TransportRefusal.extendedLengthUnsupported);
    });

    test('send emits extended length when the transport supports it', () async {
      final transceiver = ScriptedTransceiver(
        [
          ScriptedStep(
            cmd: _cmd(le: 300),
            wire: Uint8List.fromList([
              0x00,
              0xB0,
              0x00,
              0x00,
              0x00,
              0x01,
              0x2C,
            ]),
            response: Uint8List.fromList([0xAA, 0x90, 0x00]),
          ),
        ],
        isExtendedLengthApduSupported: true,
        maxTransceiveLength: 0xFFFF,
      );
      final rep = await TagReader(transceiver).send(_cmd(le: 300));
      expect(rep.data, [0xAA]);
    });
  });

  group('transceive-length gate', () {
    test(
      'a command longer than maxTransceiveLength is refused before the transport',
      () async {
        final transceiver = ScriptedTransceiver([], maxTransceiveLength: 20);
        final reader = TagReader(transceiver);
        await expectLater(
          reader.send(_cmd(data: List.filled(16, 0))),
          throwsA(isA<InvalidDataPassed>()),
        );
        expect(reader.lastRefusal, TransportRefusal.exceedsTransceiveLength);
        expect(transceiver.consumedSteps, 0);
      },
    );

    test('a command exactly maxTransceiveLength long is sent', () async {
      final cmd = _cmd(data: List.filled(15, 0));
      final transceiver = ScriptedTransceiver([
        ScriptedStep(cmd: cmd, response: Uint8List.fromList([0x90, 0x00])),
      ], maxTransceiveLength: 20);
      final reader = TagReader(transceiver);
      await reader.send(cmd);
      expect(transceiver.exhausted, isTrue);
      expect(reader.lastRefusal, isNull);
    });

    test(
      'the cap measures the secure-messaging frame, not the plain command',
      () async {
        final transceiver = ScriptedTransceiver([], maxTransceiveLength: 20);
        final reader = TagReader(transceiver)
          ..secureMessaging = _session(SecureMessagingSupportedAlgorithms.des);
        await expectLater(
          reader.selectFile(const [0x01, 0x1E]),
          throwsA(isA<InvalidDataPassed>()),
        );
        expect(reader.lastRefusal, TransportRefusal.exceedsTransceiveLength);
        expect(transceiver.consumedSteps, 0);
      },
    );

    test('a refusal is cleared by the next send', () async {
      final small = _cmd(data: const [1, 2]);
      final transceiver = ScriptedTransceiver([
        ScriptedStep(cmd: small, response: Uint8List.fromList([0x90, 0x00])),
      ], maxTransceiveLength: 20);
      final reader = TagReader(transceiver);
      await expectLater(
        reader.send(_cmd(data: List.filled(16, 0))),
        throwsA(isA<InvalidDataPassed>()),
      );
      await reader.send(small);
      expect(reader.lastRefusal, isNull);
    });
  });

  group('offset ceiling', () {
    test('a read crossing offset 32767 fails typed, not corrupted', () async {
      final reader = TagReader(_EndlessReadTransceiver());
      await expectLater(
        reader.selectFileAndRead(const [0x01, 0x1E]),
        throwsA(
          predicate(
            (e) =>
                e is InvalidDataPassed &&
                e.message.contains('READ BINARY offset exceeds 32767'),
          ),
        ),
      );
    });
  });

  group('header hardening', () {
    test('header shorter than 4 bytes throws typed', () async {
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E]),
          ScriptedStep(
            cmd: _cmd(le: 4),
            response: Uint8List.fromList([0x60, 0x10, 0x90, 0x00]),
          ),
        ]),
      );
      await expectLater(
        reader.selectFileAndRead(const [0x01, 0x1E]),
        throwsA(
          predicate(
            (e) =>
                e is InvalidDataPassed &&
                e.message.contains('file header truncated/malformed'),
          ),
        ),
      );
    });

    test('unsupported length form in the header throws typed', () async {
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E]),
          _header(const [0x60, 0x83, 0xFF, 0xFF]),
        ]),
      );
      await expectLater(
        reader.selectFileAndRead(const [0x01, 0x1E]),
        throwsA(isA<InvalidDataPassed>()),
      );
    });

    test(
      'selectFile with a malformed tag length throws UnexpectedError',
      () async {
        // A 3-byte tag would still parse (trailing byte reads as Le); 4 bytes
        // cannot fit any ISO 7816-4 case: upstream's force-unwrap crashes.
        final reader = TagReader(ScriptedTransceiver([]));
        await expectLater(
          reader.selectFile(const [0x01, 0x1E, 0xFF, 0xEE]),
          throwsA(isA<UnexpectedError>()),
        );
      },
    );
  });

  group('send SW handling edges', () {
    test('6C 00 retries with Le 256', () async {
      final transceiver = ScriptedTransceiver([
        ScriptedStep(
          cmd: _cmd(p2: 0x04, le: 160),
          response: Uint8List.fromList([0x6C, 0x00]),
        ),
        ScriptedStep(
          cmd: _cmd(p2: 0x04, le: 256),
          wire: Uint8List.fromList([0x00, 0xB0, 0x00, 0x04, 0x00]),
          response: Uint8List.fromList([0xAA, 0xBB, 0x90, 0x00]),
        ),
      ]);
      final rep = await TagReader(transceiver).send(_cmd(p2: 0x04, le: 160));
      expect(rep.data, [0xAA, 0xBB]);
      expect(transceiver.exhausted, isTrue);
    });

    test(
      '62 82 with zero progress beyond the header throws (zero-progress guard)',
      () async {
        final reader = TagReader(
          ScriptedTransceiver([
            _select(const [0x01, 0x1E]),
            _header(const [0x60, 0x10, 0xAA, 0xBB]),
            ScriptedStep(
              cmd: _cmd(p2: 0x02, le: 16),
              response: Uint8List.fromList([0x62, 0x82]),
            ),
          ]),
        );
        await expectLater(
          reader.selectFileAndRead(const [0x01, 0x1E]),
          throwsA(
            predicate(
              (e) => e is ResponseError && e.sw1 == 0x62 && e.sw2 == 0x82,
            ),
          ),
        );
      },
    );
  });

  group('misc', () {
    test('readDataGroup(Unknown) throws UnsupportedDataGroup', () async {
      final reader = TagReader(ScriptedTransceiver([]));
      await expectLater(
        reader.readDataGroup(DataGroupId.Unknown),
        throwsA(isA<UnsupportedDataGroup>()),
      );
    });

    test('transceiver errors propagate untouched', () async {
      final reader = TagReader(_ThrowingTransceiver());
      await expectLater(reader.getChallenge(), throwsA(isA<ConnectionError>()));
    });

    test('progress reports the upstream percentage trajectory', () async {
      final content = List<int>.generate(0x40, (i) => i);
      final reader = TagReader(
        ScriptedTransceiver([
          _select(const [0x01, 0x1E]),
          _header([0x60, 0x40, content[0], content[1]]),
          ScriptedStep(
            cmd: _cmd(p2: 0x02, le: 0x40),
            response: Uint8List.fromList([...content, 0x90, 0x00]),
          ),
        ]),
      );
      final seen = <int>[];
      reader.progress = seen.add;
      await reader.selectFileAndRead(const [0x01, 0x1E]);
      expect(seen, [3], reason: '2 of 66 bytes read -> 3%');
    });
  });
}
