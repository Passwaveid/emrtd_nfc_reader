/// Authors and pins the multi-chunk read transcripts, on the pattern of the
/// PACE transcript tests: `read_chunk223_bac` and `read_chunk223_pace_aes`, a
/// 1078-byte DG2 read at the `ReadProfile.standard` chunk (223) under each
/// cipher, so the 244-byte secure-messaging response frames are visible
/// byte-exactly on the Dart side and upstream's own SM produces the same
/// bytes on the Swift side (both runners: the drive args'
/// `maxDataLengthToRead` is honoured by both replay runners).
///
/// The wire is sim-synthesized ([EmrtdChipSim] answers the terminal's real
/// traffic); the BAC material is App D's (the `bac_session_efcom`
/// precedent) and the PACE keys are the `pace_session_can_ecdh_gm_aes128`
/// transcript's.
///
/// Regenerate with `REGENERATE_READ_CHUNK_TRANSCRIPTS=1 flutter test
/// test/conformance/read_chunk_transcripts_test.dart`. Otherwise the test
/// asserts the committed files still match what the port and the sim produce.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/proto/bac.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_chip_sim.dart';
import '../support/emrtd_fixtures.dart';

String _x(List<int> b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
BigInt _b(String s) => BigInt.parse(s, radix: 16);

/// App D.3's RND.IFD ‖ K.IFD, the `bac_session_efcom` rng.
const _bacRng = '781723860c06c2260b795240cb7049b01c19b33e32804f0b';

const _mappingKey =
    '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99';
const _ephemeralKey =
    'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595';

/// Records every command/response pair the sim exchanges, so the transcript
/// carries the chip's answers as well as the terminal's commands.
class _Recording implements NfcTransceiver {
  _Recording(this._inner);

  final EmrtdChipSim _inner;
  final List<(Uint8List, Uint8List)> exchanges = [];

  @override
  int get maxTransceiveLength => _inner.maxTransceiveLength;
  @override
  bool get isExtendedLengthApduSupported =>
      _inner.isExtendedLengthApduSupported;
  @override
  Uint8List? get historicalBytes => _inner.historicalBytes;
  @override
  TagCapabilities? get tagCapabilities => _inner.tagCapabilities;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    final resp = await _inner.transceive(capdu);
    exchanges.add((Uint8List.fromList(capdu), Uint8List.fromList(resp)));
    return resp;
  }
}

/// Short-form command parse into the transcript's structured shape; every
/// command these sessions send is short-form (Le 223 fits a byte).
Map<String, Object?> _step(Uint8List cmd, Uint8List resp) {
  final lc = cmd.length > 4 ? cmd[4] : 0;
  final hasData = cmd.length > 5;
  final data = hasData ? cmd.sublist(5, 5 + lc) : const <int>[];
  final le = hasData && cmd.length > 5 + lc
      ? (cmd[5 + lc] == 0 ? 256 : cmd[5 + lc])
      : (!hasData && cmd.length == 5 ? (cmd[4] == 0 ? 256 : cmd[4]) : -1);
  return {
    'cmd': {
      'cla': _x([cmd[0]]),
      'ins': _x([cmd[1]]),
      'p1': _x([cmd[2]]),
      'p2': _x([cmd[3]]),
      'data': _x(data),
      'le': le,
    },
    'wire': _x(cmd),
    'resp': {
      'data': _x(resp.sublist(0, resp.length - 2)),
      'sw': _x(resp.sublist(resp.length - 2)),
    },
  };
}

/// The port emits DO84 in MSE:Set AT, upstream never does (see UPSTREAM.md,
/// Divergences). The Swift runner replays upstream, so the step carries its
/// form too (SCHEMA.md `cmdFor`).
Map<String, Object?> withUpstreamMseSetAt(Map<String, Object?> step) {
  final cmd = (step['cmd']! as Map).cast<String, Object?>();
  final data = cmd['data']! as String;
  expect(cmd['ins'], '22');
  expect(data, endsWith('84010d'), reason: 'parameterId 13 DO84 expected');
  return {
    ...step,
    'cmdFor': {
      'swift': {...cmd, 'data': data.substring(0, data.length - 6)},
    },
  };
}

void main() {
  final regenerate =
      Platform.environment['REGENERATE_READ_CHUNK_TRANSCRIPTS'] == '1';
  final largeDg2 = buildLargeDg2();

  void pin(String name, Map<String, Object?> transcript) {
    final file = File('conformance/transcripts/$name.json');
    final rendered =
        '${const JsonEncoder.withIndent('  ').convert(transcript)}\n';
    if (regenerate) {
      file.writeAsStringSync(rendered);
      return;
    }
    expect(
      file.existsSync(),
      isTrue,
      reason:
          'missing $name.json; regenerate with '
          'REGENERATE_READ_CHUNK_TRANSCRIPTS=1',
    );
    expect(
      jsonDecode(file.readAsStringSync()),
      jsonDecode(rendered),
      reason:
          'the transcript drifted from what the port now produces; '
          'regenerate with REGENERATE_READ_CHUNK_TRANSCRIPTS=1 and review the '
          'diff',
    );
  }

  /// The READ BINARY Le sequence the steps carry, header read included:
  /// the DO97 value, since the protected wrapper's own Le is always `00`.
  List<int> readLes(List<Map<String, Object?>> steps) => [
    for (final s in steps)
      if ((s['cmd']! as Map)['ins'] == 'b0')
        () {
          final data = (s['cmd']! as Map)['data']! as String;
          final do97 = data.indexOf('9701');
          return int.parse(data.substring(do97 + 4, do97 + 6), radix: 16);
        }(),
  ];

  test('read_chunk223_bac: 3DES frames of 244 bytes', () async {
    final chip = _Recording(
      EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(dg2: largeDg2),
      ),
    );
    final reader = TagReader(chip)..overrideDataAmountToRead(223);
    await BACHandler(
      tagReader: reader,
      random: FixedRandom([
        for (var i = 0; i < _bacRng.length; i += 2)
          int.parse(_bacRng.substring(i, i + 2), radix: 16),
      ]),
    ).performBACAndGetSessionKeys(specimenMrzInfo);
    final out = await reader.selectFileAndRead(const [0x01, 0x02]);
    expect(out, largeDg2);

    final steps = [for (final (c, r) in chip.exchanges) _step(c, r)];
    expect(readLes(steps), [4, 223, 223, 223, 223, 182]);
    // GET CHALLENGE, EXTERNAL AUTHENTICATE, SELECT and the header read
    // precede the four full chunks. The frame arithmetic: a 223-byte
    // plaintext under 3DES is a 244-byte response frame (DO87 1+2+225,
    // DO99 4, DO8E 10, SW 2).
    final fullChunkFrames = [
      for (final s in steps.sublist(4, 8))
        ((s['resp']! as Map)['data']! as String).length ~/ 2 + 2,
    ];
    expect(fullChunkFrames, everyElement(244));

    pin('read_chunk223_bac', {
      'transcript': 'read_chunk223_bac',
      'schemaVersion': 1,
      'description':
          'A 1078-byte DG2 read at the standard '
          'chunk of 223 (0xDF) under BAC 3DES secure messaging; five body '
          'chunks after the header read, each full chunk answered with a '
          '244-byte response frame (DO87 1+2+225 ‖ DO99 4 ‖ DO8E 10 ‖ SW 2), '
          'the frame arithmetic that makes 223 fit both the 261-byte and the '
          '253-byte transport caps. Handshake material is ICAO 9303 P11 '
          'App D.3 (rndIcc/kicc/RND.IFD/K.IFD as in bac_session_efcom); the '
          'file bytes and every protected response are sim-synthesized. '
          'Both runners: maxDataLengthToRead is applied through '
          'overrideDataAmountToRead on each.',
      'session': {
        'secureMessaging': 'bac',
        'mrzKey': specimenMrzInfo,
        'rng': _bacRng,
      },
      'drive': {
        'op': 'selectFileAndRead',
        'args': {'tag': '0102', 'maxDataLengthToRead': 223},
      },
      'steps': steps,
      'expect': {'out': _x(largeDg2)},
    });
  });

  test('read_chunk223_pace_aes: AES frames of 244 bytes', () async {
    final chip = _Recording(
      EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(dg2: largeDg2),
        cardAccess: hx(cardAccessG1Hex),
        pace: paceG1Config(),
      ),
    );
    final reader = TagReader(chip)..overrideDataAmountToRead(223);
    await PACEHandler(
      cardAccess: CardAccess(hx(cardAccessG1Hex)),
      tagReader: reader,
      mappingPrivateKey: _b(_mappingKey),
      ephemeralPrivateKey: _b(_ephemeralKey),
    ).doPACE(specimenMrzInfo);
    final out = await reader.selectFileAndRead(const [0x01, 0x02]);
    expect(out, largeDg2);

    final steps = [for (final (c, r) in chip.exchanges) _step(c, r)];
    expect(readLes(steps), [4, 223, 223, 223, 223, 182]);
    // MSE:Set AT + four GA rounds precede the SELECT; the four full chunks
    // follow the header read. AES pads 223 to 224 as well: 244-byte frames.
    final fullChunkFrames = [
      for (final s in steps.sublist(7, 11))
        ((s['resp']! as Map)['data']! as String).length ~/ 2 + 2,
    ];
    expect(fullChunkFrames, everyElement(244));

    pin('read_chunk223_pace_aes', {
      'transcript': 'read_chunk223_pace_aes',
      'schemaVersion': 1,
      'description':
          'The same 1078-byte DG2 read at 223 under '
          'a PACE ECDH-GM AES-128 session (App G.1 domain, nonce and '
          'terminal keypairs, sim-synthesized chip side); AES pads 223 '
          'to 224 exactly as 3DES does, so each full chunk is again a '
          '244-byte response frame. The pair with read_chunk223_bac pins '
          'that the fitReadLength arithmetic holds under both ciphers. '
          'Both runners.',
      'session': {
        'secureMessaging': 'pace',
        'cardAccess': cardAccessG1Hex,
        'mrzKey': specimenMrzInfo,
        'ephemeralKeys': {
          'mappingKey': _mappingKey,
          'ephemeralKey': _ephemeralKey,
        },
      },
      'drive': {
        'op': 'selectFileAndRead',
        'args': {'tag': '0102', 'maxDataLengthToRead': 223},
      },
      'steps': [withUpstreamMseSetAt(steps.first), ...steps.skip(1)],
      'expect': {'out': _x(largeDg2)},
    });
  });
}
