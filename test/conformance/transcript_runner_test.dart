/// Golden-transcript replay runner (Dart side).
///
/// Enumerates `conformance/transcripts/*.json`, and for each fixture invokes
/// `drive.op` with `drive.args` on a [TagReader] over a [ScriptedTransceiver]
/// that asserts every emitted command structurally (both runners) and against
/// the canonical wire bytes (Dart only), then asserts `expect`:
/// deep-equal parsed output or the thrown error code, exactly like the vector
/// runner. The Swift twin lives in the fork's ConformanceTests target
/// (`TranscriptReplayTests.swift`, mock `NFCISO7816Tag`, runs at S2).
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/lds/data_group14.dart';
import 'package:emrtd_core/src/lds/data_group15.dart';
import 'package:emrtd_core/src/proto/active_authentication.dart';
import 'package:emrtd_core/src/proto/bac.dart';
import 'package:emrtd_core/src/proto/chip_authentication.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/response_apdu.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/scripted_transceiver.dart';

const _runnerName = 'dart';
const _supportedSchemaVersion = 1;

List<int> _bytes(Object? hex) {
  final s = hex! as String;
  if (s.length.isOdd) {
    fail('transcript hex value has odd length: "$s"');
  }
  return [
    for (var i = 0; i < s.length; i += 2)
      int.parse(s.substring(i, i + 2), radix: 16),
  ];
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

ScriptedStep _step(Map<String, Object?> raw) {
  final cmd = (raw['cmd']! as Map).cast<String, Object?>();
  final resp = (raw['resp']! as Map).cast<String, Object?>();
  final wire = raw['wire'] as String?;
  return ScriptedStep(
    cmd: CommandAPDU(
      instructionClass: int.parse(cmd['cla']! as String, radix: 16),
      instructionCode: int.parse(cmd['ins']! as String, radix: 16),
      p1Parameter: int.parse(cmd['p1']! as String, radix: 16),
      p2Parameter: int.parse(cmd['p2']! as String, radix: 16),
      data: _bytes(cmd['data']),
      expectedResponseLength: (cmd['le'] as num?)?.toInt() ?? -1,
    ),
    wire: wire == null ? null : Uint8List.fromList(_bytes(wire)),
    response: Uint8List.fromList([
      ..._bytes(resp['data']),
      ..._bytes(resp['sw']),
    ]),
  );
}

Map<String, Object?> _rapduMap(ResponseAPDU r) => {
  'data': _hex(r.data),
  'sw': _hex([r.sw1, r.sw2]),
};

/// A `pace` session's password. `password: {type, value}` is the general
/// form; `mrzKey` is the MRZ shorthand (additive, so schemaVersion stays 1,
/// the `ephemeralKeys` precedent).
PacePassword _password(Map<String, Object?> session) {
  final spec = (session['password'] as Map?)?.cast<String, Object?>();
  if (spec == null) {
    return PacePassword.mrz(session['mrzKey']! as String);
  }
  final value = spec['value']! as String;
  return switch (spec['type']! as String) {
    'mrz' => PacePassword.mrz(value),
    'can' => PacePassword.can(value),
    'pin' => PacePassword.pin(value),
    'cuk' => PacePassword.cuk(value),
    final other => fail('unknown session.password type "$other"'),
  };
}

void main() {
  final transcriptsDir = Directory('conformance/transcripts');
  final files = transcriptsDir.existsSync()
      ? (transcriptsDir
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json'))
            .toList()
          ..sort((a, b) => a.path.compareTo(b.path)))
      : <File>[];

  test('transcript discovery finds at least one fixture', () {
    expect(
      files,
      isNotEmpty,
      reason:
          'no *.json under conformance/transcripts: run `flutter test` '
          'from the package root',
    );
  });

  for (final file in files) {
    final t = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
    final name = t['transcript'] as String? ?? file.path;

    group('transcript/$name', () {
      test('schemaVersion is supported', () {
        expect(t['schemaVersion'], _supportedSchemaVersion);
      });

      // Omitted runners = both; split behavior ships as sibling files, one
      // per runner.
      final runners =
          (t['runners'] as List?)?.cast<String>() ?? const ['swift', 'dart'];
      if (!runners.contains(_runnerName)) {
        test(
          'transcript gated off this runner',
          () {},
          skip: 'runners: $runners excludes "$_runnerName"',
        );
        return;
      }

      test('replay', () async {
        final session =
            (t['session'] as Map?)?.cast<String, Object?>() ?? const {};
        final smMode = session['secureMessaging'];
        expect(
          smMode,
          anyOf('none', 'bac', 'pace'),
          reason:
              'session.secureMessaging must be "none", "bac" '
              'or "pace" (cardAccess + mrzKey + injected ephemeralKeys '
              'establish the session before drive.op; the MSE:AT + GA handshake '
              'steps are part of the transcript)',
        );

        final steps = (t['steps']! as List)
            .map((s) => _step((s as Map).cast<String, Object?>()))
            .toList();
        final transceiver = ScriptedTransceiver(steps);
        final reader = TagReader(transceiver);

        final drive = (t['drive']! as Map).cast<String, Object?>();
        final args =
            (drive['args'] as Map?)?.cast<String, Object?>() ?? const {};
        final maxDataLengthToRead = args['maxDataLengthToRead'] as int?;
        if (maxDataLengthToRead != null) {
          reader.overrideDataAmountToRead(maxDataLengthToRead);
        }

        BigInt? bigIntArg(Map<String, Object?> m, String key) {
          final v = m[key] as String?;
          return v == null ? null : BigInt.parse(v, radix: 16);
        }

        Future<Object?> run() async {
          if (smMode == 'bac') {
            // The injected RNG makes the handshake deterministic; rng is
            // RND.IFD(8) ‖ K.IFD(16); GET CHALLENGE/EXTERNAL AUTHENTICATE
            // are scripted steps like any other.
            final bac = BACHandler(
              tagReader: reader,
              random: FixedRandom(_bytes(session['rng'])),
            );
            await bac.performBACAndGetSessionKeys(session['mrzKey']! as String);
          } else if (smMode == 'pace') {
            // Both PACE keypairs and the Integrated Mapping's PCD nonce t
            // are injected so the whole MSE:AT + GA handshake is
            // deterministic; the steps are scripted like any other. An
            // upstream-only (DH-GM/IM) partial session throws here, before
            // drive.
            final eph =
                (session['ephemeralKeys'] as Map?)?.cast<String, Object?>() ??
                const {};
            final imNonce = eph['imNonce'] as String?;
            final handler = PACEHandler(
              cardAccess: CardAccess(_bytes(session['cardAccess'])),
              tagReader: reader,
              mappingPrivateKey: bigIntArg(eph, 'mappingKey'),
              ephemeralPrivateKey: bigIntArg(eph, 'ephemeralKey'),
              imNonce: imNonce == null
                  ? null
                  : Uint8List.fromList(_bytes(imNonce)),
            );
            await handler.doPACEWithPassword(_password(session));
          }
          return switch (drive['op']! as String) {
            'selectFileAndRead' => _hex(
              await reader.selectFileAndRead(_bytes(args['tag'])),
            ),
            'readCardAccess' => _hex(await reader.readCardAccess()),
            // The pre-authentication EF.ATR/INFO read, a bare DO sequence
            // read until the chip signals its end, so it never goes through
            // selectFileAndRead's header walk.
            'readAtrInfo' => _hex(await reader.readAtrInfo()),
            'doMutualAuthentication' => _rapduMap(
              await reader.doMutualAuthentication(
                Uint8List.fromList(_bytes(args['cmdData'])),
              ),
            ),
            'sendGeneralAuthenticate' => _rapduMap(
              await reader.sendGeneralAuthenticate(
                data: _bytes(args['data']),
                lengthExpected: args['lengthExpected'] as int? ?? 256,
                isLast: args['isLast']! as bool,
              ),
            ),
            'selectPassportApplication' => _rapduMap(
              await reader.selectPassportApplication(),
            ),
            // The CA handshake runs over the session the `session` block
            // established, then the first post-CA protected command proves
            // the derived keys, as the post-PACE SELECT does. A failed
            // handshake throws before that command is ever sent.
            'chipAuthentication' => await () async {
              final handler = ChipAuthenticationHandler(
                dg14: DataGroup14(_bytes(args['dg14'])),
                tagReader: reader,
                ephemeralPrivateKey: bigIntArg(args, 'ephemeralKey'),
              );
              await handler.doChipAuthentication();
              return _rapduMap(await reader.selectPassportApplication());
            }(),
            // INTERNAL AUTHENTICATE over the session the `session` block
            // established, then the pure verifier over the response.
            // The fixed `challenge` arg makes replay deterministic without a
            // new seam (the RNG never runs on this path).
            'activeAuthentication' => await () async {
              final challenge = _bytes(args['challenge']);
              final response = await reader.doInternalAuthentication(
                challenge: challenge,
              );
              final dg14Hex = args['dg14'] as String?;
              final verdict = verifyActiveAuthentication(
                dg15: DataGroup15(_bytes(args['dg15'])),
                dg14: dg14Hex == null ? null : DataGroup14(_bytes(dg14Hex)),
                challenge: challenge,
                signature: response.data,
              );
              return {
                'passed': verdict.passed,
                'signature': _hex(response.data),
              };
            }(),
            // The session establishment itself is under test (BAC/PACE error
            // fixtures); nothing to drive afterwards.
            'none' => '',
            final other => fail(
              'unknown drive op "$other": extend both replay runners '
              'and the transcript schema in conformance/SCHEMA.md',
            ),
          };
        }

        final expectation = (t['expect']! as Map).cast<String, Object?>();
        final expectedError = expectation['error'] as String?;
        if (expectedError != null) {
          await expectLater(
            run(),
            throwsA(
              predicate(
                (e) => e is EmrtdException && e.code == expectedError,
                'EmrtdException with code "$expectedError"',
              ),
            ),
          );
        } else {
          expect(await run(), equals(expectation['out']));
        }
        expect(
          transceiver.exhausted,
          isTrue,
          reason:
              'transcript has ${steps.length - transceiver.consumedSteps} '
              'unconsumed step(s): the implementation stopped early',
        );
      });
    });
  }
}
