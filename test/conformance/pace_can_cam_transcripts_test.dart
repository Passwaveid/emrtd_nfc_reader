/// Authors and pins the CAN-password PACE session transcript, on the pattern
/// of `pace_mapping_transcripts_test.dart`.
///
/// There is no published CAN chain anywhere: ICAO 9303's worked examples
/// (App G, App H, App I) are all MRZ, so this fixture is synthesized from the
/// App G.1 ECDH-GM material with the password swapped, through
/// [PaceChipSimulator]. That makes it a *consistency* artifact: it proves the
/// port's terminal and a chip agreeing on the `PacePassword` plumbing produce
/// a complete session, and pins the wire so a regression is visible.
///
/// The correctness anchor for the one new value in it (K_π off a CAN, and the
/// DO83 reference byte 0x02 the MSE:Set AT carries) is `kdf_pace.json`'s
/// `pace.createPaceKey` rows, whose expectations come from the independent
/// python oracle (`conformance/tools/pace_cam_password_oracle.py`), not from
/// this sim. Everything downstream of K_π is mechanism the MRZ transcripts
/// already pin against published chains.
///
/// Regenerate with `REGENERATE_PACE_CAN_CAM_TRANSCRIPTS=1 flutter test
/// test/conformance/pace_can_cam_transcripts_test.dart`. Otherwise the test
/// asserts the committed file still matches what the port and the sim
/// produce, so a behavior change cannot silently drift away from its fixture.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/pace_chip_sim.dart';
import '../support/scripted_transceiver.dart';

Uint8List _h(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);
String _x(List<int> b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
BigInt _b(String s) => BigInt.parse(s, radix: 16);

/// The CAN the `kdf_pace.json` python-oracle row derives
/// K_π = 591468CDA83D65219CCCB8560233600F from.
const _can = '123456';

/// EF.CardAccess: id-PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameterId 13.
const _cardAccessHex = '31143012060a04007f0007020204020202010202010d';

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

void main() {
  final regenerate =
      Platform.environment['REGENERATE_PACE_CAN_CAM_TRANSCRIPTS'] == '1';

  test('pace_session_can_ecdh_gm_aes128: the CAN password end to end', () async {
    final password = PacePassword.can(_can);
    final chip = PaceChipSimulator(
      oid: '0.4.0.127.0.7.2.2.4.2.2',
      password: password,
      nonce: _h('3f00c4d39d153f2b2a214a078d899b22'),
      chipMappingPrivateKey: _b(
        '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
      ),
      chipEphemeralPrivateKey: _b(
        '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
      ),
    );
    final reader = TagReader(chip);
    final handler = PACEHandler(
      cardAccess: CardAccess(_h(_cardAccessHex)),
      tagReader: reader,
      mappingPrivateKey: _b(
        '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
      ),
      ephemeralPrivateKey: _b(
        'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
      ),
    );
    await handler.doPACEWithPassword(password);
    // The SM handoff: the first protected command proves the session keys.
    await reader.selectPassportApplication();

    final steps = [
      for (var i = 0; i < chip.sentCommands.length; i++)
        _step(chip.sentCommands[i], chip.sentResponses[i]),
    ];

    // The point of the fixture: MSE:Set AT selects the CAN, not the MRZ.
    expect(
      steps[0]['wire'],
      contains('830102'),
      reason: 'DO83 must carry CAN_PACE_KEY_REFERENCE (0x02), not 0x01',
    );
    expect(steps[0]['wire'], isNot(contains('830101')));
    // The password reached the KDF: K_pi is the python-oracle value, so the
    // chip's encrypted nonce is the one that key produces.
    expect(
      _x(
        paceCreatePaceKey(
          password: password,
          cipherAlgName: 'AES',
          keyLength: 128,
        ),
      ),
      '591468cda83d65219cccb8560233600f',
      reason: 'K_pi must match the kdf_pace.json python-oracle CAN row',
    );

    final transcript = <String, Object?>{
      'transcript': 'pace_session_can_ecdh_gm_aes128',
      'schemaVersion': 1,
      'runners': ['dart'],
      'description':
          'Full PACE ECDH-GM AES-128 session authenticated with a CAN rather '
          'than the MRZ. The MSE:Set AT carries DO83 = 02 '
          '(CAN_PACE_KEY_REFERENCE) and DO84 (parameterId 13); K_pi '
          'derives from the ISO/IEC 8859-1 octets of the CAN with no hash '
          '(P11 §9.7.3 Table 14), where the MRZ path hashes. '
          'runners:["dart"]; upstream ships the CAN reference constant '
          'but never sets it, so its createPaceKey cannot derive this key '
          'at all. No published CAN chain exists (App G/H/I are '
          'all MRZ), so the wire here is sim-synthesized from the App G.1 '
          'ECDH-GM material with the password swapped; K_pi itself is '
          'pinned independently by the python-oracle rows in '
          'kdf_pace.json. Domain, both keypairs and the nonce '
          'are App G.1\'s, so a diff against '
          'pace_session_ecdh_gm_aes128.json isolates exactly what the '
          'password changes. The final step is the first post-PACE '
          'protected command.',
      'session': {
        'secureMessaging': 'pace',
        'cardAccess': _cardAccessHex,
        'password': {'type': 'can', 'value': _can},
        'ephemeralKeys': {
          'mappingKey':
              '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
          'ephemeralKey':
              'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
        },
      },
      'drive': {'op': 'selectPassportApplication'},
      'steps': steps,
      'expect': {
        'out': {'data': '', 'sw': '9000'},
      },
    };

    final file = File(
      'conformance/transcripts/pace_session_can_ecdh_gm_aes128.json',
    );
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
          'missing pace_session_can_ecdh_gm_aes128.json; regenerate '
          'with REGENERATE_PACE_CAN_CAM_TRANSCRIPTS=1',
    );
    expect(
      jsonDecode(file.readAsStringSync()),
      jsonDecode(rendered),
      reason:
          'the transcript drifted from what the port now produces; '
          'regenerate with REGENERATE_PACE_CAN_CAM_TRANSCRIPTS=1 and review the '
          'diff',
    );
  });

  // Extracting the CAM data changes nothing on the wire, so the CAM
  // transcript is both-runner and the schema has nowhere to express "and
  // camData decrypted to this". The assertion lives here instead: replay the
  // committed App I.1 fixture through the handler and check what it
  // extracted. This is the one place the *published* DO8A meets the *port's*
  // extraction end to end: the vectors pin the decrypt in isolation, the sim
  // pins the composition, and this pins both against the real published wire.
  test(
    'the committed App I.1 CAM transcript yields the published CA_IC',
    () async {
      final t =
          jsonDecode(
                File(
                  'conformance/transcripts/pace_session_cam_aes128.json',
                ).readAsStringSync(),
              )
              as Map<String, Object?>;
      final session = (t['session']! as Map).cast<String, Object?>();
      final eph = (session['ephemeralKeys']! as Map).cast<String, Object?>();

      // Only the PACE handshake steps: the trailing post-PACE SELECT is not
      // driven here.
      final steps = <ScriptedStep>[
        for (final raw in (t['steps']! as List).take(5))
          () {
            final s = (raw as Map).cast<String, Object?>();
            final cmd = (s['cmd']! as Map).cast<String, Object?>();
            final resp = (s['resp']! as Map).cast<String, Object?>();
            return ScriptedStep(
              cmd: CommandAPDU(
                instructionClass: int.parse(cmd['cla']! as String, radix: 16),
                instructionCode: int.parse(cmd['ins']! as String, radix: 16),
                p1Parameter: int.parse(cmd['p1']! as String, radix: 16),
                p2Parameter: int.parse(cmd['p2']! as String, radix: 16),
                data: _h(cmd['data']! as String),
                expectedResponseLength: (cmd['le'] as num?)?.toInt() ?? -1,
              ),
              wire: _h(s['wire']! as String),
              response: Uint8List.fromList([
                ..._h(resp['data']! as String),
                ..._h(resp['sw']! as String),
              ]),
            );
          }(),
      ];

      final handler = PACEHandler(
        cardAccess: CardAccess(_h(session['cardAccess']! as String)),
        tagReader: TagReader(ScriptedTransceiver(steps)),
        mappingPrivateKey: _b(eph['mappingKey']! as String),
        ephemeralPrivateKey: _b(eph['ephemeralKey']! as String),
      );
      await handler.doPACE(session['mrzKey']! as String);

      final cam = handler.camData;
      expect(cam, isNotNull, reason: 'a CAM session must populate camData');
      expect(cam!.cause, isNull);
      // App I-11, "Decrypted Chip Authentication Data".
      expect(
        _x(cam.chipAuthenticationData!),
        '85dc3fa93d0952bfa82f5fd189ee75bd82f11d1f0b8ed4bf5319ac9b53c426b3',
      );
      // App I-11, PK_Map,IC: retained from the step-2 DO82.
      expect(
        _x(cam.mappingPublicKey),
        '04a234236aa9b9621e8efb73b5245c0e09d2576e5277183c1208bdd55280cae8b3'
        '04f365713a356e65a451e165ecc9ac0ac46e3771342c8fe5aedd092685338e23',
      );
      expect(cam.domain.domainName, 'brainpoolp256r1');
    },
  );
}
