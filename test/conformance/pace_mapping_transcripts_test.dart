/// Authors and pins the three PACE mapping session transcripts.
///
/// The DH-GM fixture replays ICAO 9303 Part 11 App G.2: every GA command and
/// response is a published APDU, asserted here byte-for-byte before the file
/// is written, so the transcript is *published-wire* validation independent of
/// the simulator. The two IM fixtures have no published APDU listings (App H
/// prints values only), so they are synthesized from App H.1/H.2's values plus
/// the §4.4.5.2.2 wire rules through [PaceChipSimulator]: consistency, not
/// authority; correctness for those chains lives in `pace_im.json`.
///
/// Regenerate with `REGENERATE_PACE_MAPPING_TRANSCRIPTS=1 flutter test
/// test/conformance/pace_mapping_transcripts_test.dart` (the
/// `REGENERATE_PASSIVE_AUTH_VECTORS` precedent). Otherwise the test asserts the
/// committed files still match what the port and the sim produce, so a
/// behavior change cannot silently drift away from its fixture.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/pace_chip_sim.dart';

Uint8List _h(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);
String _x(List<int> b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();
BigInt _b(String s) => BigInt.parse(s, radix: 16);

const _mrz = 'T22000129364081251010318';

/// One recorded exchange, rendered into the schema-v1 `steps` shape.
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

Future<List<Map<String, Object?>>> _record(
  PaceChipSimulator chip,
  PACEHandler Function(TagReader) handler,
) async {
  final reader = TagReader(chip);
  await handler(reader).doPACE(_mrz);
  // The SM handoff: the first protected command proves the session keys.
  await reader.selectPassportApplication();
  return [
    for (var i = 0; i < chip.sentCommands.length; i++)
      _step(chip.sentCommands[i], chip.sentResponses[i]),
  ];
}

void main() {
  final regenerate =
      Platform.environment['REGENERATE_PACE_MAPPING_TRANSCRIPTS'] == '1';

  Future<void> check(
    String name,
    String description,
    Map<String, Object?> session,
    PaceChipSimulator chip,
    PACEHandler Function(TagReader) handler, {
    void Function(List<Map<String, Object?>> steps)? assertPublishedWire,
  }) async {
    final steps = await _record(chip, handler);
    assertPublishedWire?.call(steps);
    final transcript = <String, Object?>{
      'transcript': name,
      'schemaVersion': 1,
      'runners': ['dart'],
      'description': description,
      'session': session,
      'drive': {'op': 'selectPassportApplication'},
      'steps': steps,
      'expect': {
        'out': {'data': '', 'sw': '9000'},
      },
    };
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
          'REGENERATE_PACE_MAPPING_TRANSCRIPTS=1',
    );
    expect(
      jsonDecode(file.readAsStringSync()),
      jsonDecode(rendered),
      reason:
          '$name.json drifted from what the port now produces; '
          'regenerate with REGENERATE_PACE_MAPPING_TRANSCRIPTS=1 and review the diff',
    );
  }

  test('pace_session_dh_gm_aes128 matches the App G.2 published APDUs', () async {
    await check(
      'pace_session_dh_gm_aes128',
      'Full PACE DH-GM AES-128 session, ICAO 9303 Part 11 App G.2 (RFC 5114 '
          '1024/160). GA rounds 1-4 (both terminal commands and chip '
          'responses) are byte-for-byte the App G.2 APDU listings; the '
          'MSE:Set AT carries DO84 (parameterId 0), diverging from '
          'App G.2 which omits it. Both PACE keypairs are injected. '
          'This is the completed twin of pace_session_dh_gm_partial.json, '
          'which pins upstream aborting at step 3 over the same first '
          'three exchanges, hence runners:["dart"]. The final step is the '
          'first post-PACE protected command: SELECT eMRTD AID under '
          'the installed AES SM (sim-synthesized chip response; App G.2 stops '
          'at the tokens).',
      {
        'secureMessaging': 'pace',
        'cardAccess': '31143012060a04007f00070202040102020102020100',
        'mrzKey': _mrz,
        'ephemeralKeys': {
          'mappingKey': '5265030f751f4ad18b08ac565fc7ac952e41618d',
          'ephemeralKey': '89ccd99b0e8d3b1f11e1296dca68ec53411cf2ca',
        },
      },
      PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.1.2',
        password: PacePassword.mrz(_mrz),
        parameterId: 0,
        nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        chipMappingPrivateKey: _b('66ddafeac1609cb5b963bb0cb3ff8b3e047f336c'),
        chipEphemeralPrivateKey: _b('a5b780126b7c980e9fcea1d4539da1d27c342dfa'),
      ),
      (reader) => PACEHandler(
        cardAccess: CardAccess(
          _h(
            '31143012060a04007f000702020401020201'
            '02020100',
          ),
        ),
        tagReader: reader,
        mappingPrivateKey: _b('5265030f751f4ad18b08ac565fc7ac952e41618d'),
        ephemeralPrivateKey: _b('89ccd99b0e8d3b1f11e1296dca68ec53411cf2ca'),
      ),
      assertPublishedWire: (steps) {
        // Every byte below is transcribed from the App G.2 APDU listings
        // (App G-11 to G-19). The MSE:Set AT is the one deliberate
        // divergence (the port's DO84); its published form is
        // 0022c1a40f800a...830101.
        final published = <int, String>{
          1: '10860000027c0000',
          2:
              '10860000867c818381818023fb3749ea030d2a25b278d2a562047ade3f01b7'
              '4f17a15402cb7352ca7d2b3eb71c343db13d1debce9a3666dbcfc920b49174'
              'a602cb47965caa73dc702489a44d41db914de9613dc5e98c94160551c0df86'
              '274b9359bc0490d01b03ad54022dcb4f57fad6322497d7a1e28d46710f461a'
              'fe710fbbbc5f8ba166f4311975ec6c00',
          3:
              '10860000867c81838381809 07d89e2d425a178aa81af4a7774ec8e388c115c'
                      'ae67031e85eece520bd911551b9ae4d04369f29a02626c86fbc6747cc7'
                      'bc352645b6161a2a42d44eda80a08fa8d61b76d3a154ad8a5a51786b0b'
                      'c07147057871a922212c5f67f43173172236b7747d1671e6d692a3c7d4'
                      '0a0c3c5ce397545d015c175eb5130551edbc2ee5d400'
                  .replaceAll(' ', ''),
          4: '008600000c7c0a8508b46dd9bd4d98381f00',
        };
        published.forEach((i, wire) {
          expect(
            steps[i]['wire'],
            wire,
            reason: 'step $i must match the App G.2 command listing',
          );
        });
        final responses = <int, String>{
          1: '7c128010854d8df5827fa6852d1a4fa701cdddca',
          2:
              '7c81838281807 8879f57225aa8080d52ed0fc890a4b25336f699aa89a2d3a1'
                      '89654af70729e623ea5738b26381e4da19e004706face7b235c2dbf2f3'
                      '8748312f3c98c2dd4882a41947b324aa1259ac22579db93f7085655af3'
                      '0889dbb845d9e6783fe42c9f2449400306254c8ae8ee9dd812a804c0b6'
                      '6e8cafc14f84d8258950a91b44126ee6'
                  .replaceAll(' ', ''),
          3:
              '7c8183848180075693d9ae941877573e634b6e644f8e60af17a0076b8b123d'
              '9201074d36152bd8b3a213f53820c42adc79ab5d0aeec3aefb91394da476bd'
              '97b9b14d0a65c1fc71a0e019cb08af55e1f729005fba7e3fa5dc41899238a2'
              '50767a6d46db974064386cd456743585f8e5d90cc8b4004b1f6d866c79ce05'
              '84e49687ff61bc29aea1',
          4: '7c0a8608917f37b5c0e6d8d1',
        };
        responses.forEach((i, data) {
          expect(
            (steps[i]['resp']! as Map)['data'],
            data,
            reason: 'step $i must match the App G.2 response listing',
          );
        });
      },
    );
  });

  test('pace_session_im_ecdh_aes128 replays the App H.1 chain', () async {
    await check(
      'pace_session_im_ecdh_aes128',
      'Full PACE ECDH Integrated Mapping AES-128 session over Brainpool P-256, '
          'synthesized from the ICAO 9303 Part 11 App H.1 value chain plus the '
          '§4.4.5.2.2 wire rules (App H publishes values only, no APDUs). The '
          'nonce t and both ephemeral keys are App H.1\'s and injected (t as '
          'imNonce); the mapped generator, both public keys and both '
          'authentication tokens on the wire are the published ones. The DO80 '
          'ciphertext is the sim\'s: App H prints K_pi = 591468CD... with no '
          'MRZ that derives it, so only the decrypted nonce s is reproducible. '
          'GA round 2 carries DO81 = t and the chip answers with an empty DO82, '
          'as the §4.4.5.2.2 note prescribes. runners:["dart"]; upstream stubs '
          'IM out (pace_session_im_partial.json).',
      {
        'secureMessaging': 'pace',
        'cardAccess': '31143012060a04007f0007020204040202010202010d',
        'mrzKey': _mrz,
        'ephemeralKeys': {
          'ephemeralKey':
              'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
          'imNonce': '5dd4cbfc96f5453b130d890a1cdbae32',
        },
      },
      PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.4.2',
        password: PacePassword.mrz(_mrz),
        parameterId: 13,
        nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
        chipMappingPrivateKey: BigInt.one, // unused: IM has no chip mapping key
        chipEphemeralPrivateKey: _b(
          '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
        ),
      ),
      (reader) => PACEHandler(
        cardAccess: CardAccess(
          _h('31143012060a04007f0007020204040202010202010d'),
        ),
        tagReader: reader,
        imNonce: _h('5dd4cbfc96f5453b130d890a1cdbae32'),
        ephemeralPrivateKey: _b(
          'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
        ),
      ),
      assertPublishedWire: (steps) {
        expect(
          steps[2]['wire'],
          contains('81105dd4cbfc96f5453b130d890a1cdbae32'),
        );
        expect((steps[2]['resp']! as Map)['data'], '7c028200');
        expect(
          steps[3]['wire'],
          contains(
            '83410489cba23ffe96aa18d824627c3e934e54a9fd0b87a95d1471'
            'dc1c0abfdcd640d46755de9b7b778280b6bebd57439adfeb0e21fd4ed6df'
            '42578c13418a59b34c37',
          ),
        );
        expect(
          (steps[3]['resp']! as Map)['data'],
          contains(
            '84410467f78e5f7f7686082b293e8d087e056916d0f74bc01a5f89'
            '57d0de45691e51e8932b69a962b52a0985ad2c0a271ee6a13a8adddcd1a3'
            'a994b9ded257f4d22753',
          ),
        );
        expect(steps[4]['wire'], contains('8508450f02b86f6a0909')); // T_IFD
        expect(
          (steps[4]['resp']! as Map)['data'],
          contains('860875d4d96e8d5b0308'),
        ); // T_IC
      },
    );
  });

  test('pace_session_im_dh_aes128 replays the App H.2 chain', () async {
    await check(
      'pace_session_im_dh_aes128',
      'Full PACE DH Integrated Mapping AES-128 session over the RFC 5114 '
          '1024/160 group, synthesized from the ICAO 9303 Part 11 App H.2 value '
          'chain plus the §4.4.5.2.2 wire rules. The nonce t and both ephemeral '
          'keys are App H.2\'s and injected; the mapped generator ĝ, both '
          'public keys and both tokens on the wire are the published ones. As '
          'in the ECDH twin the DO80 ciphertext is the sim\'s (App H\'s K_pi '
          'has no published MRZ). runners:["dart"].',
      {
        'secureMessaging': 'pace',
        'cardAccess': '31143012060a04007f00070202040302020102020100',
        'mrzKey': _mrz,
        'ephemeralKeys': {
          'ephemeralKey':
              '4bd0e54740f9a028e6a515bfdaf967848c4f5f5fff65aa0915947ffd1a0df2fa'
              '6981271bc905f3551457b7e03ac3b8066de4aa406c1171fb43dd939c4ba16175'
              '103ba3dee16419aa248118f90cc36a3d6f4c373652e0c3cce7f0f1d0c5425b36'
              '00f0f0d6a67f004c8bba33f2b4733c7252445c1dfc4f1107203f71d2efb28161',
          'imNonce': 'b3a6db3c870c3e99245e0d1c06b747de',
        },
      },
      PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.3.2',
        password: PacePassword.mrz(_mrz),
        parameterId: 0,
        nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        chipMappingPrivateKey: BigInt.one,
        chipEphemeralPrivateKey: _b(
          '020f018c7284b047fa7721a337efb7acb1440bb30c5252bd41c97c30c994bb78'
          'e9f0c5b32744d84017d21ffa6878396a6469ca283ef5c000daf7d261a39ab886'
          '0ed4610ab5343390897aab5a7787e4faefa0649c6a94fdf82d991e8e3fc332f5'
          '142729e7040a3f7d5a4d3cd75cbee1f043c1cad2dd484feb4ed22b597d36688e',
        ),
      ),
      (reader) => PACEHandler(
        cardAccess: CardAccess(
          _h('31143012060a04007f00070202040302020102020100'),
        ),
        tagReader: reader,
        imNonce: _h('b3a6db3c870c3e99245e0d1c06b747de'),
        ephemeralPrivateKey: _b(
          '4bd0e54740f9a028e6a515bfdaf967848c4f5f5fff65aa0915947ffd1a0df2fa'
          '6981271bc905f3551457b7e03ac3b8066de4aa406c1171fb43dd939c4ba16175'
          '103ba3dee16419aa248118f90cc36a3d6f4c373652e0c3cce7f0f1d0c5425b36'
          '00f0f0d6a67f004c8bba33f2b4733c7252445c1dfc4f1107203f71d2efb28161',
        ),
      ),
      assertPublishedWire: (steps) {
        expect(
          steps[2]['wire'],
          contains('8110b3a6db3c870c3e99245e0d1c06b747de'),
        );
        expect((steps[2]['resp']! as Map)['data'], '7c028200');
        expect(
          steps[3]['wire'],
          contains(
            '8381800f0cc62945a8029251fb7ef3c094e12ec68e4ef07f27cb9d'
            '9cd04c5c4250fae0e4f8a951557e929aeb48e5c6dd47f2f5cd7c351a9bd2'
            'cd722c07ede166770f08ffcb370262cf308dd7b07f2e0da9caaa1492344c'
            '852906919538c98a4ba4187e76ce9d87832386d319ce2e043c3343aeae6e'
            'dba1a9894dc5094d22f7fe1351d5',
          ),
        );
        expect(steps[4]['wire'], contains('850855d61977cbf5307e')); // T_IFD
        expect(
          (steps[4]['resp']! as Map)['data'],
          contains('8608c2f04230187e1525'),
        ); // T_IC
      },
    );
  });
}
