/// End-to-end PACE handshake tests. The port's
/// [PACEHandler] against the [PaceChipSimulator], with both sides' private
/// keys injected from the ICAO 9303 Part 11 worked examples: App G.1
/// (ECDH-GM, Brainpool P-256, AES-128), App G.2 (**DH-GM**, RFC 5114
/// 1024/160, AES-128), App H.1 (**ECDH-IM**, Brainpool P-256, AES-128),
/// App H.2 (**DH-IM**, RFC 5114 1024/160, AES-128) and App I.1 (PACE-CAM).
///
/// Proves each composition (mapping, agreement, mutual token) is internally
/// consistent and byte-exact against the published wire, and covers the
/// divergences from upstream that have no worked example: the padded step-4
/// DH secret (against the committed python oracle), the received-key
/// validation and the P-224 guard.
library;

import 'dart:typed_data';

import 'dart:convert';

import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/kdf.dart';
import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/lds/pace_info.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/pace_chip_sim.dart';

Uint8List _h(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);
String _x(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
BigInt _b(String s) => BigInt.parse(s.replaceAll(' ', ''), radix: 16);

/// EF.CardAccess: SET { PACEInfo(oid, version 2, parameterId) }.
Uint8List _cardAccess(String oidHex, int parameterId) {
  final info = <int>[
    0x06, oidHex.length ~/ 2, ..._h(oidHex), //
    0x02, 0x01, 0x02, //
    0x02, 0x01, parameterId,
  ];
  final seq = <int>[0x30, info.length, ...info];
  return Uint8List.fromList([0x31, seq.length, ...seq]);
}

// OID bodies (the `06` value half), P11 §9.5.
const _oidBodyDhGm128 = '04007f00070202040102';
const _oidBodyEcdhGm128 = '04007f00070202040202';
const _oidBodyDhIm128 = '04007f00070202040302';
const _oidBodyEcdhIm128 = '04007f00070202040402';

// App G.1 EF.CardAccess: SET { PACEInfo(id-PACE-ECDH-GM-AES-CBC-CMAC-128,
// version 2, parameterId 13) }.
final _cardAccessG1 = _cardAccess(_oidBodyEcdhGm128, 13);
// App G.2: id-PACE-DH-GM-AES-CBC-CMAC-128, parameterId 0 (RFC 5114 1024/160).
final _cardAccessG2 = _cardAccess(_oidBodyDhGm128, 0);
// App H.1: id-PACE-ECDH-IM-AES-CBC-CMAC-128, parameterId 13.
final _cardAccessH1 = _cardAccess(_oidBodyEcdhIm128, 13);
// App H.2: id-PACE-DH-IM-AES-CBC-CMAC-128, parameterId 0.
final _cardAccessH2 = _cardAccess(_oidBodyDhIm128, 0);
// App I.1 EF.CardAccess: same shape, CAM OID (...04 06 02).
final _cardAccessI1 = _h(
  '3114301206 0A04007F00 07020204 0602 020102 02010D'.replaceAll(' ', ''),
);

const _mrzG = 'T22000129364081251010318';
const _mrzI = 'C11T002JM496081222310314';

// App G.2 / H.2 group (RFC 5114 §2.1): needed by the received-key reject
// tests.
final _dhP =
    (PACEInfo(
              oid: '0.4.0.127.0.7.2.2.4.1.2',
              version: 2,
              parameterId: 0,
            ).getParameterSpec()
            as DHStandardizedDomain)
        .p;

void main() {
  group('App G.1 ECDH-GM (Brainpool P-256, AES-128)', () {
    late TagReader reader;
    late PaceChipSimulator chip;
    late PACEHandler handler;

    setUp(() {
      chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.2.2',
        password: PacePassword.mrz(_mrzG),
        nonce: _h('3f00c4d39d153f2b2a214a078d899b22'),
        chipMappingPrivateKey: BigInt.parse(
          '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
          radix: 16,
        ),
        chipEphemeralPrivateKey: BigInt.parse(
          '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
          radix: 16,
        ),
      );
      reader = TagReader(chip);
      handler = PACEHandler(
        cardAccess: CardAccess(_cardAccessG1),
        tagReader: reader,
        mappingPrivateKey: BigInt.parse(
          '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
          radix: 16,
        ),
        ephemeralPrivateKey: BigInt.parse(
          'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
          radix: 16,
        ),
      );
    });

    test(
      'doPACE completes and installs an AES SecureMessaging session',
      () async {
        await handler.doPACE(_mrzG);
        expect(reader.secureMessaging, isA<SecureMessaging>());
      },
    );

    test('terminal emits the App G.1 GA command DOs byte-for-byte', () async {
      await handler.doPACE(_mrzG);
      // sentCommands: [0]=MSE:Set AT, [1..4]=GA rounds. Inner 7C payloads.
      expect(_x(chip.sentCommands[1]), contains('7c00')); // step1: empty 7C
      // step2 DO81 = terminal mapping pub (App G.1 T's public key).
      expect(
        _x(chip.sentCommands[2]),
        contains(
          '81410 4 7acf3efc982ec45565a4b155129efbc74650dcbfa6362d896f'
                  'c70262e0c2cc5e544552dcb6725218799115b55c9baa6d9f6bc3a9618e70'
                  'c25af71777a9c4922d'
              .replaceAll(' ', ''),
        ),
      );
      // step3 DO83 = terminal ephemeral pub.
      expect(
        _x(chip.sentCommands[3]),
        contains(
          '83410 4 2db7a64c0355044ec9df190514c625cba2cea48754887122f3'
                  'a5ef0d5edd301c3556f3b3b186df10b857b58f6a7eb80f20ba5dc7be1d43'
                  'd9bf850149fbb36462'
              .replaceAll(' ', ''),
        ),
      );
      // step4 DO85 = terminal token T_IFD.
      expect(_x(chip.sentCommands[4]), contains('8508c2b0bd78d94ba866'));
    });

    test('chip returns the App G.1 GA response DOs byte-for-byte', () async {
      await handler.doPACE(_mrzG);
      // response[1] = DO80 encrypted nonce.
      expect(
        _x(chip.sentResponses[1]),
        contains('801095a3a016522ee98d01e76cb6b98b42c3'),
      );
      // response[2] = DO82 chip mapping pub.
      expect(
        _x(chip.sentResponses[2]),
        contains(
          '8241 04 824fba91c9cbe26bef53a0ebe7342a3bf178cea9f45de0b70a'
                  'a601651fba3f5730d8c879aaa9c9f73991e61b58f4d52eb87a0a0c709a49'
                  'dc63719363ccd13c54'
              .replaceAll(' ', ''),
        ),
      );
      // response[3] = DO84 chip ephemeral pub.
      expect(
        _x(chip.sentResponses[3]),
        contains(
          '8441 04 9e880f842905b8b3181f7af7caa9f0efb743847f44a306d2d2'
                  '8c1d9ec65df6db7764b22277a2eddc3c265a9f018f9cb852e111b768b326'
                  '904b59a0193776f094'
              .replaceAll(' ', ''),
        ),
      );
      // response[4] = DO86 chip token T_IC.
      expect(_x(chip.sentResponses[4]), contains('86083abb9674bce93c08'));
    });

    test('a wrong MRZ key fails the mutual-auth token check', () async {
      // The chip encrypts its nonce under the correct MRZ; a terminal with the
      // wrong MRZ decrypts a different nonce -> different mapped generator ->
      // divergent session keys -> the step-4 tokens never match.
      await expectLater(
        handler.doPACE('X99999999XX00000000000000'),
        throwsA(
          predicate((e) => e is PACEError && e.step == 'Step3 KeyAgreement'),
        ),
      );
    });
  });

  group('App I.1 PACE-CAM (Brainpool P-256, AES-128)', () {
    test(
      'CAM completes as GM and the DO8A is consumed (upstream never reads it)',
      () async {
        final chip = PaceChipSimulator(
          oid: '0.4.0.127.0.7.2.2.4.6.2', // id-PACE-ECDH-CAM-AES-CBC-CMAC-128
          password: PacePassword.mrz(_mrzI),
          nonce: _h('658b860bc94df6f044fce6d5c82cf8e5'),
          chipMappingPrivateKey: BigInt.parse(
            '9e56a6b59c95d06ece5cd10f983bb2f4f1943528e577f23881d89d8c3bbee0aa',
            radix: 16,
          ),
          chipEphemeralPrivateKey: BigInt.parse(
            'cd626ef3c256e235fe8912cac28279e626008eda6b3a05c4cf862a3bdab79e78',
            radix: 16,
          ),
          // I.1's real encrypted chip-authentication data.
          camDataObject: _h(
            '1eea964daae372ac990e3efde6333353bfc89a6704d93da8'
            '798cf77f5b7a54bd10cba372b42be0b9b5f28aa8de2f4f92',
          ),
        );
        final reader = TagReader(chip);
        final handler = PACEHandler(
          cardAccess: CardAccess(_cardAccessI1),
          tagReader: reader,
          mappingPrivateKey: BigInt.parse(
            '5d8bb87bd74d985a4b7d4325b9f7b976fe83512277340079 8914aa22738135cc'
                .replaceAll(' ', ''),
            radix: 16,
          ),
          ephemeralPrivateKey: BigInt.parse(
            '76ecfdaa9841c323a3f5fc5e88b88db3eff7e35ebf57a7e6946cb630006c2120',
            radix: 16,
          ),
        );
        await handler.doPACE(_mrzI);
        expect(reader.secureMessaging, isA<SecureMessaging>());
        // The final chip response carried the DO8A after the DO86 token.
        expect(_x(chip.sentResponses[4]), contains('8596cf055c67c1a3')); // T_IC
        expect(_x(chip.sentResponses[4]), contains('8a30')); // DO8A present
        // The port reads it (upstream does not). App I-11's published values.
        final cam = handler.camData;
        expect(cam, isNotNull);
        expect(cam!.cause, isNull);
        expect(
          _x(cam.chipAuthenticationData!),
          '85dc3fa93d0952bfa82f5fd189ee75bd82f11d1f0b8ed4bf5319ac9b53c426b3',
        );
        expect(
          cam.chipAuthenticationValue,
          _b(
            '85DC3FA93D0952BFA82F5FD189EE75BD82F11D1F0B8ED4BF5319AC9B53C426B3',
          ),
        );
        // PK_Map,IC was retained from the step-2 DO82.
        expect(
          _x(cam.mappingPublicKey),
          '04a234236aa9b9621e8efb73b5245c0e09d2576e5277183c1208bdd55280cae8b3'
          '04f365713a356e65a451e165ecc9ac0ac46e3771342c8fe5aedd092685338e23',
        );
        expect(cam.domain.domainName, 'brainpoolp256r1');
        // And it satisfies the §4.4.3.5.2 equation against App I's PK_IC.
        expect(
          paceCamVerifyChipAuthenticationData(
            domain: cam.domain,
            chipAuthenticationValue: cam.chipAuthenticationValue!,
            chipPublicKey: ecPointDecode(
              cam.domain,
              _h(
                '041872709494399e7470a6431be25e83eee24fea568c2ed28db48e05'
                'db3a610dc884d256a40e35efcb59bf6753d3a489d28c7a4d973c2da'
                '138a6e7a4a08f68e16f',
              ),
            ),
            mappingPublicKey: cam.mappingPublicKey,
          ),
          isTrue,
        );
      },
    );

    /// The same App I.1 chip, but the sim derives the DO8A itself from a
    /// static CA keypair (§4.4.3.5.1) instead of replaying the published
    /// bytes, so extraction, decrypt and verify are exercised as a
    /// round-trip on suites App I does not publish (the vectors, not this,
    /// are what pin the values).
    PaceChipSimulator camChip({
      BigInt? staticPrivateKey,
      List<int>? camDataObject,
      List<int> camPrecedingRecords = const [],
      String oid = '0.4.0.127.0.7.2.2.4.6.2',
    }) => PaceChipSimulator(
      oid: oid,
      password: PacePassword.mrz(_mrzI),
      nonce: _h('658b860bc94df6f044fce6d5c82cf8e5'),
      chipMappingPrivateKey: _b(
        '9e56a6b59c95d06ece5cd10f983bb2f4f1943528e577f23881d89d8c3bbee0aa',
      ),
      chipEphemeralPrivateKey: _b(
        'cd626ef3c256e235fe8912cac28279e626008eda6b3a05c4cf862a3bdab79e78',
      ),
      camStaticPrivateKey: staticPrivateKey,
      camDataObject: camDataObject,
      camPrecedingRecords: camPrecedingRecords,
    );

    PACEHandler camHandler(TagReader reader) => PACEHandler(
      cardAccess: CardAccess(_cardAccessI1),
      tagReader: reader,
      mappingPrivateKey: _b(
        '5d8bb87bd74d985a4b7d4325b9f7b976fe835122773400798914aa22738135cc',
      ),
      ephemeralPrivateKey: _b(
        '76ecfdaa9841c323a3f5fc5e88b88db3eff7e35ebf57a7e6946cb630006c2120',
      ),
    );

    test(
      'a chip-computed DO8A round-trips: camData equals the chip CA_IC',
      () async {
        final chip = camChip(
          staticPrivateKey: _b(
            '0c1d2e3f405162738495a6b7c8d9eafb'
            '0c1d2e3f405162738495a6b7c8d9eafb',
          ),
        );
        final reader = TagReader(chip);
        final handler = camHandler(reader);
        await handler.doPACE(_mrzI);

        final cam = handler.camData!;
        expect(cam.cause, isNull);
        expect(
          cam.chipAuthenticationValue,
          chip.camChipAuthenticationValue,
          reason: 'the terminal must recover exactly the CA_IC the chip sent',
        );
        // §4.4.3.5.2 against the chip's own static public key.
        expect(
          paceCamVerifyChipAuthenticationData(
            domain: cam.domain,
            chipAuthenticationValue: cam.chipAuthenticationValue!,
            chipPublicKey: chip.camStaticPublicKey!,
            mappingPublicKey: cam.mappingPublicKey,
          ),
          isTrue,
        );
      },
    );

    test('a CAM session with no DO8A records cause `missing`', () async {
      final chip = camChip(); // neither a static key nor a literal payload
      final handler = camHandler(TagReader(chip));
      await handler.doPACE(_mrzI);
      expect(_x(chip.sentResponses[4]), isNot(contains('8a')));
      expect(
        handler.camData,
        isNotNull,
        reason: 'PACE still succeeded: the token verified',
      );
      expect(handler.camData!.cause, PaceCamFailure.missing);
      expect(handler.camData!.chipAuthenticationData, isNull);
    });

    test(
      'malformed DO8A payloads record cause `malformed`, never throw',
      () async {
        final shapes = <String, List<int>>{
          'not a block multiple': _h('00112233'),
          'empty': const <int>[],
          // Right length, wrong key: decrypts to garbage with no 0x80 boundary
          // (overwhelmingly likely; asserted below by the recorded cause).
          'undecryptable 48 bytes': List<int>.filled(48, 0xAB),
        };
        for (final entry in shapes.entries) {
          final handler = camHandler(
            TagReader(camChip(camDataObject: entry.value)),
          );
          await handler.doPACE(_mrzI);
          expect(
            handler.camData!.cause,
            PaceCamFailure.malformed,
            reason: 'DO8A shape "${entry.key}" must read as malformed',
          );
          expect(handler.camData!.chipAuthenticationValue, isNull);
        }
      },
    );

    test('a DO8A on a NON-CAM session stays ignored', () async {
      // Same wire, GM OID: the tag-scan is CAM-gated, so camData stays null.
      final chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.2.2', // ECDH-GM, not CAM
        password: PacePassword.mrz(_mrzG),
        nonce: _h('3f00c4d39d153f2b2a214a078d899b22'),
        chipMappingPrivateKey: _b(
          '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
        ),
        chipEphemeralPrivateKey: _b(
          '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
        ),
        camDataObject: _h(
          '1eea964daae372ac990e3efde6333353bfc89a6704d93da8'
          '798cf77f5b7a54bd10cba372b42be0b9b5f28aa8de2f4f92',
        ),
      );
      final reader = TagReader(chip);
      final handler = PACEHandler(
        cardAccess: CardAccess(_cardAccessG1),
        tagReader: reader,
        mappingPrivateKey: _b(
          '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
        ),
        ephemeralPrivateKey: _b(
          'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
        ),
      );
      await handler.doPACE(_mrzG);
      expect(_x(chip.sentResponses[4]), contains('8a30'));
      expect(handler.camData, isNull);
    });

    test(
      'a DO8A preceded by DO87/DO88 CARs is still found (tag-scan)',
      () async {
        // §4.4.5 Table 4 allows the conditional CAR objects between DO86 and
        // DO8A; upstream's commented-out tvlResp[1] index would have missed
        // this one.
        final staticKey = _b(
          '0c1d2e3f405162738495a6b7c8d9eafb'
          '0c1d2e3f405162738495a6b7c8d9eafb',
        );
        // Baseline: the same chip without the CARs, so the two runs are
        // comparable byte for byte apart from the inserted records.
        final plain = camChip(staticPrivateKey: staticKey);
        final baseline = camHandler(TagReader(plain));
        await baseline.doPACE(_mrzI);

        final withCars = camChip(
          staticPrivateKey: staticKey,
          camPrecedingRecords: [
            ...wrapDO(0x87, utf8.encode('DECVCA00001')),
            ...wrapDO(0x88, utf8.encode('DECVCA00002')),
          ],
        );
        final handler = camHandler(TagReader(withCars));
        await handler.doPACE(_mrzI);

        final response = _x(withCars.sentResponses[4]);
        expect(response, contains('870b'), reason: 'DO87 CAR present');
        expect(response, contains('880b'), reason: 'DO88 CAR present');
        expect(
          response.indexOf('8a'),
          greaterThan(response.indexOf('870b')),
          reason: 'the DO8A must no longer be the second record',
        );
        expect(handler.camData!.cause, isNull);
        expect(
          handler.camData!.chipAuthenticationData,
          baseline.camData!.chipAuthenticationData,
        );
      },
    );
  });

  // --- The non-MRZ passwords ----------------------------------------------

  group('CAN / PIN / CUK handshakes (ECDH-GM, Brainpool P-256)', () {
    PaceChipSimulator gmChip(
      PacePassword password, {
      String oid = '0.4.0.127.0.7.2.2.4.2.2',
    }) => PaceChipSimulator(
      oid: oid,
      password: password,
      nonce: _h('3f00c4d39d153f2b2a214a078d899b22'),
      chipMappingPrivateKey: _b(
        '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
      ),
      chipEphemeralPrivateKey: _b(
        '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
      ),
    );

    PACEHandler gmHandler(TagReader reader, Uint8List cardAccess) =>
        PACEHandler(
          cardAccess: CardAccess(cardAccess),
          tagReader: reader,
          mappingPrivateKey: _b(
            '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
          ),
          ephemeralPrivateKey: _b(
            'a73fb703ac1436a18e0cfa5abb3f7bec7a070e7a6788486bee230c4a22762595',
          ),
        );

    for (final entry in <String, (PacePassword, int)>{
      'CAN': (PacePassword.can('123456'), 0x02),
      'PIN': (PacePassword.pin('1234'), 0x03),
      'CUK': (PacePassword.cuk('9876543210'), 0x04),
    }.entries) {
      final (password, reference) = entry.value;
      test('${entry.key} completes and MSE:Set AT selects DO83 = '
          '0x${reference.toRadixString(16).padLeft(2, '0')}', () async {
        final chip = gmChip(password);
        final reader = TagReader(chip);
        final handler = gmHandler(reader, _cardAccessG1);
        await handler.doPACEWithPassword(password);

        expect(reader.secureMessaging, isA<SecureMessaging>());
        expect(handler.paceKeyType, reference);
        expect(
          _x(chip.sentCommands[0]),
          contains('8301${reference.toRadixString(16).padLeft(2, '0')}'),
        );
        expect(
          _x(chip.sentCommands[0]),
          isNot(contains('830101')),
          reason: 'the MRZ reference must not leak onto a non-MRZ session',
        );
      });
    }

    test(
      'a DESede-GM CAN session completes (the DNIe-adjacent shape)',
      () async {
        const desedeOid = '0.4.0.127.0.7.2.2.4.2.1';
        final password = PacePassword.can('500184');
        final chip = gmChip(password, oid: desedeOid);
        final reader = TagReader(chip);
        final handler = gmHandler(
          reader,
          _cardAccess('04007f00070202040201', 13),
        );
        await handler.doPACEWithPassword(password);
        expect(reader.secureMessaging, isA<SecureMessaging>());
        expect(handler.paceKeyType, 0x02);
      },
    );

    test('a wrong CAN fails closed at the step-4 token check', () async {
      final chip = gmChip(PacePassword.can('123456'));
      final handler = gmHandler(TagReader(chip), _cardAccessG1);
      await expectLater(
        handler.doPACEWithPassword(PacePassword.can('654321')),
        throwsA(
          predicate((e) => e is PACEError && e.step == 'Step3 KeyAgreement'),
        ),
      );
    });

    test('CAN and PIN of the same digits share f(pi); only DO83 separates '
        'them', () async {
      // Table 14 / TR Table 5 give CAN and PIN the identical character-string
      // encoding, so the derived K_pi is byte-identical and the *only* thing
      // telling a chip which credential was presented is the DO83 reference.
      // That is exactly why the password type is resolved at the call site
      // and not in the KDF.
      final can = PacePassword.can('123456');
      final pin = PacePassword.pin('123456');
      expect(pin.keySeed, can.keySeed);
      expect(
        paceCreatePaceKey(password: pin, cipherAlgName: 'AES', keyLength: 128),
        paceCreatePaceKey(password: can, cipherAlgName: 'AES', keyLength: 128),
      );

      final chip = gmChip(can);
      final handler = gmHandler(TagReader(chip), _cardAccessG1);
      await handler.doPACEWithPassword(pin);
      expect(
        _x(chip.sentCommands[0]),
        contains('830103'),
        reason:
            'the terminal emits the type it was given, so a chip '
            'expecting a CAN would reject this MSE:Set AT',
      );
    });

    test(
      'doPACE(mrzKey) is exactly doPACEWithPassword(PacePassword.mrz(...))',
      () async {
        final viaLegacy = gmChip(PacePassword.mrz(_mrzG));
        await gmHandler(TagReader(viaLegacy), _cardAccessG1).doPACE(_mrzG);
        final viaPassword = gmChip(PacePassword.mrz(_mrzG));
        await gmHandler(
          TagReader(viaPassword),
          _cardAccessG1,
        ).doPACEWithPassword(PacePassword.mrz(_mrzG));
        expect(
          viaPassword.sentCommands.map(_x).toList(),
          viaLegacy.sentCommands.map(_x).toList(),
          reason: 'the MRZ convenience must not change a single byte',
        );
      },
    );
  });

  // --- DH-GM completes -----------------------------------------------------

  group('App G.2 DH-GM (RFC 5114 1024/160, AES-128)', () {
    // Every scalar below is App G.2's; the mapped generator, ephemeral keys,
    // shared secret, session keys and both tokens are the published values.
    PaceChipSimulator makeChip() => PaceChipSimulator(
      oid: '0.4.0.127.0.7.2.2.4.1.2',
      password: PacePassword.mrz(_mrzG),
      parameterId: 0,
      nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
      chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
      chipEphemeralPrivateKey: _b('A5B780126B7C980E9FCEA1D4539DA1D27C342DFA'),
    );

    PACEHandler makeHandler(TagReader reader) => PACEHandler(
      cardAccess: CardAccess(_cardAccessG2),
      tagReader: reader,
      mappingPrivateKey: _b('5265030F751F4AD18B08AC565FC7AC952E41618D'),
      ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
    );

    test('doPACE completes and installs an AES SecureMessaging session; the '
        'step-3 abort upstream dies on is gone', () async {
      final chip = makeChip();
      final reader = TagReader(chip);
      await makeHandler(reader).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
    });

    test('the chip derives the App G.2 mapped generator ĝ', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      expect(
        _x(bigIntToBytes(chip.mappedDhGenerator!)),
        '7c9cbfe98f9fbdda8d143506fa7d9306f4cb17e3c71707aff5e1c1a123702496'
        '84d64ee37af44b8dbd9d45bf6023919cbaa027ab97acc771666c8e98ff483301'
        'bfa4872dede9034edfacb70814166b7f360676829b826bea57291b5ad69fbc84'
        'ef1e779032a305803f74341793e869742d401325b37ee8565ffcdee618342dc5',
      );
    });

    test('terminal emits the App G.2 GA command DOs byte-for-byte', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      // [0]=MSE:Set AT, [1..4]=GA rounds.
      expect(_x(chip.sentCommands[1]), contains('7c00'));
      // DO81 = terminal mapping public key (128 bytes, BN_bn2bin-stripped).
      expect(
        _x(chip.sentCommands[2]),
        contains(
          '818180'
          '23fb3749ea030d2a25b278d2a562047ade3f01b74f17a15402cb7352ca7d2b3e'
          'b71c343db13d1debce9a3666dbcfc920b49174a602cb47965caa73dc702489a4'
          '4d41db914de9613dc5e98c94160551c0df86274b9359bc0490d01b03ad54022d'
          'cb4f57fad6322497d7a1e28d46710f461afe710fbbbc5f8ba166f4311975ec6c',
        ),
      );
      // DO83 = terminal ephemeral public key over ĝ.
      expect(
        _x(chip.sentCommands[3]),
        contains(
          '838180'
          '907d89e2d425a178aa81af4a7774ec8e388c115cae67031e85eece520bd91155'
          '1b9ae4d04369f29a02626c86fbc6747cc7bc352645b6161a2a42d44eda80a08f'
          'a8d61b76d3a154ad8a5a51786b0bc07147057871a922212c5f67f43173172236'
          'b7747d1671e6d692a3c7d40a0c3c5ce397545d015c175eb5130551edbc2ee5d4',
        ),
      );
      // DO85 = T_IFD.
      expect(_x(chip.sentCommands[4]), contains('8508b46dd9bd4d98381f'));
    });

    test('chip returns the App G.2 GA response DOs byte-for-byte', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      expect(
        _x(chip.sentResponses[1]),
        contains('8010854d8df5827fa6852d1a4fa701cdddca'),
      );
      expect(
        _x(chip.sentResponses[2]),
        contains(
          '828180'
          '78879f57225aa8080d52ed0fc890a4b25336f699aa89a2d3a189654af70729e6'
          '23ea5738b26381e4da19e004706face7b235c2dbf2f38748312f3c98c2dd4882'
          'a41947b324aa1259ac22579db93f7085655af30889dbb845d9e6783fe42c9f24'
          '49400306254c8ae8ee9dd812a804c0b66e8cafc14f84d8258950a91b44126ee6',
        ),
      );
      expect(
        _x(chip.sentResponses[3]),
        contains(
          '848180'
          '075693d9ae941877573e634b6e644f8e60af17a0076b8b123d9201074d36152b'
          'd8b3a213f53820c42adc79ab5d0aeec3aefb91394da476bd97b9b14d0a65c1fc'
          '71a0e019cb08af55e1f729005fba7e3fa5dc41899238a250767a6d46db974064'
          '386cd456743585f8e5d90cc8b4004b1f6d866c79ce0584e49687ff61bc29aea1',
        ),
      );
      // DO86 = T_IC; the port verified it, so reaching here proves the match.
      expect(_x(chip.sentResponses[4]), contains('8608917f37b5c0e6d8d1'));
    });

    test('a wrong MRZ key fails the mutual-auth token check', () async {
      final handler = makeHandler(TagReader(makeChip()));
      await expectLater(
        handler.doPACE('X99999999XX00000000000000'),
        throwsA(
          predicate((e) => e is PACEError && e.step == 'Step3 KeyAgreement'),
        ),
      );
    });
  });

  group('DH-GM suite/group coverage', () {
    for (final (oid, label) in const [
      ('0.4.0.127.0.7.2.2.4.1.1', 'DH-GM-3DES-CBC-CBC'),
      ('0.4.0.127.0.7.2.2.4.1.2', 'DH-GM-AES-CBC-CMAC-128'),
      ('0.4.0.127.0.7.2.2.4.1.3', 'DH-GM-AES-CBC-CMAC-192'),
      ('0.4.0.127.0.7.2.2.4.1.4', 'DH-GM-AES-CBC-CMAC-256'),
    ]) {
      test('$label completes on the 1024/160 group', () async {
        // 3DES needs an 8-byte nonce (its own block size); AES a 16-byte one.
        final isDes = oid.endsWith('.1.1');
        final chip = PaceChipSimulator(
          oid: oid,
          password: PacePassword.mrz(_mrzG),
          parameterId: 0,
          nonce: _h(
            isDes ? 'fa5b7e3e49753a0d' : 'fa5b7e3e49753a0db9178b7b9bd898c8',
          ),
          chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
          chipEphemeralPrivateKey: _b(
            'A5B780126B7C980E9FCEA1D4539DA1D27C342DFA',
          ),
        );
        final reader = TagReader(chip);
        await PACEHandler(
          cardAccess: CardAccess(
            _cardAccess(
              _oidBodyDhGm128.substring(0, 18) +
                  oid.split('.').last.padLeft(2, '0'),
              0,
            ),
          ),
          tagReader: reader,
          mappingPrivateKey: _b('5265030F751F4AD18B08AC565FC7AC952E41618D'),
          ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
        ).doPACE(_mrzG);
        expect(reader.secureMessaging, isA<SecureMessaging>());
      });
    }

    for (final groupId in const [0, 1, 2]) {
      test('AES-128 completes on RFC 5114 group $groupId', () async {
        // The 2048-bit groups put a 256-byte public key in the GA data field,
        // which overflows a short-form Lc; such a chip must advertise
        // extended-length APDUs, so the sim does.
        final extended = groupId != 0;
        final chip = PaceChipSimulator(
          oid: '0.4.0.127.0.7.2.2.4.1.2',
          password: PacePassword.mrz(_mrzG),
          parameterId: groupId,
          nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
          chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
          chipEphemeralPrivateKey: _b(
            'A5B780126B7C980E9FCEA1D4539DA1D27C342DFA',
          ),
          maxTransceiveLength: extended ? 4096 : 261,
          isExtendedLengthApduSupported: extended,
        );
        final reader = TagReader(chip);
        await PACEHandler(
          cardAccess: CardAccess(_cardAccess(_oidBodyDhGm128, groupId)),
          tagReader: reader,
          mappingPrivateKey: _b('5265030F751F4AD18B08AC565FC7AC952E41618D'),
          ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
        ).doPACE(_mrzG);
        expect(reader.secureMessaging, isA<SecureMessaging>());
      });
    }

    test('the live path samples both DH scalars off the RNG seam', () async {
      final chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.1.2',
        password: PacePassword.mrz(_mrzG),
        parameterId: 0,
        nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
        chipEphemeralPrivateKey: _b('A5B780126B7C980E9FCEA1D4539DA1D27C342DFA'),
      );
      final reader = TagReader(chip);
      await PACEHandler(
        cardAccess: CardAccess(_cardAccess(_oidBodyDhGm128, 0)),
        tagReader: reader,
        random: SystemRandom(),
      ).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
    });
  });

  group('the step-4 DH secret is left-padded to the group length', () {
    // The one session shape where the left-padding and upstream's zero
    // relocation disagree: ephemeral scalars 2 (terminal) and 0x26 (chip)
    // over App G.2's mapped generator yield a shared secret with one leading
    // zero byte. Expectations below come from
    // conformance/tools/pace_mapping_oracle.py (`leading-zero`), never from
    // this code.
    const chipEphemeralPub =
        '26d6342c7e482eaae62fd0674f26eda5db4c6d4bdb2860a86feaa7466b8ed147'
        '6bb268d78230bc468d1413952742c78fa3e2dc751ff1d1eb70ed5d8679a02670'
        'f3b40937ff2e29e500821da0f6f77b5f0d692c18364ba1f70e4190870f3c6409'
        '3245e37a47a37fa7446ab215049a762aa5570ac85262c483608e65d9a296f0bd';
    const paddedSecret =
        '007a4635bee91875016b6b167866954ae2c9de8e41b45a75bda682c294e83e27'
        'f77f251c6c77d84833124ebf76bff3b84f9f58ad07e8e600c6c5f751d56922f2'
        'bb97c6fe7c5fe126146c8fc927b8b71d217af8c9b7801a2f35bc9f0f1ab10d3e'
        '5d310ece2fcd3b0ed68c753fbff763c02788920ba6563868029229a0d2a15597';

    test('paceDhSharedSecretBytes keeps the leading zero (not upstream\'s '
        'trailing one)', () {
      final secret = paceDhSharedSecretBytes(
        p: _dhP,
        x: BigInt.two,
        peerPublic: _b(chipEphemeralPub),
      );
      expect(_x(secret), paddedSecret);
      expect(secret.length, 128);
      // Upstream's shape for the same value, for contrast.
      final relocated = '${_x(bigIntToBytes(_b(paddedSecret)))}00';
      expect(_x(secret), isNot(relocated));
    });

    test('the derived session keys match the python oracle', () {
      const gen = SecureMessagingSessionKeyGenerator();
      final seed = paceDhSharedSecretBytes(
        p: _dhP,
        x: BigInt.two,
        peerPublic: _b(chipEphemeralPub),
      );
      expect(
        _x(
          gen.deriveKey(
            keySeed: seed,
            cipherAlgName: 'AES',
            keyLength: 128,
            mode: SMSMode.encMode,
          ),
        ),
        '945d4d9e02b7835b649ef313011f9395',
      );
      expect(
        _x(
          gen.deriveKey(
            keySeed: seed,
            cipherAlgName: 'AES',
            keyLength: 128,
            mode: SMSMode.macMode,
          ),
        ),
        '776c4691233481d311fc2956fd22d2da',
      );
    });

    test('the leading-zero session completes end-to-end', () async {
      final chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.1.2',
        password: PacePassword.mrz(_mrzG),
        parameterId: 0,
        nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
        chipEphemeralPrivateKey: BigInt.from(0x26),
      );
      final reader = TagReader(chip);
      await PACEHandler(
        cardAccess: CardAccess(_cardAccessG2),
        tagReader: reader,
        mappingPrivateKey: _b('5265030F751F4AD18B08AC565FC7AC952E41618D'),
        ephemeralPrivateKey: BigInt.two,
      ).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
      // The chip's DO84 is exactly the oracle's chip ephemeral public key.
      expect(_x(chip.sentResponses[3]), contains(chipEphemeralPub));
    });
  });

  group('received DH public keys are validated', () {
    Future<void> run({int? tamperTag, String? value}) async {
      final chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.1.2',
        password: PacePassword.mrz(_mrzG),
        parameterId: 0,
        nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        chipMappingPrivateKey: _b('66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'),
        chipEphemeralPrivateKey: _b('A5B780126B7C980E9FCEA1D4539DA1D27C342DFA'),
      );
      final reader = TagReader(
        _RetagDO(chip, tag: tamperTag!, replacement: _h(value!)),
      );
      await PACEHandler(
        cardAccess: CardAccess(_cardAccessG2),
        tagReader: reader,
        mappingPrivateKey: _b('5265030F751F4AD18B08AC565FC7AC952E41618D'),
        ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
      ).doPACE(_mrzG);
    }

    test('DO82 out of range [2, p-2] -> PACEError(Step2GM)', () async {
      await expectLater(
        run(tamperTag: 0x82, value: '01'),
        throwsA(predicate((e) => e is PACEError && e.step == 'Step2GM')),
      );
    });

    test('DO82 outside the q-subgroup -> PACEError(Step2GM)', () async {
      // y = 3 passes the range test but 3^q mod p != 1 (RFC 5114 §2.1).
      await expectLater(
        run(tamperTag: 0x82, value: '03'),
        throwsA(predicate((e) => e is PACEError && e.step == 'Step2GM')),
      );
    });

    test('DO84 outside the q-subgroup -> PACEError(Step3 KeyEx), the same '
        'message the EC decode failure uses', () async {
      await expectLater(
        run(tamperTag: 0x84, value: '03'),
        throwsA(
          predicate(
            (e) =>
                e is PACEError &&
                e.step == 'Step3 KeyEx' &&
                e.reason == 'Unable to decode passports ephemeral key',
          ),
        ),
      );
    });

    test('paceValidateDhPublicKey accepts a genuine subgroup member', () {
      final q =
          (PACEInfo(
                    oid: '0.4.0.127.0.7.2.2.4.1.2',
                    version: 2,
                    parameterId: 0,
                  ).getParameterSpec()
                  as DHStandardizedDomain)
              .q;
      expect(
        paceValidateDhPublicKey(
          p: _dhP,
          q: q,
          y: _b(
            '78879f57225aa8080d52ed0fc890a4b25336f699aa89a2d3a18965'
            '4af70729e623ea5738b26381e4da19e004706face7b235c2dbf2f38748'
            '312f3c98c2dd4882a41947b324aa1259ac22579db93f7085655af30889'
            'dbb845d9e6783fe42c9f2449400306254c8ae8ee9dd812a804c0b66e8c'
            'afc14f84d8258950a91b44126ee6',
          ),
        ),
        isTrue,
      );
      expect(paceValidateDhPublicKey(p: _dhP, q: q, y: BigInt.one), isFalse);
      expect(
        paceValidateDhPublicKey(p: _dhP, q: q, y: _dhP - BigInt.one),
        isFalse,
      );
    });
  });

  // --- Integrated Mapping ---------------------------------------------------

  group('App H.1 ECDH-IM (Brainpool P-256, AES-128)', () {
    PaceChipSimulator makeChip({
      ImMappingResponseShape shape = ImMappingResponseShape.emptyDo82,
    }) => PaceChipSimulator(
      oid: '0.4.0.127.0.7.2.2.4.4.2',
      password: PacePassword.mrz(_mrzG),
      parameterId: 13,
      imResponseShape: shape,
      nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
      // IM needs no chip mapping key at all: the mapping is a pure
      // function of (s, t).
      chipMappingPrivateKey: BigInt.one,
      chipEphemeralPrivateKey: _b(
        '107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A',
      ),
    );

    PACEHandler makeHandler(TagReader reader) => PACEHandler(
      cardAccess: CardAccess(_cardAccessH1),
      tagReader: reader,
      imNonce: _h('5dd4cbfc96f5453b130d890a1cdbae32'),
      ephemeralPrivateKey: _b(
        'A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595',
      ),
    );

    test(
      'doPACE completes; upstream\'s "IM not yet implemented" is gone',
      () async {
        final reader = TagReader(makeChip());
        await makeHandler(reader).doPACE(_mrzG);
        expect(reader.secureMessaging, isA<SecureMessaging>());
      },
    );

    test('the mapped generator Ĝ is App H.1\'s', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      expect(
        _x(ecPointEncode(chip.mappedEcGenerator!)),
        '04'
        '8e82d31559ed0fde92a4d0498add3c23baba94fb77691e31e90aea77fb17d427'
        '4c1ae14bd0c3dbac0c871b7f3608169364437ca30ac243a089d3f266c1e60fad',
      );
    });

    test('the wire carries the App H.1 values (t, both ephemeral keys, both '
        'tokens)', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      // App H publishes K_π = 591468CD... but no MRZ that derives it (App G's
      // MRZ gives 89DED1B2...), so its DO80 ciphertext is not reproducible and
      // is not asserted: the fixtures reuse App G's MRZ and the sim's own z.
      // Everything from the *decrypted* nonce s onward is App H.1's.
      // GA2 command DO81 = t, response DO82 empty (§4.4.5.2.2).
      expect(
        _x(chip.sentCommands[2]),
        contains('81105dd4cbfc96f5453b130d890a1cdbae32'),
      );
      expect(_x(chip.sentResponses[2]), '7c0282009000');
      // GA3 DO83/DO84 = the published PK_IFD / PK_IC over Ĝ.
      expect(
        _x(chip.sentCommands[3]),
        contains(
          '834104'
          '89cba23ffe96aa18d824627c3e934e54a9fd0b87a95d1471dc1c0abfdcd640d4'
          '6755de9b7b778280b6bebd57439adfeb0e21fd4ed6df42578c13418a59b34c37',
        ),
      );
      expect(
        _x(chip.sentResponses[3]),
        contains(
          '844104'
          '67f78e5f7f7686082b293e8d087e056916d0f74bc01a5f8957d0de45691e51e8'
          '932b69a962b52a0985ad2c0a271ee6a13a8adddcd1a3a994b9ded257f4d22753',
        ),
      );
      // GA4 DO85/DO86 = T_IFD / T_IC.
      expect(_x(chip.sentCommands[4]), contains('8508450f02b86f6a0909'));
      expect(_x(chip.sentResponses[4]), contains('860875d4d96e8d5b0308'));
    });

    test('an empty 7C mapping response is tolerated too', () async {
      final reader = TagReader(
        makeChip(shape: ImMappingResponseShape.emptyDynamicAuthObject),
      );
      await makeHandler(reader).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
    });
  });

  group('App H.2 DH-IM (RFC 5114 1024/160, AES-128)', () {
    PaceChipSimulator makeChip() => PaceChipSimulator(
      oid: '0.4.0.127.0.7.2.2.4.3.2',
      password: PacePassword.mrz(_mrzG),
      parameterId: 0,
      nonce: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
      chipMappingPrivateKey: BigInt.one,
      chipEphemeralPrivateKey: _b(
        '020F018C7284B047FA7721A337EFB7ACB1440BB30C5252BD41C97C30C994BB78'
        'E9F0C5B32744D84017D21FFA6878396A6469CA283EF5C000DAF7D261A39AB886'
        '0ED4610AB5343390897AAB5A7787E4FAEFA0649C6A94FDF82D991E8E3FC332F5'
        '142729E7040A3F7D5A4D3CD75CBEE1F043C1CAD2DD484FEB4ED22B597D36688E',
      ),
    );

    PACEHandler makeHandler(TagReader reader) => PACEHandler(
      cardAccess: CardAccess(_cardAccessH2),
      tagReader: reader,
      imNonce: _h('b3a6db3c870c3e99245e0d1c06b747de'),
      ephemeralPrivateKey: _b(
        '4BD0E54740F9A028E6A515BFDAF967848C4F5F5FFF65AA0915947FFD1A0DF2FA'
        '6981271BC905F3551457B7E03AC3B8066DE4AA406C1171FB43DD939C4BA16175'
        '103BA3DEE16419AA248118F90CC36A3D6F4C373652E0C3CCE7F0F1D0C5425B36'
        '00F0F0D6A67F004C8BBA33F2B4733C7252445C1DFC4F1107203F71D2EFB28161',
      ),
    );

    test('doPACE completes and the mapped generator ĝ is App H.2\'s', () async {
      final chip = makeChip();
      final reader = TagReader(chip);
      await makeHandler(reader).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
      expect(
        _x(bigIntToBytes(chip.mappedDhGenerator!)),
        '1d7d767f11e333bcd6dbaef40e799e7a926b96973550656ff3c830726d118d61'
        'c276cdcc61d475cf03a98e0c0e79caeba5be25578bd4551d0b10903236f0b0f9'
        '76852fa78eea14ea0aca87d1e91f688fe0dff897bbe35a472621d343564b262f'
        '34223ae8fc59b664bfedfa2bfe7516ca5510a6bbb633d517ec25d4e0bbaa16c2',
      );
    });

    test('the wire carries the App H.2 values', () async {
      final chip = makeChip();
      await makeHandler(TagReader(chip)).doPACE(_mrzG);
      // As in H.1, the DO80 ciphertext is not asserted (App H's K_π has no
      // published MRZ); s and everything downstream are App H.2's.
      expect(
        _x(chip.sentCommands[2]),
        contains('8110b3a6db3c870c3e99245e0d1c06b747de'),
      );
      expect(
        _x(chip.sentCommands[3]),
        contains(
          '838180'
          '0f0cc62945a8029251fb7ef3c094e12ec68e4ef07f27cb9d9cd04c5c4250fae0'
          'e4f8a951557e929aeb48e5c6dd47f2f5cd7c351a9bd2cd722c07ede166770f08'
          'ffcb370262cf308dd7b07f2e0da9caaa1492344c852906919538c98a4ba4187e'
          '76ce9d87832386d319ce2e043c3343aeae6edba1a9894dc5094d22f7fe1351d5',
        ),
      );
      expect(
        _x(chip.sentResponses[3]),
        contains(
          '848180'
          '928d9a0f9dba450f13fc859c6f290d1d36e42431138a4378500beb4e0401854c'
          'ff111f71cb6dc1d0335807a11388cc8eaa87b07907aad9fba6b169af6d8c26af'
          '8dddc39adc3ad2e3ff882b84d23e9768e95a80e4746fb07a9767679fe92133b4'
          'd379935c771bd7fbed6c7bb4b1708b275ea75679524cdc9c6a91370cc662a2f3',
        ),
      );
      expect(_x(chip.sentCommands[4]), contains('850855d61977cbf5307e'));
      expect(_x(chip.sentResponses[4]), contains('8608c2f04230187e1525'));
    });
  });

  group('IM suite coverage: all 8 OIDs', () {
    // 3DES and AES-192/256 have no published chain anywhere; these
    // round-trips prove the composition, the python-oracle rows in
    // conformance/vectors/pace_im.json prove the values.
    for (final (oid, label, isDh, klen, cipher) in const [
      ('0.4.0.127.0.7.2.2.4.3.1', 'DH-IM-3DES-CBC-CBC', true, 128, 'DESede'),
      ('0.4.0.127.0.7.2.2.4.3.2', 'DH-IM-AES-CBC-CMAC-128', true, 128, 'AES'),
      ('0.4.0.127.0.7.2.2.4.3.3', 'DH-IM-AES-CBC-CMAC-192', true, 192, 'AES'),
      ('0.4.0.127.0.7.2.2.4.3.4', 'DH-IM-AES-CBC-CMAC-256', true, 256, 'AES'),
      ('0.4.0.127.0.7.2.2.4.4.1', 'ECDH-IM-3DES-CBC-CBC', false, 128, 'DESede'),
      (
        '0.4.0.127.0.7.2.2.4.4.2',
        'ECDH-IM-AES-CBC-CMAC-128',
        false,
        128,
        'AES',
      ),
      (
        '0.4.0.127.0.7.2.2.4.4.3',
        'ECDH-IM-AES-CBC-CMAC-192',
        false,
        192,
        'AES',
      ),
      (
        '0.4.0.127.0.7.2.2.4.4.4',
        'ECDH-IM-AES-CBC-CMAC-256',
        false,
        256,
        'AES',
      ),
    ]) {
      test('$label completes', () async {
        // s is l bits wide: 128 for 3DES/AES-128, 256 for AES-192/256.
        final lBytes = (cipher == 'AES' && klen > 128) ? 32 : 16;
        final tBytes = cipher == 'DESede' ? 16 : klen ~/ 8;
        final oidBody =
            _oidBodyDhIm128.substring(0, 16) +
            (isDh ? '03' : '04') +
            oid.split('.').last.padLeft(2, '0');
        final parameterId = isDh ? 0 : 13;
        final chip = PaceChipSimulator(
          oid: oid,
          password: PacePassword.mrz(_mrzG),
          parameterId: parameterId,
          nonce: Uint8List.fromList(List.generate(lBytes, (i) => i * 7 + 1)),
          chipMappingPrivateKey: BigInt.one,
          chipEphemeralPrivateKey: _b(
            'A5B780126B7C980E9FCEA1D4539DA1D27C342DFA',
          ),
        );
        final reader = TagReader(chip);
        await PACEHandler(
          cardAccess: CardAccess(_cardAccess(oidBody, parameterId)),
          tagReader: reader,
          imNonce: Uint8List.fromList(List.generate(tBytes, (i) => 0xA0 ^ i)),
          ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
        ).doPACE(_mrzG);
        expect(reader.secureMessaging, isA<SecureMessaging>());
      });
    }

    for (final (paramId, curve) in const [
      (8, 'secp192r1'),
      (12, 'secp256r1'),
      (13, 'brainpoolp256r1'),
      (17, 'brainpoolp512r1'),
      (18, 'secp521r1'),
    ]) {
      test(
        'ECDH-IM AES-128 completes on $curve (parameterId $paramId)',
        () async {
          final chip = PaceChipSimulator(
            oid: '0.4.0.127.0.7.2.2.4.4.2',
            password: PacePassword.mrz(_mrzG),
            parameterId: paramId,
            nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
            chipMappingPrivateKey: BigInt.one,
            chipEphemeralPrivateKey: _b(
              'A5B780126B7C980E9FCEA1D4539DA1D27C342DFA',
            ),
          );
          final reader = TagReader(chip);
          await PACEHandler(
            cardAccess: CardAccess(_cardAccess(_oidBodyEcdhIm128, paramId)),
            tagReader: reader,
            imNonce: _h('5dd4cbfc96f5453b130d890a1cdbae32'),
            ephemeralPrivateKey: _b('89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'),
          ).doPACE(_mrzG);
          expect(reader.secureMessaging, isA<SecureMessaging>());
        },
      );
    }
  });

  group('IM guards', () {
    PACEHandler imHandler({
      required int parameterId,
      Uint8List? imNonce,
      String oidBody = _oidBodyEcdhIm128,
    }) => PACEHandler(
      cardAccess: CardAccess(_cardAccess(oidBody, parameterId)),
      tagReader: TagReader(
        PaceChipSimulator(
          oid: oidBody == _oidBodyEcdhIm128
              ? '0.4.0.127.0.7.2.2.4.4.2'
              : '0.4.0.127.0.7.2.2.4.3.2',
          password: PacePassword.mrz(_mrzG),
          parameterId: parameterId,
          nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
          chipMappingPrivateKey: BigInt.one,
          chipEphemeralPrivateKey: BigInt.from(7),
        ),
      ),
      imNonce: imNonce ?? _h('5dd4cbfc96f5453b130d890a1cdbae32'),
    );

    test('parameterId 10 (NIST P-224) is rejected: p != 3 mod 4', () async {
      await expectLater(
        imHandler(parameterId: 10).doPACE(_mrzG),
        throwsA(
          predicate(
            (e) =>
                e is PACEError &&
                e.step == 'Step2IM' &&
                e.reason.contains('p = 3 mod 4'),
          ),
        ),
      );
    });

    test(
      'the P-224 guard fires before the nonce-t round reaches the chip',
      () async {
        final chip = PaceChipSimulator(
          oid: '0.4.0.127.0.7.2.2.4.4.2',
          password: PacePassword.mrz(_mrzG),
          parameterId: 10,
          nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
          chipMappingPrivateKey: BigInt.one,
          chipEphemeralPrivateKey: BigInt.from(7),
        );
        await expectLater(
          PACEHandler(
            cardAccess: CardAccess(_cardAccess(_oidBodyEcdhIm128, 10)),
            tagReader: TagReader(chip),
            imNonce: _h('5dd4cbfc96f5453b130d890a1cdbae32'),
          ).doPACE(_mrzG),
          throwsA(isA<PACEError>()),
        );
        // MSE:Set AT + GA1 only; GA2 never went out.
        expect(chip.sentCommands.length, 2);
      },
    );

    test('an injected nonce t of the wrong length is rejected', () async {
      await expectLater(
        imHandler(
          parameterId: 13,
          imNonce: _h('0011223344556677'),
        ).doPACE(_mrzG),
        throwsA(
          predicate(
            (e) =>
                e is PACEError &&
                e.step == 'Step2IM' &&
                e.reason.contains('expected 16'),
          ),
        ),
      );
    });

    test('the live path samples t off the RNG seam', () async {
      final chip = PaceChipSimulator(
        oid: '0.4.0.127.0.7.2.2.4.4.2',
        password: PacePassword.mrz(_mrzG),
        parameterId: 13,
        nonce: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
        chipMappingPrivateKey: BigInt.one,
        chipEphemeralPrivateKey: _b('A5B780126B7C980E9FCEA1D4539DA1D27C342DFA'),
      );
      final reader = TagReader(chip);
      await PACEHandler(
        cardAccess: CardAccess(_cardAccess(_oidBodyEcdhIm128, 13)),
        tagReader: reader,
        random: FixedRandom(List.generate(48, (i) => 0x5A ^ i)),
      ).doPACE(_mrzG);
      expect(reader.secureMessaging, isA<SecureMessaging>());
      // t came off the seam: DO81 carries the first 16 seam bytes.
      expect(
        _x(chip.sentCommands[2]),
        contains('8110${_x(List.generate(16, (i) => 0x5A ^ i))}'),
      );
    });
  });
}

/// Rewrites the value of a chosen context-specific DO in the chip's response,
/// the received-key tamper harness. Only the outermost `7C` payload is
/// touched, and only the first record carrying [tag].
class _RetagDO implements NfcTransceiver {
  _RetagDO(this._inner, {required this.tag, required this.replacement});

  final NfcTransceiver _inner;
  final int tag;
  final Uint8List replacement;

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
    // Find `tag` followed by a (short or 81-form) length inside the response.
    for (var i = 0; i + 1 < resp.length - 2; i++) {
      if (resp[i] != tag) {
        continue;
      }
      final int len, header;
      if (resp[i + 1] == 0x81 && i + 2 < resp.length) {
        len = resp[i + 2];
        header = 3;
      } else if (resp[i + 1] < 0x80) {
        len = resp[i + 1];
        header = 2;
      } else {
        continue;
      }
      if (i + header + len + 2 != resp.length) {
        continue; // not the DO that runs to the end of the 7C payload
      }
      final rebuilt = <int>[
        ...resp.sublist(0, i),
        tag,
        replacement.length,
        ...replacement,
        ...resp.sublist(resp.length - 2),
      ];
      // Fix the enclosing 7C length (always the 81-form in these fixtures).
      if (rebuilt.length >= 3 && rebuilt[0] == 0x7c) {
        final inner = rebuilt.length - 2 - (rebuilt[1] == 0x81 ? 3 : 2);
        return Uint8List.fromList([
          0x7c,
          inner,
          ...rebuilt.sublist(rebuilt[1] == 0x81 ? 3 : 2),
        ]);
      }
      return Uint8List.fromList(rebuilt);
    }
    return resp;
  }
}
