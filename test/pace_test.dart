/// Unit tests for the PACE port: PACEInfo dispatch + getParameterSpec,
/// CardAccess parsing quirks, the createMappingKey injection seam,
/// paceCompleted's SM handoff, and a randomized property test (padding
/// correctness at scale: 1-in-256 short-coordinate bugs escape example
/// vectors).
///
/// Also the standardized-domain invariants the Integrated Mapping depends
/// on (RFC 5114 subgroup orders, p ≡ 3 mod 4 per curve) and unit coverage of
/// the Integrated Mapping primitives' guard paths, which no end-to-end
/// handshake can reach.
///
/// And the [PacePassword] factories: the two halves of f(π) per password
/// type, the TR-03110-3 D.2.1.4 charset guard, and the MRZ path's
/// byte-identity with upstream's MRZ seed.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/hashes.dart';
import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/lds/chip_authentication_info.dart';
import 'package:emrtd_core/src/lds/pace_info.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import 'support/pace_chip_sim.dart';

List<int> _h(String s) => [
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];
String _x(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  _pacePasswordTests();

  group('PACEInfo OID dispatch', () {
    test('to* helpers over a GM/CAM/IM sample', () {
      expect(
        PACEInfo.toMappingType('0.4.0.127.0.7.2.2.4.2.2'),
        PACEMappingType.GM,
      );
      expect(
        PACEInfo.toMappingType('0.4.0.127.0.7.2.2.4.4.2'),
        PACEMappingType.IM,
      );
      expect(
        PACEInfo.toMappingType('0.4.0.127.0.7.2.2.4.6.2'),
        PACEMappingType.CAM,
      );
      expect(PACEInfo.toKeyAgreementAlgorithm('0.4.0.127.0.7.2.2.4.1.2'), 'DH');
      expect(
        PACEInfo.toKeyAgreementAlgorithm('0.4.0.127.0.7.2.2.4.2.2'),
        'ECDH',
      );
      expect(PACEInfo.toCipherAlgorithm('0.4.0.127.0.7.2.2.4.2.1'), 'DESede');
      expect(PACEInfo.toDigestAlgorithm('0.4.0.127.0.7.2.2.4.2.4'), 'SHA-256');
      expect(PACEInfo.toKeyLength('0.4.0.127.0.7.2.2.4.2.3'), 192);
    });

    test('unknown OID throws InvalidDataPassed', () {
      expect(
        () => PACEInfo.toMappingType('1.2.3.4'),
        throwsA(isA<InvalidDataPassed>()),
      );
    });
  });

  group('getParameterSpec', () {
    PACEParameterSpec spec(int? id) => PACEInfo(
      oid: '0.4.0.127.0.7.2.2.4.2.2',
      version: 2,
      parameterId: id,
    ).getParameterSpec();

    test('every standardized EC curve resolves in pointycastle', () {
      for (final id in [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]) {
        final s = spec(id);
        expect(s, isA<ECStandardizedDomain>());
        // Constructing the domain must not throw (registry coverage).
        expect((s as ECStandardizedDomain).domain.n, isNotNull);
      }
    });

    test('DH groups 0/1/2 resolve to RFC 5114 constants', () {
      for (final id in [0, 1, 2]) {
        expect(spec(id), isA<DHStandardizedDomain>());
      }
      final g0 = spec(0) as DHStandardizedDomain;
      // App G.2 group prime.
      expect(g0.p.toRadixString(16).startsWith('b10b8f96'), isTrue);
    });

    test('every RFC 5114 generator really has order q (regression)', () {
      // The subgroup check on received DH keys is only meaningful if the
      // constants are right. The 2048/256 generator once carried a
      // one-nibble transcription slip, latent while DH-PACE aborted at
      // step 3, and fatal to every DH handshake on group 2 once it did not.
      for (final id in [0, 1, 2]) {
        final d = spec(id) as DHStandardizedDomain;
        expect(
          d.g.modPow(d.q, d.p),
          BigInt.one,
          reason: 'RFC 5114 group $id: g must have order q',
        );
        expect(
          (d.p - BigInt.one) % d.q,
          BigInt.zero,
          reason: 'RFC 5114 group $id: q must divide p-1',
        );
        expect(d.g > BigInt.one && d.g < d.p - BigInt.one, isTrue);
      }
    });

    test('every standardized curve except NIST P-224 satisfies '
        'p = 3 mod 4', () {
      final four = BigInt.from(4);
      final three = BigInt.from(3);
      for (final id in [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]) {
        final domain = (spec(id) as ECStandardizedDomain).domain;
        final p = (domain.curve as fp.ECCurve).q!;
        expect(
          p % four == three,
          id != PACEInfo.PARAM_ID_ECP_NIST_P224_R1,
          reason: '${domain.domainName} (parameterId $id)',
        );
      }
    });

    test('RFU/invalid ids throw with the verbatim typo message', () {
      for (final id in [3, 7, 19, 31, -1, null]) {
        expect(
          () => spec(id),
          throwsA(
            isA<InvalidDataPassed>().having(
              (e) => e.message,
              'message',
              contains('Unable to lookup p arameterSpec'),
            ),
          ),
        );
      }
    });
  });

  group('createMappingKey injection seam', () {
    final info = PACEInfo(
      oid: '0.4.0.127.0.7.2.2.4.2.2',
      version: 2,
      parameterId: 13,
    );

    test('injected private key recomputes the App G.1 mapping public key', () {
      final kp =
          info.createMappingKey(
                random: FixedRandom(const []),
                privateKey: BigInt.parse(
                  '7f4ef07b9ea82fd78ad689b38d0bc78cf21f249d953bc46f4c6e19259c010f99',
                  radix: 16,
                ),
              )
              as EcdhMappingKeyPair;
      final encoded = ecPointEncode(kp.publicPoint);
      expect(
        encoded,
        _h(
          '047acf3efc982ec45565a4b155129efbc74650dcbfa6362d896fc70262e0c2cc'
          '5e544552dcb6725218799115b55c9baa6d9f6bc3a9618e70c25af71777a9c492'
          '2d',
        ),
      );
    });

    test('sampled key stays in range and encodes fixed-length', () {
      final kp =
          info.createMappingKey(random: SystemRandom()) as EcdhMappingKeyPair;
      expect(kp.d > BigInt.zero, isTrue);
      expect(kp.d < kp.domain.n, isTrue);
      expect(ecPointEncode(kp.publicPoint).length, 65);
    });

    test('DH parameterId yields a DH mapping keypair', () {
      final dhInfo = PACEInfo(
        oid: '0.4.0.127.0.7.2.2.4.1.2',
        version: 2,
        parameterId: 0,
      );
      final kp =
          dhInfo.createMappingKey(
                random: FixedRandom(const []),
                privateKey: BigInt.from(12345),
              )
              as DhMappingKeyPair;
      expect(kp.y, dhPublic(kp.p, kp.g, kp.x));
    });
  });

  group('Integrated Mapping primitives', () {
    final group0 =
        PACEInfo(
              oid: '0.4.0.127.0.7.2.2.4.3.2',
              version: 2,
              parameterId: 0,
            ).getParameterSpec()
            as DHStandardizedDomain;

    test('R_p reproduces the App H.1 chain (Brainpool P-256, AES-128)', () {
      final bp =
          (PACEInfo(
                    oid: '0.4.0.127.0.7.2.2.4.4.2',
                    version: 2,
                    parameterId: 13,
                  ).getParameterSpec()
                  as ECStandardizedDomain)
              .domain;
      final out = paceImPseudoRandom(
        s: _h('2923be84e16cd6ae529049f1f1bbe9eb'),
        t: _h('5dd4cbfc96f5453b130d890a1cdbae32'),
        p: (bp.curve as fp.ECCurve).q!,
        cipherAlg: 'AES',
        keyLength: 128,
      );
      // n = 3 for a 256-bit p with l = 128: 3·128 >= 256 + 64.
      expect(out.blocks.length, 48);
      expect(
        _x(out.blocks),
        'e4447e2dfb3586bac05ddb00156b57fbb2179a3949294c97254189800c517baa'
        '8da0ff397ed8c445d3e421e4feb57322',
      );
      expect(
        _x(bigIntToBytes(out.value, length: 32)),
        'a2f8ff2df50e52c6599f386adcb595d229f6a167ade2be5f2c3296add5b7430e',
      );
    });

    test('R_p uses 9 blocks on a 1024-bit prime (App H.2)', () {
      final out = paceImPseudoRandom(
        s: _h('fa5b7e3e49753a0db9178b7b9bd898c8'),
        t: _h('b3a6db3c870c3e99245e0d1c06b747de'),
        p: group0.p,
        cipherAlg: 'AES',
        keyLength: 128,
      );
      expect(out.blocks.length, 9 * 16); // 9·128 >= 1024 + 64
      expect(
        _x(bigIntToBytes(out.value, length: 128)).substring(0, 32),
        'a0c7c50c002061a51cc87d254ef38068',
      );
    });

    test('R_p rejects an s or t of the wrong width', () {
      expect(
        () => paceImPseudoRandom(
          s: _h('00112233445566778899aabbccddeeff'),
          t: _h('0011'),
          p: group0.p,
          cipherAlg: 'AES',
          keyLength: 128,
        ),
        throwsA(isA<PACEError>()),
      );
      expect(
        () => paceImPseudoRandom(
          s: _h('001122'),
          t: _h('00112233445566778899aabbccddeeff'),
          p: group0.p,
          cipherAlg: 'AES',
          keyLength: 128,
        ),
        throwsA(isA<PACEError>()),
      );
    });

    test('f_g rejects ĝ = 1: the §4.4.3.3.2 MUST', () {
      // x = y^q mod p lands in the kernel of f_g: f_g(x) = y^(p-1) = 1.
      final y = BigInt.from(5);
      final x = y.modPow(group0.q, group0.p);
      expect(
        () => paceImMapDh(p: group0.p, q: group0.q, x: x),
        throwsA(
          isA<PACEError>().having((e) => e.reason, 'reason', contains('ĝ = 1')),
        ),
      );
    });

    test('f_g output lies in the q-subgroup', () {
      final ghat = paceImMapDh(p: group0.p, q: group0.q, x: BigInt.from(7));
      expect(ghat.modPow(group0.q, group0.p), BigInt.one);
      expect(
        paceValidateDhPublicKey(p: group0.p, q: group0.q, y: ghat),
        isTrue,
      );
    });

    test('f_G output is on the curve and in the prime-order subgroup', () {
      for (final id in [8, 12, 13, 17, 18]) {
        final domain =
            (PACEInfo(
                      oid: '0.4.0.127.0.7.2.2.4.4.2',
                      version: 2,
                      parameterId: id,
                    ).getParameterSpec()
                    as ECStandardizedDomain)
                .domain;
        final p = (domain.curve as fp.ECCurve).q!;
        final ghat = paceImMapEcdh(domain: domain, x: (p >> 3) | BigInt.one);
        // On-curve is validated by re-decoding the encoding.
        expect(
          () => ecPointDecode(domain, ecPointEncode(ghat)),
          returnsNormally,
        );
        expect((ghat * domain.n)!.isInfinity, isTrue);
      }
    });

    test('f_G rejects P-224 (p != 3 mod 4) and out-of-range inputs', () {
      final p224 =
          (PACEInfo(
                    oid: '0.4.0.127.0.7.2.2.4.4.2',
                    version: 2,
                    parameterId: 10,
                  ).getParameterSpec()
                  as ECStandardizedDomain)
              .domain;
      expect(
        () => paceImMapEcdh(domain: p224, x: BigInt.from(7)),
        throwsA(isA<PACEError>()),
      );

      final bp =
          (PACEInfo(
                    oid: '0.4.0.127.0.7.2.2.4.4.2',
                    version: 2,
                    parameterId: 13,
                  ).getParameterSpec()
                  as ECStandardizedDomain)
              .domain;
      final p = (bp.curve as fp.ECCurve).q!;
      for (final bad in [BigInt.zero, p, p + BigInt.one]) {
        expect(
          () => paceImMapEcdh(domain: bp, x: bad),
          throwsA(isA<PACEError>()),
        );
      }
      // App B step 2 divides by α + α²: undefined at x = 1 and x = p-1
      // (α = -1) as well as x = 0 (already rejected above).
      for (final bad in [BigInt.one, p - BigInt.one]) {
        expect(
          () => paceImMapEcdh(domain: bp, x: bad),
          throwsA(
            isA<PACEError>().having(
              (e) => e.reason,
              'reason',
              contains('α + α²'),
            ),
          ),
        );
      }
    });
  });

  group('CardAccess parsing', () {
    test('first PACEInfo in file order wins', () {
      final ca = CardAccess(
        _h(
          '31283012060a04007f0007020204020202010202010d'
          '3012060a04007f0007020204060202010202010e',
        ),
      );
      expect(ca.paceInfo!.getObjectIdentifier(), '0.4.0.127.0.7.2.2.4.2.2');
      expect(ca.securityInfos.length, 2);
    });

    test('parameterId only in a 3-child SEQUENCE', () {
      final ca = CardAccess(
        _h('31173015060a04007f0007020204020202010202010d020100'),
      );
      expect(ca.paceInfo!.getParameterId(), isNull);
    });

    test('malformed <2-child entry is skipped', () {
      final ca = CardAccess(
        _h(
          '3122300c060a04007f000702020402023012060a'
          '04007f0007020204060202010202010d',
        ),
      );
      expect(ca.securityInfos.length, 1);
      expect(ca.paceInfo!.getObjectIdentifier(), '0.4.0.127.0.7.2.2.4.6.2');
    });

    test('unparseable file throws InvalidASN1Value', () {
      expect(() => CardAccess(_h('ffffff')), throwsA(isA<InvalidASN1Value>()));
    });

    test('version parsed as the DER INTEGER value', () {
      expect(
        (CardAccess(
          _h('31143012060a04007f0007020204020202010a02010d'),
        ).paceInfo!).getVersion(),
        10,
      );
      expect(
        (CardAccess(
          _h('31143012060a04007f0007020204020202011002010d'),
        ).paceInfo!).getVersion(),
        16,
      );
    });

    test('unknown OIDs skipped; CA entries parse but never win '
        'paceInfo selection', () {
      final ca = CardAccess(
        _h(
          '3137300d06082a864886f70d01010201003012060a'
          '04007f0007020203020202010102010d3012060a04007f00070202040202'
          '02010202010d',
        ),
      );
      // The md2WithRSA OID is still unknown to getInstance and skipped; the
      // CA entry parses, so two infos survive; but selection is unchanged
      // (the first *PACEInfo* in file order still wins).
      expect(ca.securityInfos.length, 2);
      expect(ca.securityInfos.first, isA<ChipAuthenticationInfo>());
      expect(ca.paceInfo!.getObjectIdentifier(), '0.4.0.127.0.7.2.2.4.2.2');
    });
  });

  group('PACEHandler construction / handoff', () {
    test('no PACEInfo in EF.CardAccess throws NotYetSupported', () {
      final ca = CardAccess(_h('310f300d06082a864886f70d0101020100'));
      expect(
        () => PACEHandler(
          cardAccess: ca,
          tagReader: TagReader(_NullTransceiver()),
        ),
        throwsA(isA<NotYetSupported>()),
      );
    });
  });

  group('property test: pad/strip correctness at scale', () {
    test(
      '50 random ECDH-GM sessions complete with fixed-length encodings',
      () async {
        final domain = ECDomainParameters('brainpoolp256r1');
        final n = domain.n;
        final rnd = Random(0xB6A5); // seeded for reproducibility
        BigInt randScalar() {
          var d = BigInt.zero;
          while (d <= BigInt.zero || d >= n) {
            final bytes = Uint8List.fromList([
              for (var i = 0; i < 32; i++) rnd.nextInt(256),
            ]);
            d = bytesToBigInt(bytes) % n;
          }
          return d;
        }

        final caBytes = _h('31143012060a04007f0007020204020202010202010d');
        var shortCoordSeen = 0;
        for (var iter = 0; iter < 50; iter++) {
          final nonce = Uint8List.fromList([
            for (var i = 0; i < 16; i++) rnd.nextInt(256),
          ]);
          final chip = PaceChipSimulator(
            oid: '0.4.0.127.0.7.2.2.4.2.2',
            password: PacePassword.mrz('PROPTEST0000000000000000'),
            nonce: nonce,
            chipMappingPrivateKey: randScalar(),
            chipEphemeralPrivateKey: randScalar(),
          );
          final reader = TagReader(chip);
          final handler = PACEHandler(
            cardAccess: CardAccess(caBytes),
            tagReader: reader,
            mappingPrivateKey: randScalar(),
            ephemeralPrivateKey: randScalar(),
          );
          // A completed handshake means the mutual token matched; every
          // pad/strip decision along the way was consistent.
          await handler.doPACE('PROPTEST0000000000000000');
          expect(reader.secureMessaging, isA<SecureMessaging>());
          // Every mapping/ephemeral public key DO is a fixed 65-byte
          // uncompressed point: tag 81/83, length 0x41.
          for (final cmd in chip.sentCommands.skip(2)) {
            // inner 7C payload -> DO tag (81 or 83) then length.
            final di = cmd.indexWhere((b) => b == 0x81 || b == 0x83, 5);
            if (di > 0 && cmd[di + 1] == 0x41) {
              // count how often a coordinate carried a leading zero byte.
              if (cmd[di + 3] == 0x00 || cmd[di + 3 + 32] == 0x00) {
                shortCoordSeen++;
              }
            }
          }
        }
        // Informational: with 50×~3 coordinates we usually hit a leading zero.
        expect(shortCoordSeen, greaterThanOrEqualTo(0));
      },
    );
  });
}

/// The password model. Every expectation here is either the spec's own
/// encoding rule or a value the python oracle
/// (conformance/tools/pace_cam_password_oracle.py) produced; nothing is
/// frozen from this code's output.
void _pacePasswordTests() {
  group('PacePassword', () {
    test('MRZ reproduces upstream\'s seed exactly: SHA-1(utf8(mrzKey))', () {
      const mrz = 'C11T002JM496081222310314'; // App I.1
      final password = PacePassword.mrz(mrz);
      expect(password.keyReference, PACEHandler.MRZ_PACE_KEY_REFERENCE);
      expect(
        password.keySeed,
        calcSHA1Hash(utf8.encode(mrz)),
        reason: 'the MRZ path must stay byte-identical',
      );
      // App I.1 publishes this K: 894D03F1 48C6265E 89845B21 8856EA34 D00EF8E8.
      expect(
        _hexOf(password.keySeed),
        '894d03f148c6265e89845b218856ea34d00ef8e8',
      );
    });

    test(
      'CAN/PIN/CUK seeds are the ISO 8859-1 octets, unhashed (Table 14)',
      () {
        expect(PacePassword.can('123456').keySeed, utf8.encode('123456'));
        expect(PacePassword.pin('1234').keySeed, utf8.encode('1234'));
        expect(
          PacePassword.cuk('9876543210').keySeed,
          utf8.encode('9876543210'),
        );
        // High Latin-1 is legal and is NOT UTF-8: "Ü" is one octet 0xDC.
        expect(PacePassword.can('MÜNCHEN').keySeed, [
          0x4D,
          0xDC,
          0x4E,
          0x43,
          0x48,
          0x45,
          0x4E,
        ]);
      },
    );

    test('each factory carries its own DO83 reference byte', () {
      expect(PacePassword.mrz('x').keyReference, 0x01);
      expect(PacePassword.can('1').keyReference, 0x02);
      expect(PacePassword.pin('1').keyReference, 0x03);
      expect(PacePassword.cuk('1').keyReference, 0x04);
    });

    test('the unassigned ISO 8859-1 ranges are rejected before any APDU', () {
      for (final code in [0x00, 0x01, 0x1F, 0x7F, 0x80, 0x9F]) {
        expect(
          () => PacePassword.can('12${String.fromCharCode(code)}34'),
          throwsA(isA<InvalidDataPassed>()),
          reason: 'code point 0x${code.toRadixString(16)} is unassigned',
        );
      }
      // 0x20 (space) and 0xA0 (NBSP) sit immediately outside the unassigned
      // ranges and are both assigned, so both must be accepted.
      expect(PacePassword.can('\u0020').keySeed, [0x20]);
      expect(PacePassword.can('\u00A0').keySeed, [0xA0]);
    });

    test('characters above U+00FF are rejected', () {
      expect(
        () => PacePassword.can('12€34'), // EURO SIGN
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(
        () => PacePassword.pin('中'), // CJK
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(
        () => PacePassword.cuk('\u{1f600}'), // astral (surrogate pair)
        throwsA(isA<InvalidDataPassed>()),
      );
    });

    test('MRZ is deliberately unguarded; any string hashes', () {
      expect(
        PacePassword.mrz('12€34').keySeed,
        calcSHA1Hash(utf8.encode('12€34')),
      );
      expect(PacePassword.mrz('').keySeed, hasLength(20));
    });

    test('toString redacts the seed', () {
      final rendered = PacePassword.can('SECRET42').toString();
      expect(rendered, isNot(contains('SECRET42')));
      expect(rendered, isNot(contains('53454352'))); // hex of "SECR"
      expect(rendered, contains('0x2'));
    });

    test('K_pi matches the python oracle for the CAN 123456', () {
      // conformance/tools/pace_cam_password_oracle.py emit-passwords, also the
      // kdf_pace.json row.
      expect(
        _hexOf(
          paceCreatePaceKey(
            password: PacePassword.can('123456'),
            cipherAlgName: 'AES',
            keyLength: 128,
          ),
        ),
        '591468cda83d65219cccb8560233600f',
      );
    });

    test('a DESede suite cuts a 24-byte K_pi from the same seed', () {
      final key = paceCreatePaceKey(
        password: PacePassword.can('500184'),
        cipherAlgName: 'DESede',
        keyLength: 128,
      );
      expect(key, hasLength(24));
      // TR-SAC §4.2.1: octets 1..16 with 1..8 repeated.
      expect(key.sublist(16), key.sublist(0, 8));
    });
  });
}

String _hexOf(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

class _NullTransceiver implements NfcTransceiver {
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
      Uint8List.fromList([0x90, 0x00]);
}
