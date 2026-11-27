/// Crypto unit tests. The below-conformance-granularity pieces:
/// pointycastle curve-registry coverage + Brainpool constants vs RFC 5639,
/// the RNG seam ([FixedRandom] exhaustion, [SystemRandom] shape,
/// rejection-sampling keypair generation off [FixedRandom]), and KDF/cipher
/// internals no vector reaches.
library;

import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/kdf.dart';
import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

/// Every PACEInfo standardized domain parameter (ICAO 9303 P11 Table 12 /
/// TR-03110-3 Table 4, ids 8-18) by pointycastle registry name. Ids 0-2 are
/// the RFC 5114 DH groups (constants held in PACEInfo: no library support
/// needed).
const paceCurveNames = [
  'secp192r1', // 8  (incl. deprecated ids; still in the table)
  'brainpoolp192r1', // 9
  'secp224r1', // 10
  'brainpoolp224r1', // 11
  'secp256r1', // 12
  'brainpoolp256r1', // 13
  'brainpoolp320r1', // 14
  'secp384r1', // 15
  'brainpoolp384r1', // 16
  'brainpoolp512r1', // 17
  'secp521r1', // 18
];

/// RFC 5639 §3 domain parameters, (p, A, B, Gx, Gy, q[order]), hex verbatim
/// from the RFC (Brainpool is where platform crypto quietly fails).
const rfc5639 = {
  'brainpoolp192r1': (
    p: 'C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297',
    a: '6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF',
    b: '469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9',
    x: 'C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6',
    y: '14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F',
    q: 'C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1',
  ),
  'brainpoolp224r1': (
    p: 'D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF',
    a: '68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43',
    b: '2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B',
    x: '0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D',
    y: '58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD',
    q: 'D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F',
  ),
  'brainpoolp256r1': (
    p: 'A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377',
    a: '7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9',
    b: '26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6',
    x: '8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262',
    y: '547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997',
    q: 'A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7',
  ),
  'brainpoolp320r1': (
    p:
        'D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28'
        'FCD412B1F1B32E27',
    a:
        '3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F4'
        '92F375A97D860EB4',
    b:
        '520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD88453981'
        '6F5EB4AC8FB1F1A6',
    x:
        '43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C7'
        '10AF8D0D39E20611',
    y:
        '14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7'
        'D35245D1692E8EE1',
    q:
        'D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E9'
        '8691555B44C59311',
  ),
  'brainpoolp384r1': (
    p:
        '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123'
        'ACD3A729901D1A71874700133107EC53',
    a:
        '7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F'
        '8AA5814A503AD4EB04A8C7DD22CE2826',
    b:
        '04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D5'
        '7CB4390295DBC9943AB78696FA504C11',
    x:
        '1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8'
        'E826E03436D646AAEF87B2E247D4AF1E',
    y:
        '8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF9912928'
        '0E4646217791811142820341263C5315',
    q:
        '8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7'
        'CF3AB6AF6B7FC3103B883202E9046565',
  ),
  'brainpoolp512r1': (
    p:
        'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330871'
        '7D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3',
    a:
        '7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC'
        '2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA',
    b:
        '3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A7'
        '2BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723',
    x:
        '81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098E'
        'FF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822',
    y:
        '7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111'
        'B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892',
    q:
        'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870'
        '553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069',
  ),
};

BigInt bi(String hex) => BigInt.parse(hex, radix: 16);

void main() {
  group('curve registry', () {
    test('pointycastle resolves every PACEInfo standardized curve', () {
      for (final name in paceCurveNames) {
        final domain = ECDomainParameters(name);
        expect(
          domain.domainName.toLowerCase(),
          name,
          reason: 'registry resolved a different curve for $name',
        );
        // Generator must be on the curve and of order n.
        expect(
          (domain.G * domain.n)!.isInfinity,
          isTrue,
          reason: '$name: n*G != O',
        );
      }
    });

    test('Brainpool domain constants match RFC 5639 verbatim', () {
      rfc5639.forEach((name, expected) {
        final domain = ECDomainParameters(name);
        final curve = domain.curve as fp.ECCurve;
        expect(curve.q, bi(expected.p), reason: '$name prime');
        expect(curve.a!.toBigInteger(), bi(expected.a), reason: '$name a');
        expect(curve.b!.toBigInteger(), bi(expected.b), reason: '$name b');
        expect(domain.G.x!.toBigInteger(), bi(expected.x), reason: '$name Gx');
        expect(domain.G.y!.toBigInteger(), bi(expected.y), reason: '$name Gy');
        expect(domain.n, bi(expected.q), reason: '$name order');
      });
    });

    test('every PACE curve has cofactor 1 (plain-scalar-mult parity)', () {
      for (final name in paceCurveNames) {
        final domain = ECDomainParameters(name) as ECDomainParametersImpl;
        expect(domain.h, BigInt.one, reason: '$name cofactor');
      }
    });
  });

  group('rng seam', () {
    test('FixedRandom serves canned bytes front-to-back', () {
      final rng = FixedRandom([1, 2, 3, 4, 5]);
      expect(rng.nextBytes(2), [1, 2]);
      expect(rng.nextBytes(3), [3, 4, 5]);
      expect(rng.remaining, 0);
    });

    test('FixedRandom throws when exhausted instead of wrapping', () {
      final rng = FixedRandom([1, 2, 3]);
      rng.nextBytes(2);
      expect(() => rng.nextBytes(2), throwsStateError);
      // A zero-length request on an exhausted source is still fine.
      expect(rng.nextBytes(0), isEmpty);
    });

    test('SystemRandom returns requested lengths', () {
      final rng = SystemRandom();
      expect(rng.nextBytes(0), isEmpty);
      expect(rng.nextBytes(16).length, 16);
    });
  });

  group('keypair generation off the seam', () {
    test('ecGenerateKeyPair is deterministic under FixedRandom and consistent '
        'with ecPublicFromPrivate', () {
      final curve = ECDomainParameters('brainpoolp256r1');
      // 32 in-range bytes -> accepted on the first draw.
      final seed = List<int>.generate(32, (i) => i + 1);
      final pair = ecGenerateKeyPair(curve, FixedRandom(seed));
      expect(pair.d, bytesToBigInt(seed));
      expect(pair.q, ecPublicFromPrivate(curve, pair.d));
      // Same bytes, same pair.
      expect(ecGenerateKeyPair(curve, FixedRandom(seed)).d, pair.d);
    });

    test('ecGenerateKeyPair rejection-samples out-of-range draws', () {
      final curve = ECDomainParameters('brainpoolp256r1');
      // First draw: all 0xFF (>= n, rejected). Second: in range.
      final rng = FixedRandom([
        ...List.filled(32, 0xFF),
        ...List.generate(32, (i) => i + 1),
      ]);
      final pair = ecGenerateKeyPair(curve, rng);
      expect(pair.d, bytesToBigInt(List.generate(32, (i) => i + 1)));
    });

    test('dhGenerateKeyPair samples below q and matches dhPublic', () {
      final p = bi(
        'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA'
        '52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3C'
        'D49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4F'
        'F55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC'
        '2E4A4371',
      );
      final g = BigInt.two;
      final q = bi('F518AA8781A8DF278ABA4E7D64B7CB9D49462353');
      final seed = List<int>.generate(20, (i) => i + 1);
      final pair = dhGenerateKeyPair(p: p, g: g, q: q, rng: FixedRandom(seed));
      expect(pair.x, bytesToBigInt(seed));
      expect(pair.x < q, isTrue);
      expect(pair.y, dhPublic(p, g, pair.x));
    });
  });

  group('kdf internals', () {
    const kdf = SecureMessagingSessionKeyGenerator();

    test(
      'getHash rejects unknown digest with InvalidHashAlgorithmSpecified',
      () {
        expect(
          () => kdf.getHash(
            algo: 'md5',
            dataElements: [
              [1, 2, 3],
            ],
          ),
          throwsA(isA<InvalidHashAlgorithmSpecified>()),
        );
      },
    );

    test('getHash digests the concatenation of data elements', () {
      final split = kdf.getHash(
        algo: 'SHA1',
        dataElements: [
          [1, 2],
          [3],
        ],
      );
      final joined = kdf.getHash(
        algo: 'sha1',
        dataElements: [
          [1, 2, 3],
        ],
      );
      expect(split, joined);
    });

    test('digest inference mirrors upstream exact-match table', () {
      String infer(String alg, int len) =>
          kdf.inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(
            cipherAlg: alg,
            keyLength: len,
          );
      expect(infer('DESede', 128), 'SHA1');
      expect(infer('AES-128', 256), 'SHA1'); // keyLength ignored on this arm
      expect(infer('AES', 128), 'SHA1');
      expect(infer('AES', 192), 'SHA256');
      expect(infer('AES-256', 128), 'SHA256');
      expect(() => infer('desede', 128), throwsA(isA<InvalidDataPassed>()));
      expect(() => infer('AES', 64), throwsA(isA<InvalidDataPassed>()));
    });
  });

  group('ec_dh conversions', () {
    test('bigIntToBytes round-trips with bytesToBigInt at both semantics', () {
      final v = bi('00ffee');
      expect(bigIntToBytes(v), [0xFF, 0xEE]);
      expect(bigIntToBytes(v, length: 4), [0, 0, 0xFF, 0xEE]);
      expect(bytesToBigInt(bigIntToBytes(v, length: 32)), v);
      expect(bigIntToBytes(BigInt.zero), isEmpty);
      expect(() => bigIntToBytes(BigInt.from(-1)), throwsArgumentError);
      expect(() => bigIntToBytes(v, length: 1), throwsArgumentError);
    });
  });
}
