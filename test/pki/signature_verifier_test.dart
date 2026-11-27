/// The allowlisted signature verifier, which fixes upstream's dispatch (PSS
/// parameters ignored, SHA-256 by default).
///
/// OID wiring per scheme, the RFC 4055 PSS parameter matrix, the lenient
/// ECDSA DER decoder, and the shared-SPKI reuse.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/lds/subject_public_key_info.dart';
import 'package:emrtd_core/src/pki/signature_verifier.dart';
import 'package:emrtd_core/src/pki/x509_certificate.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_test_pki.dart';
import '../support/pki_fixtures.dart';

void main() {
  group('allowlist (fixes upstream\'s dispatch)', () {
    test('the five RSA PKCS#1 v1.5 OIDs', () {
      const cases = {
        '1.2.840.113549.1.1.5': 'SHA1',
        '1.2.840.113549.1.1.14': 'SHA224',
        '1.2.840.113549.1.1.11': 'SHA256',
        '1.2.840.113549.1.1.12': 'SHA384',
        '1.2.840.113549.1.1.13': 'SHA512',
      };
      for (final e in cases.entries) {
        final r = resolveSignatureAlgorithm(signatureAlgorithmOid: e.key)!;
        expect(r.scheme, PkiSignatureScheme.rsaPkcs1);
        expect(r.digestName, e.value);
      }
    });

    test('the five ECDSA OIDs', () {
      const cases = {
        '1.2.840.10045.4.1': 'SHA1',
        '1.2.840.10045.4.3.1': 'SHA224',
        '1.2.840.10045.4.3.2': 'SHA256',
        '1.2.840.10045.4.3.3': 'SHA384',
        '1.2.840.10045.4.3.4': 'SHA512',
      };
      for (final e in cases.entries) {
        final r = resolveSignatureAlgorithm(signatureAlgorithmOid: e.key)!;
        expect(r.scheme, PkiSignatureScheme.ecdsa);
        expect(r.digestName, e.value);
      }
    });

    test('plain rsaEncryption takes its digest from the SignerInfo', () {
      final r = resolveSignatureAlgorithm(
        signatureAlgorithmOid: oidRsaEncryption,
        signerDigestOid: '2.16.840.1.101.3.4.2.3',
      )!;
      expect(r.scheme, PkiSignatureScheme.rsaPkcs1);
      expect(r.digestName, 'SHA512');
      // With no SignerInfo digest to consult (a certificate signature) there
      // is nothing to resolve; upstream would silently use SHA-256.
      expect(
        resolveSignatureAlgorithm(signatureAlgorithmOid: oidRsaEncryption),
        isNull,
      );
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsaEncryption,
          signerDigestOid: '1.2.3.4',
        ),
        isNull,
      );
    });

    test('unsupported algorithms resolve to null, never a SHA-256 default', () {
      for (final oid in const [
        '1.2.840.10040.4.3', // dsaWithSHA1
        '2.16.840.1.101.3.4.3.2', // dsa_with_SHA256
        '1.3.101.112', // Ed25519
        '1.2.3.4.5',
      ]) {
        expect(
          resolveSignatureAlgorithm(signatureAlgorithmOid: oid),
          isNull,
          reason: oid,
        );
      }
    });

    test('SHA-1/224 resolve and are flagged weak, not rejected', () {
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: '1.2.840.113549.1.1.5',
        )!.weakDigest,
        isTrue,
      );
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: '1.2.840.113549.1.1.14',
        )!.weakDigest,
        isTrue,
      );
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: '1.2.840.113549.1.1.11',
        )!.weakDigest,
        isFalse,
      );
    });

    test('scheme wire names', () {
      expect(PkiSignatureScheme.rsaPkcs1.wireName, 'rsa_pkcs1');
      expect(PkiSignatureScheme.rsaPss.wireName, 'rsa_pss');
      expect(PkiSignatureScheme.ecdsa.wireName, 'ecdsa');
    });
  });

  group('RSASSA-PSS parameters (RFC 4055)', () {
    test('every digest resolves from its own parameters', () {
      for (final name in const [
        'SHA1',
        'SHA224',
        'SHA256',
        'SHA384',
        'SHA512',
      ]) {
        final r = resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: pssParameters(name),
        )!;
        expect(r.scheme, PkiSignatureScheme.rsaPss);
        expect(r.digestName, name, reason: name);
        expect(r.mgfDigestName, name);
        expect(r.saltLength, digestFor(name)!.digestSize);
      }
    });

    test('absent parameters take RFC 4055 DEFAULTs (sha1/mgf1SHA1/20/1)', () {
      final r = resolveSignatureAlgorithm(signatureAlgorithmOid: oidRsassaPss)!;
      expect(r.digestName, 'SHA1');
      expect(r.mgfDigestName, 'SHA1');
      expect(r.saltLength, 20);
      final explicitNull = resolveSignatureAlgorithm(
        signatureAlgorithmOid: oidRsassaPss,
        parameters: Der.nul(),
      )!;
      expect(explicitNull.digestName, 'SHA1');
    });

    test('an MGF1 digest may differ from the content digest', () {
      final params = Der.seq([
        Der.explicit(0, Der.seq([Der.oid(digestSha512), Der.nul()])),
        Der.explicit(
          1,
          Der.seq([
            Der.oid('1.2.840.113549.1.1.8'),
            Der.seq([Der.oid(digestSha256), Der.nul()]),
          ]),
        ),
        Der.explicit(2, Der.int32(32)),
        Der.explicit(3, Der.int32(1)),
      ]);
      final r = resolveSignatureAlgorithm(
        signatureAlgorithmOid: oidRsassaPss,
        parameters: params,
      )!;
      expect(r.digestName, 'SHA512');
      expect(r.mgfDigestName, 'SHA256');
      expect(r.saltLength, 32);
    });

    test('a non-MGF1 mask is unsupported', () {
      final params = Der.seq([
        Der.explicit(0, Der.seq([Der.oid(digestSha256), Der.nul()])),
        Der.explicit(
          1,
          Der.seq([
            Der.oid('1.2.3.4'),
            Der.seq([Der.oid(digestSha256), Der.nul()]),
          ]),
        ),
      ]);
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: params,
        ),
        isNull,
      );
    });

    test('trailerField must be 1', () {
      final params = Der.seq([
        Der.explicit(0, Der.seq([Der.oid(digestSha256), Der.nul()])),
        Der.explicit(3, Der.int32(2)),
      ]);
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: params,
        ),
        isNull,
      );
    });

    test('an unsupported hash or garbage parameters resolve to null', () {
      final unknownHash = Der.seq([
        Der.explicit(0, Der.seq([Der.oid('1.2.3.4'), Der.nul()])),
      ]);
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: unknownHash,
        ),
        isNull,
      );
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: const [0x01, 0x02],
        ),
        isNull,
      );
      final absurdSalt = Der.seq([
        Der.explicit(0, Der.seq([Der.oid(digestSha256), Der.nul()])),
        Der.explicit(2, Der.int32(99999)),
      ]);
      expect(
        resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: absurdSalt,
        ),
        isNull,
      );
    });
  });

  group('ECDSA DER decoding', () {
    test('a minimal encoding decodes', () {
      final der = Der.seq([Der.int32(0x1234), Der.int32(0x5678)]);
      expect(decodeEcdsaDerSignature(der), (
        BigInt.from(0x1234),
        BigInt.from(0x5678),
      ));
    });

    test('non-minimal INTEGERs are accepted (upstream repairs them)', () {
      final nonMinimal = Uint8List.fromList([
        0x30, 0x08, //
        0x02, 0x02, 0x00, 0x12, //
        0x02, 0x02, 0x00, 0x34,
      ]);
      expect(decodeEcdsaDerSignature(nonMinimal), (
        BigInt.from(0x12),
        BigInt.from(0x34),
      ));
    });

    test('garbage, wrong shapes and negatives are rejected', () {
      expect(decodeEcdsaDerSignature(const [0x01, 0x02]), isNull);
      expect(decodeEcdsaDerSignature(Der.seq([Der.int32(1)])), isNull);
      expect(
        decodeEcdsaDerSignature(
          Der.seq([Der.int32(1), Der.int32(2), Der.int32(3)]),
        ),
        isNull,
      );
      expect(
        decodeEcdsaDerSignature(
          Der.seq([
            Der.octetString(const [1]),
            Der.int32(2),
          ]),
        ),
        isNull,
      );
      expect(
        decodeEcdsaDerSignature(
          Uint8List.fromList([0x30, 0x06, 0x02, 0x01, 0xFF, 0x02, 0x01, 0x02]),
        ),
        isNull,
        reason: 'a negative r has no valid reading',
      );
      expect(
        decodeEcdsaDerSignature([
          ...Der.seq([Der.int32(1), Der.int32(2)]),
          0x00,
        ]),
        isNull,
        reason: 'trailing bytes',
      );
    });
  });

  group('verification', () {
    final data = Uint8List.fromList(List.generate(64, (i) => i));

    test('RSA PKCS#1 v1.5 round-trips at every digest', () {
      final key =
          parseSubjectPublicKeyInfo(dscRsaKey.spki())! as SpkiRsaPublicKey;
      for (final oid in const [
        sigSha1Rsa,
        sigSha256Rsa,
        sigSha384Rsa,
        sigSha512Rsa,
      ]) {
        final alg = resolveSignatureAlgorithm(signatureAlgorithmOid: oid)!;
        final sig = testSign(key: dscRsaKey, sigAlgOid: oid, data: data);
        expect(
          verifyPkiSignature(
            key: key,
            algorithm: alg,
            data: data,
            signature: sig,
          ),
          isTrue,
          reason: oid,
        );
        expect(
          verifyPkiSignature(
            key: key,
            algorithm: alg,
            data: [...data, 0x00],
            signature: sig,
          ),
          isFalse,
        );
      }
    });

    test('RSASSA-PSS round-trips with the declared parameters', () {
      final key =
          parseSubjectPublicKeyInfo(dscRsaKey.spki())! as SpkiRsaPublicKey;
      for (final name in const ['SHA256', 'SHA384', 'SHA512']) {
        final params = pssParameters(name);
        final alg = resolveSignatureAlgorithm(
          signatureAlgorithmOid: oidRsassaPss,
          parameters: params,
        )!;
        final sig = testSign(
          key: dscRsaKey,
          sigAlgOid: oidRsassaPss,
          data: data,
          pssParams: params,
        );
        expect(
          verifyPkiSignature(
            key: key,
            algorithm: alg,
            data: data,
            signature: sig,
          ),
          isTrue,
          reason: name,
        );
        // Upstream's failure: verifying the same signature under SHA-256
        // parameters (upstream's hard-coded default) fails for SHA-384/512.
        if (name != 'SHA256') {
          final wrong = resolveSignatureAlgorithm(
            signatureAlgorithmOid: oidRsassaPss,
            parameters: pssParameters('SHA256'),
          )!;
          expect(
            verifyPkiSignature(
              key: key,
              algorithm: wrong,
              data: data,
              signature: sig,
            ),
            isFalse,
            reason: 'upstream\'s default: $name PSS under SHA-256 params',
          );
        }
      }
    });

    test('ECDSA round-trips on both fixture curves', () {
      for (final k in [dscEcKey, dscBrainpoolKey]) {
        final key = parseSubjectPublicKeyInfo(k.spki())! as SpkiEcPublicKey;
        final alg = resolveSignatureAlgorithm(
          signatureAlgorithmOid: sigEcdsaSha256,
        )!;
        final sig = testSign(key: k, sigAlgOid: sigEcdsaSha256, data: data);
        expect(
          verifyPkiSignature(
            key: key,
            algorithm: alg,
            data: data,
            signature: sig,
          ),
          isTrue,
          reason: k.curveName,
        );
      }
    });

    test('a key of the wrong family fails rather than throwing', () {
      final rsaKey =
          parseSubjectPublicKeyInfo(dscRsaKey.spki())! as SpkiRsaPublicKey;
      final ecAlg = resolveSignatureAlgorithm(
        signatureAlgorithmOid: sigEcdsaSha256,
      )!;
      expect(
        verifyPkiSignature(
          key: rsaKey,
          algorithm: ecAlg,
          data: data,
          signature: const [1],
        ),
        isFalse,
      );
    });

    test('garbage signatures fail rather than throwing', () {
      final key =
          parseSubjectPublicKeyInfo(dscRsaKey.spki())! as SpkiRsaPublicKey;
      final alg = resolveSignatureAlgorithm(
        signatureAlgorithmOid: sigSha256Rsa,
      )!;
      for (final sig in [
        const <int>[],
        List<int>.filled(256, 0xFF),
        List<int>.filled(3, 0x01),
      ]) {
        expect(
          verifyPkiSignature(
            key: key,
            algorithm: alg,
            data: data,
            signature: sig,
          ),
          isFalse,
        );
      }
    });

    test('the shared SPKI parser drives certificate keys', () {
      // Explicit-params EC certificates produce a usable key (as upstream),
      // and their signatures verify like any other.
      final cert = X509Certificate.tryParse(dscEcExplicitCert)!;
      expect(cert.publicKey, isA<SpkiEcPublicKey>());
      final alg = resolveSignatureAlgorithm(
        signatureAlgorithmOid: sigEcdsaSha256,
      )!;
      final sig = testSign(
        key: dscEcExplicitKey,
        sigAlgOid: sigEcdsaSha256,
        data: data,
      );
      expect(
        verifyPkiSignature(
          key: cert.publicKey!,
          algorithm: alg,
          data: data,
          signature: sig,
        ),
        isTrue,
      );
    });
  });
}
