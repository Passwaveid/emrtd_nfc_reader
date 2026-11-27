/// The passive-authentication verdict API and path building.
///
/// The precedence matrix, every cause, the upstream quirks preserved, the
/// deviations from upstream, and totality under fuzzing.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/lds/data_group.dart';
import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:emrtd_core/src/lds/data_group_parser.dart';
import 'package:emrtd_core/src/lds/sod.dart';
import 'package:emrtd_core/src/pki/csca_trust_store.dart';
import 'package:emrtd_core/src/pki/passive_auth.dart';
import 'package:emrtd_core/src/pki/x509_certificate.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_chip_sim.dart' show hx;
import '../support/emrtd_fixtures.dart';
import '../support/pki_fixtures.dart';

final CscaTrustStore defaultStore = CscaTrustStore.fromPem(trustPemDefault);
final CscaTrustStore linkStore = CscaTrustStore.fromPem(trustPemLink);
final CscaTrustStore emptyStore = CscaTrustStore.fromPem(trustPemEmpty);
final CscaTrustStore dscAnchorStore = CscaTrustStore.fromPem(
  trustPemDscAsAnchor,
);

Map<DataGroupId, DataGroup> readSet({bool tamperedDg1 = false}) {
  final parser = DataGroupParser();
  return {
    DataGroupId.DG1: parser.parseDG(
      data: hx(tamperedDg1 ? dg1TamperedHex : dg1GoodHex),
    ),
    DataGroupId.DG2: parser.parseDG(data: hx(dg2Hex)),
  };
}

PassiveAuthResult verify(
  Uint8List sodFile, {
  CscaTrustStore? store,
  Map<DataGroupId, DataGroup> dataGroups = const {},
  DateTime? at,
}) => verifyPassiveAuth(
  sod: SOD(sodFile),
  trustStore: store ?? defaultStore,
  dataGroupsRead: dataGroups,
  verificationTime: at ?? pkiVerificationTime,
);

void main() {
  group('the happy path, per scheme', () {
    final schemes = <String, Uint8List>{
      'RSA v1.5 SHA-256': sodRsaSha256,
      'plain rsaEncryption + SHA-256': sodRsaEncryptionSha256,
      'plain rsaEncryption + SHA-512 (upstream fails it)':
          sodRsaEncryptionSha512,
      'RSASSA-PSS SHA-256': sodRsaPssSha256,
      'RSASSA-PSS SHA-384 (upstream fails it)': sodRsaPssSha384,
      'ECDSA P-256': sodEcdsaP256,
      'ECDSA brainpoolP256r1': sodEcdsaBrainpool,
      'ECDSA explicit params (as upstream)': sodEcdsaExplicitParams,
    };
    for (final e in schemes.entries) {
      test('${e.key} verifies with hashes, signature and chain', () {
        final r = verify(e.value, dataGroups: readSet());
        expect(
          r.outcome,
          PassiveAuthOutcome.verified,
          reason: r.signature.detail,
        );
        expect(r.cause, isNull);
        expect(r.annotations, isEmpty);
        expect(r.signature.valid, isTrue);
        expect(r.hashCheck!.passed, isTrue);
        expect(r.trust!.trusted, isTrue);
        expect(r.trust!.chain, hasLength(2));
        expect(r.documentSigningCertificate, isNotNull);
        expect(r.countrySigningCertificate, isNotNull);
        // the upstream boolean triple
        expect(r.passportDataNotTampered, isTrue);
        expect(r.documentSigningCertificateVerified, isTrue);
        expect(r.passportCorrectlySigned, isTrue);
      });
    }

    test('SHA-1 verifies and is annotated weakDigest', () {
      final r = verify(sodRsaSha1, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.verified);
      expect(r.annotations, {PassiveAuthAnnotation.weakDigest});
      expect(r.signature.digestAlgorithm, 'SHA1');
      expect(PassiveAuthAnnotation.weakDigest.wireName, 'weak_digest');
    });

    test('an ECDSA signature with non-minimal INTEGERs verifies', () {
      final r = verify(sodEcdsaLeadingZero, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.verified);
    });

    test('no data groups: the hash half passes vacuously', () {
      final r = verify(sodRsaSha256);
      expect(r.outcome, PassiveAuthOutcome.verified);
      expect(r.hashCheck, isNull);
      expect(r.passportDataNotTampered, isTrue);
    });

    test('scheme and digest are reported', () {
      expect(verify(sodRsaSha256).signature.signatureScheme, 'rsa_pkcs1');
      expect(verify(sodRsaPssSha384).signature.signatureScheme, 'rsa_pss');
      expect(verify(sodRsaPssSha384).signature.digestAlgorithm, 'SHA384');
      expect(verify(sodEcdsaP256).signature.signatureScheme, 'ecdsa');
    });
  });

  group('precedence (tamper > unsupported > bad-signature > chain)', () {
    test('a tampered DG wins over everything else', () {
      final r = verify(
        sodCorruptSignature,
        store: emptyStore,
        dataGroups: readSet(tamperedDg1: true),
      );
      expect(r.outcome, PassiveAuthOutcome.invalid);
      expect(r.cause, PassiveAuthCause.dgHashMismatch);
      expect(r.passportDataNotTampered, isFalse);
      // both halves are still computed and attached
      expect(r.signature.valid, isFalse);
      expect(r.trust!.trusted, isFalse);
    });

    test('an unsupported algorithm wins over a bad chain', () {
      final r = verify(
        sodDsaAlgorithm,
        store: emptyStore,
        dataGroups: readSet(),
      );
      expect(r.outcome, PassiveAuthOutcome.unverifiable);
      expect(r.cause, PassiveAuthCause.unsupportedAlgorithm);
      expect(r.signature.cause, PassiveAuthCause.unsupportedAlgorithm);
      expect(r.signature.detail, contains('allowlist'));
    });

    test('a bad signature wins over a bad chain (upstream swallows it)', () {
      final r = verify(
        sodCorruptSignature,
        store: emptyStore,
        dataGroups: readSet(),
      );
      expect(r.outcome, PassiveAuthOutcome.invalid);
      expect(r.cause, PassiveAuthCause.badDsSignature);
      // Upstream swallows this entirely and reports the boolean triple only.
      expect(r.documentSigningCertificateVerified, isFalse);
      expect(r.passportDataNotTampered, isTrue);
    });

    test('the chain is last', () {
      final r = verify(sodRsaSha256, store: emptyStore, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.unverifiable);
      expect(r.cause, PassiveAuthCause.unknownCsca);
    });

    test('cause wire names match the server-side taxonomy', () {
      expect(PassiveAuthCause.values.map((c) => c.wireName), [
        'dg_hash_mismatch',
        'bad_ds_signature',
        'malformed_sod',
        'unknown_csca',
        'expired_chain_element',
        'unsupported_algorithm',
      ]);
    });
  });

  group('malformed SODs (strictness)', () {
    final cases = <String, Uint8List>{
      'eContentType is not id-ldsSecurityObject': sodWrongEContentType,
      'the content-type attribute does not match': sodContentTypeAttrMismatch,
      'signedAttrs are absent': sodNoSignedAttributes,
      'the certificate set is empty (upstream crashes)': sodCertless,
    };
    for (final e in cases.entries) {
      test('${e.key} -> invalid/malformed_sod', () {
        final r = verify(e.value, dataGroups: readSet());
        expect(r.outcome, PassiveAuthOutcome.invalid);
        expect(r.cause, PassiveAuthCause.malformedSod);
        expect(r.signature.valid, isFalse);
        expect(r.signature.cause, PassiveAuthCause.malformedSod);
        expect(r.signature.detail, isNotEmpty);
        expect(r.trust, isNull);
        expect(r.documentSigningCertificate, isNull);
        // The hash half is still attached where it could be computed.
        expect(r.hashCheck, isNotNull);
      });
    }

    test('the dummy-SignerInfo fixture SOD is malformed, not a crash', () {
      final r = verify(hx(sodHex), dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.invalid);
      expect(r.cause, PassiveAuthCause.malformedSod);
    });
  });

  group('path building', () {
    test('an expired DSC is expired_chain_element, not unknown_csca', () {
      final r = verify(sodExpiredDsc, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.unverifiable);
      expect(r.cause, PassiveAuthCause.expiredChainElement);
      expect(r.trust!.detail, contains('validity window'));
    });

    test(
      'the same DSC verifies at a time inside its window (injected clock)',
      () {
        final r = verify(
          sodExpiredDsc,
          dataGroups: readSet(),
          at: DateTime.utc(2018, 6, 1),
        );
        expect(r.outcome, PassiveAuthOutcome.verified);
      },
    );

    test('a DSC that is its own anchor fails with chain length 1', () {
      final r = verify(
        sodDscAsAnchor,
        store: dscAnchorStore,
        dataGroups: readSet(),
      );
      expect(r.outcome, PassiveAuthOutcome.unverifiable);
      expect(r.cause, PassiveAuthCause.unknownCsca);
      expect(r.trust!.chain, hasLength(1));
      expect(r.trust!.detail, contains('its own anchor'));
      expect(r.signature.valid, isTrue, reason: 'only the chain half fails');
    });

    test('a CSCA link certificate is walked multi-hop to the anchor', () {
      final r = verify(sodLinkChain, store: linkStore, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.verified);
      expect(r.trust!.chain, hasLength(3));
      expect(r.countrySigningCertificate!.subject, contains('CSCA 2018'));
    });

    test('a case-differing DN still builds a chain', () {
      final r = verify(sodCaseDifferingDn, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.verified);
      expect(r.trust!.chain, hasLength(2));
    });

    test('an out-of-store CSCA is unknown_csca', () {
      final r = verify(sodLinkChain, dataGroups: readSet());
      expect(r.outcome, PassiveAuthOutcome.unverifiable);
      expect(r.cause, PassiveAuthCause.unknownCsca);
      expect(r.trust!.detail, contains('no trusted issuer'));
    });

    test('an issuer that is not a CA is not a candidate', () {
      // The DSC is not a CA; a store that contains it cannot make it one.
      final store = CscaTrustStore.fromCertificates([dscRsaCert]);
      final dsc = X509Certificate.tryParse(dscUnderNewCert)!;
      final chain = buildTrustChain(
        dsc: dsc,
        trustStore: store,
        at: pkiVerificationTime,
      );
      expect(chain.trusted, isFalse);
      expect(chain.cause, PassiveAuthCause.unknownCsca);
    });

    test('an expired anchor is expired_chain_element', () {
      final store = CscaTrustStore.fromCertificates([cscaRsaCert]);
      final chain = buildTrustChain(
        dsc: X509Certificate.tryParse(dscRsaCert)!,
        trustStore: store,
        at: DateTime.utc(2130),
      );
      expect(chain.trusted, isFalse);
      expect(chain.cause, PassiveAuthCause.expiredChainElement);
    });

    test('the reported CSCA is the terminal anchor of the built chain', () {
      final r = verify(sodRsaSha256, dataGroups: readSet());
      expect(
        r.countrySigningCertificate!.fingerprintSha256,
        X509Certificate.tryParse(cscaRsaCert)!.fingerprintSha256,
      );
    });
  });

  group('verifySodSignature (storeless)', () {
    test('is computable with no trust store at all', () {
      final ok = verifySodSignature(SOD(sodRsaSha256));
      expect(ok.valid, isTrue);
      expect(ok.cause, isNull);
      expect(ok.digestAlgorithm, 'SHA256');

      final bad = verifySodSignature(SOD(sodCorruptSignature));
      expect(bad.valid, isFalse);
      expect(bad.cause, PassiveAuthCause.badDsSignature);

      final malformed = verifySodSignature(SOD(sodCertless));
      expect(malformed.valid, isFalse);
      expect(malformed.cause, PassiveAuthCause.malformedSod);

      final unsupported = verifySodSignature(SOD(sodDsaAlgorithm));
      expect(unsupported.valid, isFalse);
      expect(unsupported.cause, PassiveAuthCause.unsupportedAlgorithm);
    });

    test('annotations travel on the signature-only result too', () {
      expect(verifySodSignature(SOD(sodRsaSha1)).annotations, {
        PassiveAuthAnnotation.weakDigest,
      });
    });
  });

  group('totality', () {
    test('a hash mismatch never throws out of the verdict layer', () {
      final r = verify(sodRsaSha256, dataGroups: readSet(tamperedDg1: true));
      expect(r.outcome, PassiveAuthOutcome.invalid);
      expect(r.cause, PassiveAuthCause.dgHashMismatch);
      expect(r.hashCheck!.errors, contains('invalid hash'));
    });

    test('a SOD attesting data groups that were not read is a mismatch', () {
      final parser = DataGroupParser();
      final r = verify(
        sodRsaSha256,
        dataGroups: {
          DataGroupId.DG1: parser.parseDG(data: hx(dg1GoodHex)),
          DataGroupId.DG2: parser.parseDG(data: hx(dg2Hex)),
          DataGroupId.DG15: parser.parseDG(data: buildDg15()),
        },
      );
      expect(r.cause, PassiveAuthCause.dgHashMismatch);
    });

    test('bit-flip fuzzing over a valid SOD always yields a verdict', () {
      // Truncations never reach this layer at all: the `SOD` constructor
      // rejects them eagerly, which the CMS suite pins separately.
      // What *can* reach it is a structurally intact file with corrupted
      // content, so that is what is fuzzed here.
      var verdicts = 0;
      for (var i = 4; i < sodRsaSha256.length; i += 37) {
        final mutated = Uint8List.fromList(sodRsaSha256);
        mutated[i] ^= 0x40;
        SOD sod;
        try {
          sod = SOD(mutated);
        } catch (_) {
          continue; // the LDS walk rejected it first
        }
        expect(
          () => verifyPassiveAuth(
            sod: sod,
            trustStore: defaultStore,
            dataGroupsRead: readSet(),
            verificationTime: pkiVerificationTime,
          ),
          returnsNormally,
          reason: 'byte $i',
        );
        verdicts++;
      }
      expect(verdicts, greaterThan(10));
    });

    test('a hostile CMS body is a malformed_sod verdict', () {
      for (final body in <List<int>>[
        const [0x30, 0x00],
        const [0x30, 0x03, 0x02, 0x01, 0x01],
      ]) {
        final file = Uint8List.fromList([0x77, body.length, ...body]);
        final r = verifyPassiveAuth(
          sod: SOD(file),
          trustStore: defaultStore,
          verificationTime: pkiVerificationTime,
        );
        expect(r.outcome, PassiveAuthOutcome.invalid);
        expect(r.cause, PassiveAuthCause.malformedSod);
      }
    });
  });
}
