/// The CSCA trust store.
///
/// PEM ingestion, dedup, the DN/SKI index, and the signed-`.ml` matrix:
/// verify-signature-first, eContentType gating, signer pinning, and the
/// tolerant-reader skip count.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/pki/csca_trust_store.dart';
import 'package:emrtd_core/src/pki/x509_certificate.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/pki_fixtures.dart';

void main() {
  group('fromPem (upstream\'s format)', () {
    test('reads a concatenation and indexes it', () {
      final store = CscaTrustStore.fromPem(trustPemDefault);
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 0);
      expect(store.masterListInfo, isNull);

      final dsc = X509Certificate.tryParse(dscRsaCert)!;
      final candidates = store.candidateIssuers(dsc);
      expect(candidates, hasLength(1));
      expect(
        candidates.single.fingerprintSha256,
        X509Certificate.tryParse(cscaRsaCert)!.fingerprintSha256,
      );
    });

    test('an empty or non-PEM input yields an empty store, not an error', () {
      expect(CscaTrustStore.fromPem(trustPemEmpty).certificateCount, 0);
      expect(
        CscaTrustStore.fromPem('not a pem file at all').certificateCount,
        0,
      );
    });

    test('duplicates are deduped by SHA-256 fingerprint', () {
      final store = CscaTrustStore.fromPem(trustPemDefault + trustPemDefault);
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 0);
    });

    test('an unparseable block is skipped and counted', () {
      const bad =
          '-----BEGIN CERTIFICATE-----\nMTIz\n'
          '-----END CERTIFICATE-----\n';
      final store = CscaTrustStore.fromPem(trustPemDefault + bad);
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 1);
    });

    test('candidate lookup: SKI first, then the normalized DN', () {
      final store = CscaTrustStore.fromPem(trustPemDefault);
      // The case-differing DSC has no AKI, so only the normalized DN
      // comparison can find its issuer.
      final caseDiff = X509Certificate.tryParse(dscCaseDiffCert)!;
      expect(caseDiff.authorityKeyIdentifier, isNull);
      expect(store.candidateIssuers(caseDiff), hasLength(1));

      // A DSC issued under an anchor that is not in the store has none.
      final orphan = X509Certificate.tryParse(dscUnderNewCert)!;
      expect(store.candidateIssuers(orphan), isEmpty);
    });

    test('contains() is fingerprint identity (the own-anchor input)', () {
      final store = CscaTrustStore.fromPem(trustPemDscAsAnchor);
      expect(
        store.contains(X509Certificate.tryParse(dscSelfSignedCert)!),
        isTrue,
      );
      expect(store.contains(X509Certificate.tryParse(cscaRsaCert)!), isFalse);
    });
  });

  group('fromCertificates', () {
    test('takes DER directly and counts unparseable entries', () {
      final store = CscaTrustStore.fromCertificates([
        cscaRsaCert,
        const [0xDE, 0xAD],
        cscaEcCert,
      ]);
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 1);
    });
  });

  group('fromSignedMasterList (no upstream analogue)', () {
    test('a valid pinned list loads', () {
      final store = CscaTrustStore.fromSignedMasterList(
        masterListValid,
        pinnedSignerDer: mlSignerCert,
      );
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 0);
      final info = store.masterListInfo!;
      expect(info.eContentType, '2.23.136.1.1.2');
      expect(info.version, 0);
      expect(info.signatureVerified, isTrue);
      expect(info.pinned, isTrue);
      expect(info.signerSubject, contains('MASTER LIST SIGNER'));
      expect(
        info.signerFingerprintSha256,
        X509Certificate.tryParse(mlSignerCert)!.fingerprintSha256,
      );
    });

    test('a BER indefinite-length list loads identically', () {
      final der = CscaTrustStore.fromSignedMasterList(
        masterListValid,
        pinnedSignerDer: mlSignerCert,
      );
      final ber = CscaTrustStore.fromSignedMasterList(
        masterListIndefiniteLengths,
        pinnedSignerDer: mlSignerCert,
      );
      expect(ber.certificateCount, der.certificateCount);
      expect(
        ber.certificates.map((c) => c.fingerprintSha256),
        der.certificates.map((c) => c.fingerprintSha256),
      );
    });

    test('pinning by chain: the CSCA that issued the signer also pins it', () {
      final store = CscaTrustStore.fromSignedMasterList(
        masterListValid,
        pinnedSignerDer: cscaRsaCert,
      );
      expect(store.masterListInfo!.pinned, isTrue);
    });

    test('a wrong pin throws unless allowUnpinned is set', () {
      expect(
        () => CscaTrustStore.fromSignedMasterList(
          masterListValid,
          pinnedSignerDer: cscaEcCert,
        ),
        throwsA(isA<MasterListPinningException>()),
      );
      final store = CscaTrustStore.fromSignedMasterList(
        masterListValid,
        pinnedSignerDer: cscaEcCert,
        allowUnpinned: true,
      );
      expect(store.masterListInfo!.pinned, isFalse);
      expect(store.certificateCount, 2);
    });

    test('no pin at all is refused unless allowUnpinned is set', () {
      expect(
        () => CscaTrustStore.fromSignedMasterList(masterListValid),
        throwsA(isA<MasterListPinningException>()),
      );
      expect(
        CscaTrustStore.fromSignedMasterList(
          masterListValid,
          allowUnpinned: true,
        ).certificateCount,
        2,
      );
    });

    test('the signature is checked BEFORE pinning', () {
      // allowUnpinned cannot rescue a list whose own signature is broken.
      expect(
        () => CscaTrustStore.fromSignedMasterList(
          masterListBadSignature,
          allowUnpinned: true,
        ),
        throwsA(isA<MasterListSignatureException>()),
      );
    });

    test('a wrong eContentType is refused', () {
      expect(
        () => CscaTrustStore.fromSignedMasterList(
          masterListWrongEContentType,
          pinnedSignerDer: mlSignerCert,
        ),
        throwsA(isA<MasterListContentTypeException>()),
      );
    });

    test('an unparseable embedded certificate is skipped and counted', () {
      final store = CscaTrustStore.fromSignedMasterList(
        masterListWithGarbageEntry,
        pinnedSignerDer: mlSignerCert,
      );
      expect(store.certificateCount, 2);
      expect(store.skippedCertificates, 1);
    });

    test('garbage input and an unparseable pin are typed errors', () {
      expect(
        () => CscaTrustStore.fromSignedMasterList(
          Uint8List.fromList(const [1, 2, 3]),
        ),
        throwsA(isA<MasterListParseException>()),
      );
      expect(
        () => CscaTrustStore.fromSignedMasterList(
          masterListValid,
          pinnedSignerDer: const [0xDE, 0xAD],
        ),
        throwsA(isA<MasterListPinningException>()),
      );
    });

    test('every exception carries a stable code and a reason', () {
      final errors = <MasterListException>[];
      void capture(void Function() f) {
        try {
          f();
        } on MasterListException catch (e) {
          errors.add(e);
        }
      }

      capture(
        () =>
            CscaTrustStore.fromSignedMasterList(Uint8List.fromList(const [1])),
      );
      capture(
        () => CscaTrustStore.fromSignedMasterList(
          masterListWrongEContentType,
          pinnedSignerDer: mlSignerCert,
        ),
      );
      capture(
        () => CscaTrustStore.fromSignedMasterList(
          masterListBadSignature,
          allowUnpinned: true,
        ),
      );
      capture(() => CscaTrustStore.fromSignedMasterList(masterListValid));

      expect(errors.map((e) => e.code), [
        'MasterListParseError',
        'MasterListContentTypeError',
        'MasterListSignatureError',
        'MasterListPinningError',
      ]);
      for (final e in errors) {
        expect(e.reason, isNotEmpty);
        expect(e.toString(), startsWith(e.code));
      }
    });

    test('a truncated list never crashes', () {
      for (var n = 0; n < masterListValid.length; n += 97) {
        expect(
          () => CscaTrustStore.fromSignedMasterList(
            Uint8List.sublistView(masterListValid, 0, n),
            allowUnpinned: true,
          ),
          throwsA(isA<MasterListException>()),
          reason: 'truncated at $n',
        );
      }
    });
  });

  test('an ingested master list is usable as a trust store', () {
    final store = CscaTrustStore.fromSignedMasterList(
      masterListValid,
      pinnedSignerDer: mlSignerCert,
    );
    final dsc = X509Certificate.tryParse(dscRsaCert)!;
    expect(store.candidateIssuers(dsc), hasLength(1));
  });
}
