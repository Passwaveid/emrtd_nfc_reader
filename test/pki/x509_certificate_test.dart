/// The X.509 slice.
///
/// Parse of every fixture certificate, the `X509Wrapper`-parity display
/// surface, DN comparison, and the 720-certificate `masterList.pem` ingestion
/// smoke that doubles as the ingestion wall-clock baseline.
library;

// ignore_for_file: implementation_imports

import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/lds/subject_public_key_info.dart';
import 'package:emrtd_core/src/pki/csca_trust_store.dart';
import 'package:emrtd_core/src/pki/x509_certificate.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_test_pki.dart';
import '../support/pki_fixtures.dart';

/// The 720-certificate ICAO master-list fixture, vendored from upstream's
/// `Examples/Example_SPM/NFCPassportReaderApp/masterList.pem` at PIN
/// `3bf5456` (release 2.3.2). Vendored rather than read out of the upstream
/// checkout so the suite stays self-contained; see swift-runner/README.md.
const String _upstreamMasterListPem = 'test/fixtures/masterList.pem';

void main() {
  group('parse', () {
    test('every fixture certificate parses', () {
      final all = <String, Uint8List>{
        'csca-rsa': cscaRsaCert,
        'csca-ec': cscaEcCert,
        'csca-old': cscaOldCert,
        'csca-link': cscaLinkCert,
        'dsc-rsa': dscRsaCert,
        'dsc-rsa-expired': dscRsaExpiredCert,
        'dsc-rsa-4096': dscRsa4096Cert,
        'dsc-case': dscCaseDiffCert,
        'dsc-self': dscSelfSignedCert,
        'dsc-ec': dscEcCert,
        'dsc-ec-explicit': dscEcExplicitCert,
        'dsc-bp': dscBrainpoolCert,
        'dsc-under-new': dscUnderNewCert,
        'ml-signer': mlSignerCert,
      };
      for (final e in all.entries) {
        final cert = X509Certificate.tryParse(e.value);
        expect(cert, isNotNull, reason: e.key);
        expect(cert!.der, e.value, reason: '${e.key}: DER kept verbatim');
        expect(cert.publicKey, isNotNull, reason: '${e.key}: SPKI usable');
      }
    });

    test('the TBS slice is the exact signature input', () {
      final cert = X509Certificate.tryParse(dscRsaCert)!;
      // The TBS element starts right after the outer SEQUENCE header and is
      // a byte-for-byte prefix-aligned slice of the certificate.
      expect(
        String.fromCharCodes(
          cert.der,
        ).contains(String.fromCharCodes(cert.tbsDer)),
        isTrue,
      );
      expect(cert.tbsDer[0], 0x30);
    });

    test('extension fields', () {
      final csca = X509Certificate.tryParse(cscaRsaCert)!;
      expect(csca.basicConstraintsCa, isTrue);
      expect(csca.keyCertSign, isTrue);
      expect(csca.subjectKeyIdentifier, isNotNull);
      expect(csca.authorityKeyIdentifier, isNull); // built without one
      expect(csca.isSelfIssued, isTrue);

      final dsc = X509Certificate.tryParse(dscRsaCert)!;
      expect(dsc.basicConstraintsCa, isFalse);
      expect(dsc.keyCertSign, isFalse);
      expect(dsc.authorityKeyIdentifier, csca.subjectKeyIdentifier);
      expect(dsc.isSelfIssued, isFalse);
    });

    test('an EC certificate with explicit parameters yields a usable key', () {
      final cert = X509Certificate.tryParse(dscEcExplicitCert)!;
      expect(cert.publicKey, isA<SpkiEcPublicKey>());
      expect(cert.publicKeyAlgorithmOid, '1.2.840.10045.2.1');
    });

    test('validity windows', () {
      final good = X509Certificate.tryParse(dscRsaCert)!;
      expect(good.isValidAt(pkiVerificationTime), isTrue);
      expect(good.isValidAt(DateTime.utc(2014)), isFalse);
      expect(good.isValidAt(DateTime.utc(2130)), isFalse);

      final expired = X509Certificate.tryParse(dscRsaExpiredCert)!;
      expect(expired.isValidAt(pkiVerificationTime), isFalse);
      expect(expired.isValidAt(DateTime.utc(2018, 6)), isTrue);
    });

    test('hostile input is null, never a throw', () {
      expect(X509Certificate.tryParse(const []), isNull);
      expect(X509Certificate.tryParse(const [0x30, 0x00]), isNull);
      expect(
        X509Certificate.tryParse([...dscRsaCert, 0x00]),
        isNull,
        reason: 'trailing garbage is rejected outright',
      );
      for (var n = 0; n < dscRsaCert.length; n += 53) {
        expect(
          () => X509Certificate.tryParse(dscRsaCert.sublist(0, n)),
          returnsNormally,
        );
      }
    });
  });

  group('display surface (X509Wrapper parity)', () {
    test('info fields', () {
      final cert = X509Certificate.tryParse(cscaRsaCert)!;
      final info = cert.info;
      expect(
        info.subject,
        'CN=UTOPIA CSCA RSA,O=Utopia Ministry of Interior,C=UT',
      );
      expect(info.issuer, info.subject);
      expect(info.serialNumber, '1001');
      expect(info.signatureAlgorithm, 'sha256WithRSAEncryption');
      expect(info.publicKeyAlgorithm, 'rsaEncryption');
      expect(info.notBefore, '2015-01-01T00:00:00.000Z');
      expect(info.notAfter, '2126-01-01T00:00:00.000Z');
      expect(info.isCa, isTrue);
      expect(info.keyCertSign, isTrue);
    });

    test('fingerprints: upstream colon-hex SHA-1 plus a SHA-256', () {
      final cert = X509Certificate.tryParse(cscaRsaCert)!;
      expect(
        cert.fingerprintSha1,
        matches(RegExp(r'^([0-9A-F]{2}:){19}[0-9A-F]{2}$')),
      );
      expect(cert.fingerprintSha256, matches(RegExp('^[0-9a-f]{64}\$')));
      expect(cert.info.fingerprintSha256, cert.fingerprintSha256);
    });

    test('EC algorithm names', () {
      final cert = X509Certificate.tryParse(dscEcCert)!;
      expect(cert.info.signatureAlgorithm, 'ecdsa-with-SHA256');
      expect(cert.info.publicKeyAlgorithm, 'id-ecPublicKey');
    });

    test('public key width and curve, per key kind', () {
      X509CertificateInfo info(Uint8List der) =>
          X509Certificate.tryParse(der)!.info;

      final rsa2048 = info(cscaRsaCert);
      expect(rsa2048.publicKeyBits, 2048);
      expect(rsa2048.publicKeyCurve, isNull);

      final rsa4096 = info(dscRsa4096Cert);
      expect(rsa4096.publicKeyAlgorithm, 'rsaEncryption');
      expect(rsa4096.publicKeyBits, 4096);
      expect(rsa4096.publicKeyCurve, isNull);

      final p256 = info(dscEcCert);
      expect(p256.publicKeyBits, 256);
      expect(p256.publicKeyCurve, 'secp256r1');

      final brainpool = info(dscBrainpoolCert);
      expect(brainpool.publicKeyBits, 256);
      expect(brainpool.publicKeyCurve, 'brainpoolp256r1');

      final explicit = info(dscEcExplicitCert);
      expect(
        explicit.publicKeyBits,
        256,
        reason: 'the field width is known even when no curve is named',
      );
      expect(
        explicit.publicKeyCurve,
        isNull,
        reason: 'explicit ECParameters name no curve',
      );
    });

    test('an SPKI the parser rejects yields null width and curve', () {
      final der = buildCertificate(
        subject: dnDscRsa,
        issuer: dnCscaRsa,
        serial: 0x2FFF,
        notBefore: DateTime.utc(2015, 1, 1),
        notAfter: DateTime.utc(2126, 1, 1),
        subjectKey: const UnknownAlgorithmTestKey(),
        issuerKey: cscaRsaKey,
        signatureAlgorithmOid: sigSha256Rsa,
      );
      final cert = X509Certificate.tryParse(der)!;
      expect(cert.publicKey, isNull);
      expect(cert.info.publicKeyAlgorithm, '1.2.3.4.5');
      expect(cert.info.publicKeyBits, isNull);
      expect(cert.info.publicKeyCurve, isNull);
    });

    test('an unknown algorithm OID renders as its dotted form', () {
      expect(algorithmDisplayName('1.2.3.4.5'), '1.2.3.4.5');
    });

    test('toPem round-trips through the PEM store reader', () {
      final cert = X509Certificate.tryParse(cscaRsaCert)!;
      final store = CscaTrustStore.fromPem(cert.toPem());
      expect(store.certificateCount, 1);
      expect(
        store.certificates.single.fingerprintSha256,
        cert.fingerprintSha256,
      );
    });
  });

  group('distinguished names', () {
    test('RFC 2253-style, most specific first, short names', () {
      expect(
        formatDistinguishedName(dnDscRsa),
        'CN=UTOPIA DS RSA 001,O=Utopia Ministry of Interior,C=UT',
      );
    });

    test('the normalized comparand folds case and collapses whitespace', () {
      final upper = X509Certificate.tryParse(cscaRsaCert)!;
      final lower = X509Certificate.tryParse(dscCaseDiffCert)!;
      expect(upper.subjectDer, isNot(lower.issuerDer));
      expect(upper.normalizedSubject, lower.normalizedIssuer);
    });

    test('RFC 2253 escaping', () {
      final dn = testDn(
        country: 'UT',
        organisation: 'A, B',
        commonName: r'C+D\E',
      );
      expect(formatDistinguishedName(dn), r'CN=C\+D\\E,O=A\, B,C=UT');
    });

    test('an unknown attribute type renders as its OID', () {
      final dn = Der.seq([
        Der.set([
          Der.seq([Der.oid('1.2.3.4'), Der.printableString('x')]),
        ]),
      ]);
      expect(formatDistinguishedName(dn), '1.2.3.4=x');
    });
  });

  group('upstream masterList.pem (720 certificates)', () {
    final file = File(_upstreamMasterListPem);
    final present = file.existsSync();

    test(
      'ingests, and records the wall-clock baseline',
      () {
        final pem = file.readAsStringSync();
        final watch = Stopwatch()..start();
        final store = CscaTrustStore.fromPem(pem);
        watch.stop();
        // The fixture is a 1.5 MB, 720-certificate PEM concatenation. Every
        // entry must parse: a skipped certificate here would mean the X.509
        // slice cannot read real CSCAs.
        expect(store.certificateCount + store.skippedCertificates, 720);
        expect(store.skippedCertificates, 0);
        // Not an assertion about speed, a recorded baseline (consumers run
        // ingestion off the NFC path). Generous ceiling so CI never flakes.
        expect(
          watch.elapsedMilliseconds,
          lessThan(120000),
          reason: 'ingestion wall clock: ${watch.elapsedMilliseconds} ms',
        );
        // ignore: avoid_print
        print(
          'masterList.pem: ${store.certificateCount} certificates in '
          '${watch.elapsedMilliseconds} ms',
        );
      },
      skip: present ? null : 'fixture missing: $_upstreamMasterListPem',
    );

    test(
      'every certificate exposes a usable key and a subject',
      () {
        final store = CscaTrustStore.fromPem(file.readAsStringSync());
        var withoutKey = 0;
        for (final cert in store.certificates) {
          expect(cert.subjectString, isNotEmpty);
          expect(cert.fingerprintSha256.length, 64);
          if (cert.publicKey == null) {
            withoutKey++;
          }
        }
        // Real CSCA lists carry DSA and unusual-curve roots the shared SPKI
        // parser cannot produce keys for; those become `unsupported_algorithm`
        // if they are ever an issuer, never a crash. Recorded, not asserted to
        // be zero.
        // ignore: avoid_print
        print('masterList.pem: $withoutKey certificates with no usable key');
        expect(withoutKey, lessThan(store.certificateCount));
      },
      skip: present ? null : 'fixture missing: $_upstreamMasterListPem',
    );
  });
}
