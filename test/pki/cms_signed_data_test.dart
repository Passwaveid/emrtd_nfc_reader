/// The CMS `SignedData` model.
///
/// Field extraction, the `A0`->`31` slice's byte-exactness, attribute
/// accessors, BER indefinite lengths, and totality on hostile input.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/lds/sod.dart';
import 'package:emrtd_core/src/pki/cms_signed_data.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_fixtures.dart';
import '../support/emrtd_test_pki.dart';
import '../support/pki_fixtures.dart';

CmsSignedData _parse(Uint8List sodFile) {
  final outcome = CmsSignedData.parse(SOD(sodFile).pkcs7CertificateData);
  expect(
    outcome,
    isA<CmsParsed>(),
    reason: outcome is CmsMalformed ? outcome.reason : '',
  );
  return (outcome as CmsParsed).data;
}

void main() {
  group('field extraction', () {
    test('the baseline SOD', () {
      final cms = _parse(sodRsaSha256);
      expect(cms.version, 3);
      expect(cms.eContentType, oidLdsSecurityObject);
      expect(cms.digestAlgorithmOids, ['2.16.840.1.101.3.4.2.1']);
      expect(cms.eContent, isNotNull);
      expect(cms.certificates.length, 1);
      expect(cms.certificates.single, dscRsaCert);
      expect(cms.signerInfos.length, 1);

      final si = cms.signerInfos.single;
      expect(si.version, 1);
      expect(si.digestAlgorithmOid, '2.16.840.1.101.3.4.2.1');
      expect(si.signatureAlgorithmOid, '1.2.840.113549.1.1.11');
      expect(si.signature.length, 256); // RSA-2048
      expect(si.signerId, isA<CmsIssuerAndSerial>());
      expect(
        (si.signerId as CmsIssuerAndSerial).serialNumber,
        BigInt.from(0x2001),
      );
      expect((si.signerId as CmsIssuerAndSerial).issuerDer, dnCscaRsa);
    });

    test('the eContent is the LDS security object', () {
      final cms = _parse(sodRsaSha256);
      // The hash oracle reads exactly these bytes off `SOD`; both paths must
      // agree.
      expect(cms.eContent, SOD(sodRsaSha256).getEncapsulatedContent());
    });

    test('PSS parameters travel as raw DER on the SignerInfo', () {
      final cms = _parse(sodRsaPssSha384);
      final si = cms.signerInfos.single;
      expect(si.signatureAlgorithmOid, '1.2.840.113549.1.1.10');
      expect(si.signatureAlgorithmParameters, pssParameters('SHA384'));
    });

    test('an ECDSA SignerInfo carries no signature parameters', () {
      final si = _parse(sodEcdsaP256).signerInfos.single;
      expect(si.signatureAlgorithmOid, '1.2.840.10045.4.3.2');
      expect(si.signatureAlgorithmParameters, isNull);
    });
  });

  group('signed attributes', () {
    test('the A0->31 view is the raw slice with one byte swapped', () {
      final si = _parse(sodRsaSha256).signerInfos.single;
      final raw = si.signedAttributesDer!;
      final verification = si.signedAttributesForVerification!;
      expect(raw[0], 0xA0);
      expect(verification[0], 0x31);
      expect(verification.length, raw.length);
      expect(
        verification.sublist(1),
        raw.sublist(1),
        reason: 'nothing but the tag byte may change',
      );
    });

    test('attribute accessors', () {
      final si = _parse(sodRsaSha256).signerInfos.single;
      expect(si.signedAttributes.length, 2);
      expect(si.contentTypeAttribute, oidLdsSecurityObject);
      expect(si.messageDigestAttribute, hasLength(32));
      expect(si.attribute('1.2.3.4'), isNull);
    });

    test('a mismatched content-type attribute is modeled, not judged', () {
      final si = _parse(sodContentTypeAttrMismatch).signerInfos.single;
      expect(si.contentTypeAttribute, oidCscaMasterList);
      expect(si.contentTypeAttribute, isNot(oidLdsSecurityObject));
    });

    test('an absent signedAttrs is null on both accessors', () {
      final si = _parse(sodNoSignedAttributes).signerInfos.single;
      expect(si.signedAttributesDer, isNull);
      expect(si.signedAttributesForVerification, isNull);
      expect(si.contentTypeAttribute, isNull);
      expect(si.messageDigestAttribute, isNull);
    });

    test(
      'an indefinite-length signedAttrs is re-headered as a definite SET',
      () {
        // Hand-built: the byte swap cannot fix a `0x80` length, so the model
        // rebuilds the SET over the attributes' original encodings, in order.
        final attrs = [
          Der.seq([
            Der.oid(oidContentTypeAttribute),
            Der.set([Der.oid(oidLdsSecurityObject)]),
          ]),
          Der.seq([
            Der.oid(oidMessageDigestAttribute),
            Der.set([Der.octetString(List<int>.filled(32, 7))]),
          ]),
        ];
        final indefinite = Der.indefinite(0xA0, [for (final a in attrs) ...a]);
        final si = CmsSignedData.tryParse(
          Der.seq([
            Der.oid(oidSignedData),
            Der.explicit(
              0,
              Der.seq([
                Der.int32(3),
                Der.set([
                  Der.seq([Der.oid('2.16.840.1.101.3.4.2.1'), Der.nul()]),
                ]),
                Der.seq([
                  Der.oid(oidLdsSecurityObject),
                  Der.explicit(0, Der.octetString(const [1, 2, 3])),
                ]),
                Der.set([
                  Der.seq([
                    Der.int32(1),
                    Der.seq([dnCscaRsa, Der.int32(1)]),
                    Der.seq([Der.oid('2.16.840.1.101.3.4.2.1'), Der.nul()]),
                    indefinite,
                    Der.seq([Der.oid('1.2.840.113549.1.1.11'), Der.nul()]),
                    Der.octetString(const [0xAA]),
                  ]),
                ]),
              ]),
            ),
          ]),
        )!.signerInfos.single;
        final rebuilt = si.signedAttributesForVerification!;
        expect(rebuilt[0], 0x31);
        expect(rebuilt.sublist(2), Der.setOf(attrs).sublist(2));
        expect(si.contentTypeAttribute, oidLdsSecurityObject);
      },
    );
  });

  group('BER and shape tolerance', () {
    test('an indefinite-length CMS parses to the same model', () {
      // A BER-encoded SOD *file* never reaches this layer: the shipped `SOD`
      // constructor rejects indefinite lengths (as upstream's does, and
      // unchanged), so the model is pinned on the CMS blob directly. BER
      // tolerance is what the master-list path needs.
      final definite = (CmsSignedData.parse(cmsRsaSha256) as CmsParsed).data;
      final indefinite =
          (CmsSignedData.parse(cmsIndefiniteLengths) as CmsParsed).data;
      expect(indefinite.eContentType, definite.eContentType);
      expect(indefinite.eContent, definite.eContent);
      expect(indefinite.certificates, definite.certificates);
      expect(
        indefinite.signerInfos.single.signature,
        definite.signerInfos.single.signature,
      );
    });

    test('a bare SignedData SEQUENCE is accepted, as d2i_PKCS7_bio does', () {
      final wrapped = SOD(sodRsaSha256).pkcs7CertificateData;
      final inner = Der.seq([
        Der.int32(3),
        Der.set([
          Der.seq([Der.oid('2.16.840.1.101.3.4.2.1'), Der.nul()]),
        ]),
        Der.seq([
          Der.oid(oidLdsSecurityObject),
          Der.explicit(0, Der.octetString(const [1])),
        ]),
        Der.set([
          Der.seq([
            Der.int32(1),
            Der.seq([dnCscaRsa, Der.int32(1)]),
            Der.seq([Der.oid('2.16.840.1.101.3.4.2.1'), Der.nul()]),
            Der.seq([Der.oid('1.2.840.113549.1.1.11'), Der.nul()]),
            Der.octetString(const [0xAA]),
          ]),
        ]),
      ]);
      expect(CmsSignedData.tryParse(inner), isNotNull);
      expect(CmsSignedData.tryParse(wrapped), isNotNull);
    });

    test('a certless SignedData models an empty certificate set', () {
      final cms = _parse(sodCertless);
      expect(cms.certificates, isEmpty);
      expect(cms.signerInfos, hasLength(1));
    });
  });

  group('totality', () {
    test('non-CMS input reports a reason', () {
      expect(CmsSignedData.parse(const [1, 2, 3]), isA<CmsMalformed>());
      expect(CmsSignedData.parse(const []), isA<CmsMalformed>());
      final wrongType = CmsSignedData.parse(
        Der.seq([
          Der.oid('1.2.840.113549.1.7.1'), // id-data, not id-signedData
          Der.explicit(0, Der.octetString(const [1])),
        ]),
      );
      expect(wrongType, isA<CmsMalformed>());
      expect((wrongType as CmsMalformed).reason, contains('id-signedData'));
    });

    test('the dummy-signature fixture SOD is malformed here, not a crash', () {
      // `emrtd_fixtures.sodHex` carries a two-element stand-in SignerInfo,
      // fine for the hash oracle, unusable as a CMS signature.
      final outcome = CmsSignedData.parse(SOD(hxSod).pkcs7CertificateData);
      expect(outcome, isA<CmsMalformed>());
    });

    test('every truncation of a real CMS returns without throwing', () {
      for (var n = 0; n < cmsRsaSha256.length; n += 41) {
        expect(
          () => CmsSignedData.parse(Uint8List.sublistView(cmsRsaSha256, 0, n)),
          returnsNormally,
        );
      }
      expect(CmsSignedData.parse(cmsTruncated), isA<CmsMalformed>());
    });
  });
}

/// The fixture SOD file, for the dummy-SignerInfo case above.
final Uint8List hxSod = Uint8List.fromList([
  for (var i = 0; i < sodHex.length; i += 2)
    int.parse(sodHex.substring(i, i + 2), radix: 16),
]);
