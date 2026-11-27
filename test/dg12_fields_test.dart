/// `Dg12Fields` unit tests, the `Dg11Fields`/`Dg1Fields` pattern: specimen
/// inputs REUSED from `conformance/vectors/dg12.json`, the rest Dart-only
/// synthetics. The typed layer has no Swift counterpart.
///
/// Runs under `flutter test` from the package root (CI does exactly that).
library;

import 'dart:convert';
import 'dart:io';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter_test/flutter_test.dart';

/// The dg12.json vector suite, loaded once.
final List<Map<String, Object?>> _vectorCases = (() {
  final suite =
      jsonDecode(File('conformance/vectors/dg12.json').readAsStringSync())
          as Map<String, Object?>;
  return (suite['cases']! as List)
      .cast<Map>()
      .map((c) => c.cast<String, Object?>())
      .toList();
})();

List<int> _hex(String hex) => [
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
];

DataGroup12 vectorDg12(String namePrefix) {
  final c = _vectorCases.firstWhere(
    (c) => (c['name']! as String).startsWith(namePrefix),
  );
  return DataGroup12(_hex((c['input']! as Map)['data']! as String));
}

/// Minimal DG12 shell: `6C { 5C <taglist>, <elements> }` (the tag list is
/// never validated).
DataGroup12 dg12With(List<List<int>> elements) {
  final body = <int>[0x5C, 0x01, 0x5F, for (final e in elements) ...e];
  return DataGroup12([0x6C, ..._len(body.length), ...body]);
}

List<int> _len(int n) => n < 0x80 ? [n] : [0x81, n];

List<int> _element(List<int> tag, String value) =>
    _elementBytes(tag, utf8.encode(value));

List<int> _elementBytes(List<int> tag, List<int> value) => [
  ...tag,
  ..._len(value.length),
  ...value,
];

const _issuingAuthority = [0x5F, 0x19];
const _dateOfIssue = [0x5F, 0x26];
const _frontImage = [0x5F, 0x1D];
const _rearImage = [0x5F, 0x1E];
const _personalizationTime = [0x5F, 0x55];
const _serial = [0x5F, 0x56];

/// The JFIF bytes the DG2/DG7 fixtures use.
const _jpeg = [
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, //
  0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
];
const _jp2 = [
  0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, 0x87, 0x0a, //
];
const _codestream = [0xff, 0x4f, 0xff, 0x51, 0x00, 0x01, 0xff, 0xd9];

void main() {
  group('full specimen (vector reuse)', () {
    final dg12 = vectorDg12('full specimen');
    final fields = Dg12Fields.from(dg12);

    test('scalars, with the one ICAO-full rename', () {
      expect(fields.issuingAuthority, 'UTOPIAN PASSPORT AUTHORITY');
      expect(fields.dateOfIssue, '20150315');
      expect(fields.endorsementsOrObservations, 'SEE PAGE 5');
      expect(fields.taxOrExitRequirements, 'EXIT TAX PAID');
      expect(fields.personalizationTime, '20150315123045');
      // Upstream spells it `...Nr` on the ported class; the typed layer spells
      // it out.
      expect(fields.personalizationDeviceSerialNumber, 'PERSO-DEVICE-0042');
      expect(
        fields.personalizationDeviceSerialNumber,
        dg12.personalizationDeviceSerialNr,
      );
    });

    test('other persons are split name records, in file order', () {
      expect(fields.otherPersons, [
        (primaryIdentifier: 'ERIKSSON', secondaryIdentifier: 'ANNA MARIA'),
        (primaryIdentifier: 'SMITH', secondaryIdentifier: 'JOHN'),
      ]);
    });

    test('both images travel with their sniffed formats', () {
      expect(fields.frontImage, dg12.frontImage);
      expect(fields.frontImageFormat, FaceImageFormat.jpeg);
      expect(fields.rearImage, dg12.rearImage);
      expect(fields.rearImageFormat, FaceImageFormat.jp2);
    });
  });

  group('image-format sniffing', () {
    test('each recognized prefix maps to its member', () {
      final fields = Dg12Fields.from(
        dg12With([
          _elementBytes(_frontImage, _jp2),
          _elementBytes(_rearImage, _codestream),
        ]),
      );
      expect(fields.frontImageFormat, FaceImageFormat.jp2);
      expect(fields.rearImageFormat, FaceImageFormat.jpeg2000Codestream);
    });

    test(
      'unrecognized bytes and an empty image sniff to null, never throw',
      () {
        final fields = Dg12Fields.from(
          dg12With([
            _elementBytes(_frontImage, const [0xAA, 0xBB, 0xCC]),
            _elementBytes(_rearImage, const []),
          ]),
        );
        expect(fields.frontImage, isNotNull);
        expect(fields.frontImageFormat, isNull);
        expect(fields.rearImage, isNotNull);
        expect(fields.rearImageFormat, isNull);
      },
    );

    test('an Exif JPEG sniffs to null (the DG2 JFIF-only rule, inherited)', () {
      final fields = Dg12Fields.from(
        dg12With([
          _elementBytes(_frontImage, const [
            0xff,
            0xd8,
            0xff,
            0xe1,
            0x00,
            0x08,
            0xff,
            0xd9,
          ]),
        ]),
      );
      expect(fields.frontImageFormat, isNull);
    });

    test('an absent image has a null format, not a sniffed one', () {
      final fields = Dg12Fields.from(
        dg12With([_element(_issuingAuthority, 'AUTHORITY')]),
      );
      expect(fields.frontImage, isNull);
      expect(fields.frontImageFormat, isNull);
      expect(fields.rearImage, isNull);
      expect(fields.rearImageFormat, isNull);
    });
  });

  group('dates are opaque', () {
    test('the BCD expansion and its 4-byte quirks arrive verbatim', () {
      expect(
        Dg12Fields.from(vectorDg12('5F26: a 4-byte BCD')).dateOfIssue,
        '20150315',
      );
      expect(
        Dg12Fields.from(vectorDg12('FOUR ASCII digits')).dateOfIssue,
        '32303135',
      );
      expect(
        Dg12Fields.from(vectorDg12('non-digit nibbles')).dateOfIssue,
        'ABCDEF01',
      );
    });

    test('P10 partial dates pass through untouched', () {
      expect(
        Dg12Fields.from(
          dg12With([_element(_dateOfIssue, '20150000')]),
        ).dateOfIssue,
        '20150000',
      );
    });

    test('a 14-char ASCII 5F55 passes through verbatim', () {
      final fields = Dg12Fields.from(
        dg12With([_element(_personalizationTime, '20150315123045')]),
      );
      expect(fields.personalizationTime, '20150315123045');
    });

    test('a BCD 5F55 is null, not repaired by the typed layer', () {
      final fields = Dg12Fields.from(vectorDg12('a BCD-encoded 5F55'));
      expect(fields.personalizationTime, isNull);
    });
  });

  group('totality (the Dg1Fields contract)', () {
    test('a DG12 whose every element is absent yields an all-null value', () {
      final fields = Dg12Fields.from(
        dg12With([
          _element([0x5F, 0x02], 'IGNORED'),
        ]),
      );
      expect(fields.issuingAuthority, isNull);
      expect(fields.dateOfIssue, isNull);
      expect(fields.otherPersons, isEmpty);
      expect(fields.endorsementsOrObservations, isNull);
      expect(fields.taxOrExitRequirements, isNull);
      expect(fields.frontImage, isNull);
      expect(fields.frontImageFormat, isNull);
      expect(fields.rearImage, isNull);
      expect(fields.rearImageFormat, isNull);
      expect(fields.personalizationTime, isNull);
      expect(fields.personalizationDeviceSerialNumber, isNull);
    });

    test('undecodable element bytes degrade to null, never throw', () {
      final fields = Dg12Fields.from(
        dg12With([
          _elementBytes(_serial, const [0xFF, 0xFE]),
          _elementBytes(_frontImage, _jpeg),
          _element(_issuingAuthority, 'AUTHORITY'),
        ]),
      );
      expect(fields.personalizationDeviceSerialNumber, isNull);
      expect(fields.issuingAuthority, 'AUTHORITY');
      expect(fields.frontImageFormat, FaceImageFormat.jpeg);
    });

    test('a malformed A0 interior leaves otherPersons empty', () {
      final fields = Dg12Fields.from(vectorDg12('malformed A0 interior'));
      expect(fields.otherPersons, isEmpty);
      expect(fields.issuingAuthority, 'AUTHORITY');
    });
  });
}
