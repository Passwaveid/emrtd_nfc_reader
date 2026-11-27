/// `Dg11Fields` unit tests. Unit tests, not conformance vectors: the
/// dual-runner suite pins upstream parity on the *parser*, and the typed
/// layer has no Swift counterpart (the `Dg1Fields` pattern). Specimen inputs
/// are REUSED from `conformance/vectors/dg11.json` (each case's `input.data`
/// hex -> a parsed [DataGroup11]), not duplicated; the rest are Dart-only
/// synthetics.
///
/// Runs under `flutter test` from the package root (CI does exactly that).
library;

import 'dart:convert';
import 'dart:io';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter_test/flutter_test.dart';

/// The dg11.json vector suite, loaded once.
final List<Map<String, Object?>> _vectorCases = (() {
  final suite =
      jsonDecode(File('conformance/vectors/dg11.json').readAsStringSync())
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

/// Parses the `input.data` hex of the first vector case whose name starts
/// with [namePrefix].
DataGroup11 vectorDg11(String namePrefix) {
  final c = _vectorCases.firstWhere(
    (c) => (c['name']! as String).startsWith(namePrefix),
  );
  return DataGroup11(_hex((c['input']! as Map)['data']! as String));
}

/// Minimal DG11 shell: `6B { 5C <taglist>, <elements> }`. The tag list is
/// never validated, so a one-byte placeholder is enough.
DataGroup11 dg11With(List<List<int>> elements) {
  final body = <int>[0x5C, 0x01, 0x5F, for (final e in elements) ...e];
  return DataGroup11([0x6B, ..._len(body.length), ...body]);
}

List<int> _len(int n) => n < 0x80 ? [n] : [0x81, n];

List<int> _element(List<int> tag, String value) {
  final bytes = utf8.encode(value);
  return [...tag, ..._len(bytes.length), ...bytes];
}

List<int> _elementBytes(List<int> tag, List<int> value) => [
  ...tag,
  ..._len(value.length),
  ...value,
];

const _fullName = [0x5F, 0x0E];
const _personalNumber = [0x5F, 0x10];
const _placeOfBirth = [0x5F, 0x11];
const _dateOfBirth = [0x5F, 0x2B];
const _address = [0x5F, 0x42];
const _tdNumbers = [0x5F, 0x17];
const _proofOfCitizenship = [0x5F, 0x16];

void main() {
  group('full specimen (vector reuse)', () {
    final fields = Dg11Fields.from(vectorDg11('full specimen'));

    test('name split follows the Dg1Fields rules', () {
      expect(fields.primaryIdentifier, 'ERIKSSON');
      expect(fields.secondaryIdentifier, 'ANNA MARIA');
    });

    test('other names are split records, in file order', () {
      expect(fields.otherNames, [
        (primaryIdentifier: 'SMITH', secondaryIdentifier: 'JANE ELIZABETH'),
        (primaryIdentifier: 'ERIKSSON', secondaryIdentifier: 'ANNA'),
      ]);
    });

    test('`<`-separated components split, scalars stay verbatim', () {
      expect(fields.placeOfBirth, ['STOCKHOLM', 'SWEDEN']);
      expect(fields.permanentAddress, ['123', 'MAIN', 'ST', 'UTOPIA', 'CITY']);
      expect(fields.otherTravelDocumentNumbers, ['AB1234567', 'CD7654321']);
      expect(fields.personalNumber, '19203040');
      expect(fields.fullDateOfBirth, '19740812');
      expect(fields.telephone, '+46812345678');
      expect(fields.profession, 'ENGINEER');
      expect(fields.title, 'DR');
      expect(fields.personalSummary, 'SEE ATTACHED');
      expect(fields.custodyInfo, 'MOTHER');
    });
  });

  group('5F16 is omitted from the typed layer', () {
    test('a proof-of-citizenship value never surfaces here', () {
      final dg11 = vectorDg11('5F16 carries a JPEG');
      // The ported class carries it (garbage-or-null by construction)...
      expect(dg11.proofOfCitizenship, isNull);
      // ...and Dg11Fields has no such field at all: the whole value is
      // null-fielded, which is what the type below asserts by compiling.
      final fields = Dg11Fields.from(dg11);
      expect(fields.primaryIdentifier, isNull);
      expect(fields.otherNames, isEmpty);
    });
  });

  group('name-split edge shapes', () {
    test('no `<<` separator -> secondaryIdentifier is empty, not null '
        '(the Brunei shape)', () {
      final fields = Dg11Fields.from(
        dg11With([_element(_fullName, 'ERIKSSONANNAMARIA')]),
      );
      expect(fields.primaryIdentifier, 'ERIKSSONANNAMARIA');
      expect(fields.secondaryIdentifier, '');
    });

    test(
      'trailing fillers stripped, embedded `<` -> space, first `<<` wins',
      () {
        final fields = Dg11Fields.from(
          dg11With([_element(_fullName, 'DE<LA<CRUZ<<MARIA<<JOSE<<<<<<')]),
        );
        expect(fields.primaryIdentifier, 'DE LA CRUZ');
        expect(fields.secondaryIdentifier, 'MARIA  JOSE');
      },
    );

    test('non-Latin names round-trip through the split (P10 note)', () {
      final fields = Dg11Fields.from(
        dg11With([_element(_fullName, 'МЮЛЛЕР<<ХАНС')]),
      );
      expect(fields.primaryIdentifier, 'МЮЛЛЕР');
      expect(fields.secondaryIdentifier, 'ХАНС');
    });

    test('an all-filler name collapses to two empty strings, never null', () {
      final fields = Dg11Fields.from(dg11With([_element(_fullName, '<<<<')]));
      expect(fields.primaryIdentifier, '');
      expect(fields.secondaryIdentifier, '');
    });
  });

  group('component splits preserve empties (the Dg1Fields rules)', () {
    test('leading, embedded and trailing empty segments survive', () {
      final fields = Dg11Fields.from(
        dg11With([
          _element(_placeOfBirth, '<CITY<<REGION<'),
          _element(_address, 'ONLY'),
        ]),
      );
      expect(fields.placeOfBirth, ['', 'CITY', '', 'REGION', '']);
      expect(fields.permanentAddress, ['ONLY']);
    });

    test('an absent component field is null, an empty one is [\'\']', () {
      final fields = Dg11Fields.from(dg11With([_element(_tdNumbers, '')]));
      expect(fields.otherTravelDocumentNumbers, ['']);
      expect(fields.placeOfBirth, isNull);
      expect(fields.permanentAddress, isNull);
    });

    test('personalNumber keeps its fillers (P10: free-form, no strip)', () {
      final fields = Dg11Fields.from(
        dg11With([_element(_personalNumber, '1234<<<')]),
      );
      expect(fields.personalNumber, '1234<<<');
    });
  });

  group('dates are opaque', () {
    test('8 ASCII digits pass through', () {
      final fields = Dg11Fields.from(
        dg11With([_element(_dateOfBirth, '19740812')]),
      );
      expect(fields.fullDateOfBirth, '19740812');
    });

    test(
      'P10 partial dates (00 month/day, 0000 year) pass through untouched',
      () {
        expect(
          Dg11Fields.from(
            dg11With([_element(_dateOfBirth, '19740000')]),
          ).fullDateOfBirth,
          '19740000',
        );
        expect(
          Dg11Fields.from(
            dg11With([_element(_dateOfBirth, '00000812')]),
          ).fullDateOfBirth,
          '00000812',
        );
      },
    );

    test('the BCD expansion arrives verbatim from the parser', () {
      final fields = Dg11Fields.from(vectorDg11('4-byte BCD date of birth'));
      expect(fields.fullDateOfBirth, '19870315');
    });
  });

  group('totality (the Dg1Fields contract)', () {
    test('a DG11 whose every element is absent yields an all-null value', () {
      // One unknown tag keeps the do-while walk legal; nothing is assigned.
      final fields = Dg11Fields.from(
        dg11With([
          _element([0x5F, 0x01], 'IGNORED'),
        ]),
      );
      expect(fields.primaryIdentifier, isNull);
      expect(fields.secondaryIdentifier, isNull);
      expect(fields.otherNames, isEmpty);
      expect(fields.personalNumber, isNull);
      expect(fields.fullDateOfBirth, isNull);
      expect(fields.placeOfBirth, isNull);
      expect(fields.permanentAddress, isNull);
      expect(fields.telephone, isNull);
      expect(fields.profession, isNull);
      expect(fields.title, isNull);
      expect(fields.personalSummary, isNull);
      expect(fields.otherTravelDocumentNumbers, isNull);
      expect(fields.custodyInfo, isNull);
    });

    test('undecodable element bytes degrade to null, never throw', () {
      final fields = Dg11Fields.from(
        dg11With([
          _elementBytes(_fullName, const [0xFF, 0xFE]),
          _elementBytes(_proofOfCitizenship, const [0xFF, 0xD8, 0xFF, 0xE0]),
          _element(_title, 'DR'),
        ]),
      );
      expect(fields.primaryIdentifier, isNull);
      expect(fields.title, 'DR');
    });
  });
}

const _title = [0x5F, 0x14];
