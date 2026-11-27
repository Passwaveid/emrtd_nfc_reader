/// `Dg1Fields` unit tests. Unit tests, not conformance vectors: the
/// dual-runner vector suite pins upstream parity, and `Dg1Fields` has no
/// Swift counterpart. Specimen inputs are REUSED from
/// `conformance/vectors/dg1.json` (each case's `input.data` hex -> a parsed
/// [DataGroup1]), not duplicated; the note-j/MRV/deviation shapes are
/// Dart-only synthetics authored with [mrzCheckDigit].
///
/// Runs under `flutter test` from the package root (CI does exactly that).
library;

import 'dart:convert';
import 'dart:io';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter_test/flutter_test.dart';

/// The dg1.json vector suite, loaded once.
final List<Map<String, Object?>> _vectorCases = (() {
  final suite =
      jsonDecode(File('conformance/vectors/dg1.json').readAsStringSync())
          as Map<String, Object?>;
  return (suite['cases']! as List)
      .cast<Map>()
      .map((c) => c.cast<String, Object?>())
      .toList();
})();

/// Parses the `input.data` hex of the single vector case whose name starts
/// with [namePrefix].
DataGroup1 vectorDg1(String namePrefix) {
  final c = _vectorCases.singleWhere(
    (c) => (c['name']! as String).startsWith(namePrefix),
  );
  final hex = (c['input']! as Map)['data']! as String;
  final bytes = <int>[
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ];
  return DataGroup1(bytes);
}

/// Wraps an ASCII MRZ body in the DG1 TLV shell (`61 len 5F1F len body`):
/// single-byte lengths suffice for every MRZ shape (body ≤ 91).
DataGroup1 dg1FromBody(String body) {
  final bytes = body.codeUnits;
  return DataGroup1([
    0x61,
    bytes.length + 3,
    0x5F,
    0x1F,
    bytes.length,
    ...bytes,
  ]);
}

String _digit(String field) => '${mrzCheckDigit(field)}';

void main() {
  group('TD3 ERIKSSON specimen (P4 worked example)', () {
    final fields = Dg1Fields.from(vectorDg1('TD3 specimen'));

    test('every typed field', () {
      expect(fields.layout, Dg1Layout.td3);
      expect(fields.documentCode, 'PP');
      expect(fields.issuingState, 'UTO');
      expect(fields.primaryIdentifier, 'ERIKSSON');
      expect(fields.secondaryIdentifier, 'ANNA MARIA');
      expect(fields.documentNumber, 'L898902C3');
      expect(fields.nationality, 'UTO');
      expect(fields.dateOfBirth, '740812');
      expect(fields.sex, 'F');
      expect(fields.dateOfExpiry, '340415');
      expect(fields.optionalData, 'ZE184226B');
      expect(
        fields.mrz,
        'PPUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<'
        'L898902C36UTO7408122F3404159ZE184226B<<<<<16',
      );
    });

    test('all five flags true', () {
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isTrue);
      expect(fields.checkDigits.composite, isTrue);
    });
  });

  group('TD1 specimen (P5 I<UTO D23145890)', () {
    final fields = Dg1Fields.from(vectorDg1('TD1 specimen'));

    test('fields + layout', () {
      expect(fields.layout, Dg1Layout.td1);
      expect(fields.documentCode, 'I');
      expect(fields.issuingState, 'UTO');
      expect(fields.primaryIdentifier, 'ERIKSSON');
      expect(fields.secondaryIdentifier, 'ANNA MARIA');
      expect(fields.documentNumber, 'D23145890');
      expect(fields.nationality, 'UTO');
      expect(fields.dateOfBirth, '740812');
      expect(fields.sex, 'F');
      expect(fields.dateOfExpiry, '120415');
      // The all-filler optional-data concatenation strips to present-but-
      // empty, not null.
      expect(fields.optionalData, '');
    });

    test('flags: four live, optionalData layout-precluded', () {
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isNull);
      expect(fields.checkDigits.composite, isTrue);
    });
  });

  group('TD2 hand-built vector case', () {
    final fields = Dg1Fields.from(vectorDg1('TD2 hand-built'));

    test('fields + layout', () {
      expect(fields.layout, Dg1Layout.td2);
      expect(fields.documentCode, 'I');
      expect(fields.issuingState, 'UTO');
      expect(fields.primaryIdentifier, 'ERIKSSON');
      expect(fields.secondaryIdentifier, 'ANNA MARIA');
      expect(fields.documentNumber, 'D23145890');
      expect(fields.dateOfBirth, '740812');
      expect(fields.sex, 'F');
      expect(fields.dateOfExpiry, '120415');
      expect(fields.optionalData, '');
    });

    test('flags: four live, optionalData layout-precluded', () {
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isNull);
      expect(fields.checkDigits.composite, isTrue);
    });
  });

  group('field anomalies (vector reuse)', () {
    test('Brunei no-<< name -> secondaryIdentifier is empty, not null', () {
      final fields = Dg1Fields.from(vectorDg1('field-anomaly: name'));
      expect(fields.primaryIdentifier, 'ERIKSSONANNAMARIA');
      expect(fields.secondaryIdentifier, '');
      expect(fields.layout, Dg1Layout.td3);
    });

    test('Norwegian TD1 leading-filler optional data preserved', () {
      final fields = Dg1Fields.from(
        vectorDg1('field-anomaly: TD1 optional data'),
      );
      expect(fields.layout, Dg1Layout.td1);
      expect(fields.optionalData, '<1234567890');
      // No note-j (5F04 carries a real digit); plain document number.
      expect(fields.documentNumber, 'D23145890');
      expect(fields.checkDigits.documentNumber, isTrue);
      // The vector kept the specimen composite digit while changing the
      // optional data it covers; the advisory flag reports the mismatch.
      expect(fields.checkDigits.composite, isFalse);
    });

    test('personal-number digit slot carries < -> flag true (< matches 0)', () {
      final fields = Dg1Fields.from(
        vectorDg1('field-anomaly: personal-number check digit'),
      );
      expect(fields.optionalData, '');
      expect(fields.checkDigits.optionalData, isTrue);
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      // Stored composite digit is the specimen's; the all-filler optional
      // data changes the computation -> advisory false.
      expect(fields.checkDigits.composite, isFalse);
    });
  });

  group('non-UTF8 vector case (absent 53/5F1F keys)', () {
    test('from is total: null fields, null layout, all-null flags', () {
      final fields = Dg1Fields.from(vectorDg1('non-UTF8 field bytes'));
      expect(fields.mrz, isNull);
      expect(fields.layout, isNull);
      expect(fields.optionalData, isNull);
      expect(fields.checkDigits.documentNumber, isNull);
      expect(fields.checkDigits.dateOfBirth, isNull);
      expect(fields.checkDigits.dateOfExpiry, isNull);
      expect(fields.checkDigits.optionalData, isNull);
      expect(fields.checkDigits.composite, isNull);
      // Per-tag fields still extract.
      expect(fields.documentCode, 'PP');
      expect(fields.documentNumber, 'L898902C3');
      expect(fields.primaryIdentifier, 'ERIKSSON');
      expect(fields.dateOfBirth, '740812');
    });
  });

  group('nonstandard TD3-shaped bodies (mirroring the DG1 parser)', () {
    for (final prefix in ['89-byte body', '91-byte body']) {
      test('$prefix -> td3, fixed-offset fields intact, flags live', () {
        final fields = Dg1Fields.from(vectorDg1(prefix));
        expect(fields.layout, Dg1Layout.td3);
        expect(fields.documentCode, 'PP');
        expect(fields.documentNumber, 'L898902C3');
        expect(fields.primaryIdentifier, 'ERIKSSON');
        expect(fields.secondaryIdentifier, 'ANNA MARIA');
        expect(fields.optionalData, 'ZE184226B');
        expect(fields.checkDigits.documentNumber, isTrue);
        expect(fields.checkDigits.dateOfBirth, isTrue);
        expect(fields.checkDigits.dateOfExpiry, isTrue);
        expect(fields.checkDigits.optionalData, isTrue);
        expect(fields.checkDigits.composite, isTrue);
      });
    }
  });

  group('note-j extended document numbers (synthetics)', () {
    test('TD1 12-char document number: assembly, flag, splice', () {
      const fullDocNum = 'D23145890123'; // 12 chars, note-j territory
      final continuation = fullDocNum.substring(9) + _digit(fullDocNum);
      final optionalData1 = continuation.padRight(15, '<');
      final optionalData2 = 'ABC'.padRight(11, '<');
      final line1 = 'I<UTO${fullDocNum.substring(0, 9)}<$optionalData1';
      final dob = '740812${_digit('740812')}';
      final expiry = '120415${_digit('120415')}';
      final composite = _digit(
        line1.substring(5) + dob + expiry + optionalData2,
      );
      final line2 = '${dob}F${expiry}UTO$optionalData2$composite';
      final line3 = 'ERIKSSON<<ANNA<MARIA'.padRight(30, '<');
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2$line3'));

      expect(fields.layout, Dg1Layout.td1);
      expect(fields.documentNumber, fullDocNum);
      // Transferred digit (continuation's last char) vs the digit of the
      // complete document number.
      expect(fields.checkDigits.documentNumber, isTrue);
      // Continuation + its one separator filler spliced out of the
      // concatenated optional data; the remaining leading fillers are data.
      expect(fields.optionalData, '${'<' * 10}ABC');
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.composite, isTrue);
    });

    test('TD2 11-char document number: assembly, flag, splice', () {
      const fullDocNum = 'D2314589012'; // 11 chars
      final continuation = fullDocNum.substring(9) + _digit(fullDocNum);
      final optionalData = '$continuation<QR'.padRight(7, '<');
      final line1 = 'I<UTO${'ERIKSSON<<ANNA<MARIA'.padRight(31, '<')}';
      final dob = '740812${_digit('740812')}';
      final expiry = '120415${_digit('120415')}';
      final composite = _digit(
        '${fullDocNum.substring(0, 9)}<$dob$expiry$optionalData',
      );
      final line2 =
          '${fullDocNum.substring(0, 9)}<UTO${dob}F$expiry$optionalData'
          '$composite';
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2'));

      expect(fields.layout, Dg1Layout.td2);
      expect(fields.documentNumber, fullDocNum);
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.optionalData, 'QR');
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.composite, isTrue);
    });

    test('guard failure (5F04 == <, all-filler 53) -> plain extraction', () {
      final line1 = 'I<UTOD23145890<${'<' * 15}';
      final dob = '740812${_digit('740812')}';
      final expiry = '120415${_digit('120415')}';
      final composite = _digit(line1.substring(5) + dob + expiry + '<' * 11);
      final line2 = '${dob}F${expiry}UTO${'<' * 11}$composite';
      final line3 = 'ERIKSSON<<ANNA<MARIA'.padRight(30, '<');
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2$line3'));

      expect(fields.documentNumber, 'D23145890');
      expect(fields.optionalData, '');
      // The `<`-matches-0 rule on the positional slot: stored `<` vs a
      // computed digit of 7 -> false, not null.
      expect(fields.checkDigits.documentNumber, isFalse);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.composite, isTrue);
    });
  });

  group('MRV layouts (synthetics)', () {
    final docNum = 'L898902C3${_digit('L898902C3')}';
    final dob = '740812${_digit('740812')}';

    test('MRV-A: V code at 88 -> mrvA, re-sliced optional data', () {
      final line1 = 'V<UTO${'ERIKSSON<<ANNA<MARIA'.padRight(39, '<')}';
      final expiry = '340415${_digit('340415')}';
      final line2 =
          '${docNum}UTO${dob}F$expiry${'HOTEL<INTL'.padRight(16, '<')}';
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2'));

      expect(fields.layout, Dg1Layout.mrvA);
      expect(fields.documentCode, 'V');
      expect(fields.documentNumber, 'L898902C3');
      // [72,88) of 5F1F: the parser's 53/5F02/5F07 slots are one
      // contiguous optional-data field on visas.
      expect(fields.optionalData, 'HOTEL<INTL');
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isNull);
      expect(fields.checkDigits.composite, isNull);
    });

    test('MRV-B: V code at 72 -> mrvB, re-sliced optional data', () {
      final line1 = 'V<UTO${'ERIKSSON<<ANNA<MARIA'.padRight(31, '<')}';
      final expiry = '120415${_digit('120415')}';
      final line2 = '${docNum}UTO${dob}F$expiry${'XY12'.padRight(8, '<')}';
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2'));

      expect(fields.layout, Dg1Layout.mrvB);
      expect(fields.documentCode, 'V');
      expect(fields.documentNumber, 'L898902C3');
      expect(fields.optionalData, 'XY12'); // [64,72) of 5F1F
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isNull);
      expect(fields.checkDigits.composite, isNull);
    });

    test('V code at 89 -> td3, not MRV', () {
      final line1 = 'V<UTO${'ERIKSSON<<ANNA<MARIA'.padRight(39, '<')}';
      final expiry = '340415${_digit('340415')}';
      final line2 =
          '${docNum}UTO${dob}F$expiry${'HOTEL<INTL'.padRight(16, '<')}';
      final fields = Dg1Fields.from(dg1FromBody('$line1$line2<'));

      expect(fields.layout, Dg1Layout.td3);
      expect(fields.documentCode, 'V');
      // TD3 tag slicing: 53 = [72,86), trailing-stripped.
      expect(fields.optionalData, 'HOTEL<INTL');
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfBirth, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      // TD3 reads digit slots at [86]/[87], which hold visa optional-data
      // fillers here: stored `<` vs non-zero computed digits -> false.
      expect(fields.checkDigits.optionalData, isFalse);
      expect(fields.checkDigits.composite, isFalse);
    });
  });

  group('flag degradation synthetics', () {
    final specimen = Dg1Fields.from(vectorDg1('TD3 specimen')).mrz!;

    test('deviation wrong check digit -> flag false', () {
      // P3 §7.3.4.3 id-Deviation-MRZ-WrongCheckDigit: bump the stored DOB
      // digit ([63]) off by one.
      final body = specimen.replaceRange(63, 64, '3');
      final fields = Dg1Fields.from(dg1FromBody(body));
      expect(fields.checkDigits.dateOfBirth, isFalse);
      // The composite span covers the altered digit slot -> false too.
      expect(fields.checkDigits.composite, isFalse);
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isTrue);
    });

    test('out-of-charset char in a digit slice -> flag null', () {
      // '!' in the DOB slice [57,63): mrzCheckDigit throws (caught -> null)
      // for the DOB flag and the composite whose span covers it.
      final body = specimen.replaceRange(57, 58, '!');
      final fields = Dg1Fields.from(dg1FromBody(body));
      expect(fields.dateOfBirth, '!40812'); // verbatim, no validation
      expect(fields.checkDigits.dateOfBirth, isNull);
      expect(fields.checkDigits.composite, isNull);
      expect(fields.checkDigits.documentNumber, isTrue);
      expect(fields.checkDigits.dateOfExpiry, isTrue);
      expect(fields.checkDigits.optionalData, isTrue);
    });
  });
}
