import 'package:emrtd_core_example/mrz_input.dart';
import 'package:flutter_test/flutter_test.dart';

import 'specimen.dart';

void main() {
  group('MrzInput.parse', () {
    MrzInput parse(String doc, String dob, String expiry) => MrzInput.parse(
      documentNumber: doc,
      dateOfBirth: dob,
      dateOfExpiry: expiry,
    );

    Matcher throwsMrz(MrzField field, [MrzErrorReason? reason]) => throwsA(
      isA<MrzInputError>()
          .having((e) => e.field, 'field', field)
          .having((e) => reason == null ? reason : e.reason, 'reason', reason),
    );

    test('the specimen composes the ICAO Appendix D key', () {
      expect(parse('L898902C', '690806', '940623').mrzKey, specimenMrzKey);
    });

    test('lowercase is uppercased', () {
      expect(parse('l898902c', '690806', '940623').mrzKey, specimenMrzKey);
    });

    test('surrounding whitespace on every field is trimmed', () {
      expect(
        parse(' L898902C ', '  690806', '940623  ').mrzKey,
        specimenMrzKey,
      );
    });

    test('an empty document number is rejected', () {
      expect(
        () => parse('', '690806', '940623'),
        throwsMrz(MrzField.documentNumber, MrzErrorReason.empty),
      );
    });

    test('a whitespace-only document number is rejected', () {
      expect(
        () => parse('   ', '690806', '940623'),
        throwsMrz(MrzField.documentNumber, MrzErrorReason.empty),
      );
    });

    test('a nine-character document number is not padded', () {
      expect(
        parse('L898902C3', '690806', '940623').mrzKey.substring(0, 9),
        'L898902C3',
      );
    });

    test('a twelve-character document number passes through verbatim', () {
      // The TD1 concatenated case: ICAO 9303 Part 11 §9.7.3 wants the
      // complete number, so `composeMrzKey` does not pad or truncate it.
      final key = parse('ABC123456789', '690806', '940623').mrzKey;
      expect(key.substring(0, 12), 'ABC123456789');
      // 12 + its check digit + two dates with theirs: no padding anywhere.
      expect(key.length, 27);
    });

    for (final bad in ['L898-902', 'L898 902', 'L898902é']) {
      test('a document number containing "$bad" is rejected', () {
        expect(
          () => parse(bad, '690806', '940623'),
          throwsMrz(MrzField.documentNumber, MrzErrorReason.illegalCharacter),
        );
      });
    }

    test('a filler date is legal (Part 3 §4.8)', () {
      expect(parse('L898902C', '85<<<<', '940623').dateOfBirth, '85<<<<');
    });

    for (final bad in ['69080', '6908061']) {
      test('a date of "$bad" is the wrong length', () {
        expect(
          () => parse('L898902C', bad, '940623'),
          throwsMrz(MrzField.dateOfBirth, MrzErrorReason.wrongLength),
        );
      });
    }

    test('a date containing letters is rejected', () {
      expect(
        () => parse('L898902C', '85AB23', '940623'),
        throwsMrz(MrzField.dateOfBirth, MrzErrorReason.illegalCharacter),
      );
    });

    test('fields are checked in order, so the first failure wins', () {
      // Only the expiry is wrong: the reported field must be the expiry, not
      // a date-of-birth error the form would then point at the wrong box.
      expect(
        () => parse('L898902C', '690806', '9406'),
        throwsMrz(MrzField.dateOfExpiry, MrzErrorReason.wrongLength),
      );
    });
  });
}
