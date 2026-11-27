/// The vendored BER walker.
///
/// The three properties `lib/src/pki/asn1_reader.dart` exists for: BER
/// indefinite lengths, byte-exact raw slices, and totality on hostile input.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/src/pki/asn1_reader.dart';
import 'package:flutter_test/flutter_test.dart';

import '../support/emrtd_test_pki.dart';
import '../support/pki_fixtures.dart';

Uint8List _hx(String hex) => Uint8List.fromList([
  for (var i = 0; i < hex.length; i += 2)
    int.parse(hex.substring(i, i + 2), radix: 16),
]);

void main() {
  group('definite lengths', () {
    test('short form primitive', () {
      final node = parseAsn1(_hx('020101'))!;
      expect(node.tag, 0x02);
      expect(node.headerLength, 2);
      expect(node.contentLength, 1);
      expect(node.totalLength, 3);
      expect(node.isConstructed, isFalse);
      expect(node.children, isNull);
      expect(node.content, [0x01]);
    });

    test('long form (0x82) and nested children', () {
      final inner = Der.octetString(List<int>.filled(300, 0xAB));
      final seq = Der.seq([inner]);
      final node = parseAsn1(seq)!;
      expect(node.tag, 0x30);
      expect(node.childCount, 1);
      expect(node.child(0)!.contentLength, 300);
      expect(node.child(0)!.encoded, inner);
    });

    test('multi-byte tags parse as big-endian tag values', () {
      // `7F49` is constructed (bit 0x20 of the leading octet), so its content
      // is walked as children: the BER tag rule, package-wide.
      final node = parseAsn1(_hx('7f4903020101'))!;
      expect(node.tag, 0x7F49);
      expect(node.contentLength, 3);
      expect(node.isConstructed, isTrue);
      expect(integerOf(node.child(0)), BigInt.one);
    });

    test('a zero-length element is ordinary', () {
      final node = parseAsn1(_hx('0500'))!;
      expect(node.contentLength, 0);
      expect(node.content, isEmpty);
    });
  });

  group('indefinite lengths (BER)', () {
    test('walks to the end-of-contents pair', () {
      final ber = Der.indefinite(0x30, [...Der.int32(1), ...Der.int32(2)]);
      final node = parseAsn1(ber)!;
      expect(node.indefinite, isTrue);
      expect(node.childCount, 2);
      expect(node.totalLength, ber.length);
      expect(node.encoded, ber);
    });

    test('a zero-length TLV inside an indefinite region parses', () {
      // pointycastle's asn1_utils.dart:142-144 throws on exactly this shape;
      // the vendored walker exists to parse it.
      final node = parseAsn1(zeroLengthInsideIndefinite)!;
      expect(node.indefinite, isTrue);
      expect(node.childCount, 2);
      expect(node.child(0)!.tag, Asn1Tag.nullTag);
      expect(node.child(0)!.contentLength, 0);
      expect(integerOf(node.child(1)), BigInt.from(42));
    });

    test('nested indefinite regions', () {
      final ber = Der.indefinite(
        0x30,
        Der.indefinite(0xA0, Der.octetString(const [1, 2, 3])),
      );
      final node = parseAsn1(ber)!;
      expect(node.child(0)!.indefinite, isTrue);
      expect(node.child(0)!.child(0)!.content, [1, 2, 3]);
    });

    test('an unterminated indefinite region is malformed, not a throw', () {
      expect(parseAsn1(_hx('3080020101')), isNull);
    });

    test('indefinite length is rejected on a primitive tag', () {
      expect(parseAsn1(_hx('04800000')), isNull);
    });
  });

  group('totality on hostile input', () {
    test('truncated content', () {
      expect(parseAsn1(_hx('300502010102')), isNull);
    });

    test('length declaring more than 4 octets', () {
      expect(parseAsn1(_hx('3085010203040500')), isNull);
    });

    test('empty and one-byte inputs', () {
      expect(parseAsn1(Uint8List(0)), isNull);
      expect(parseAsn1(_hx('30')), isNull);
    });

    test('a truncated multi-byte tag', () {
      expect(parseAsn1(_hx('7f')), isNull);
    });

    test('every truncation of a real SOD is null-or-parsed, never a throw', () {
      final sod = sodRsaSha256;
      for (var n = 0; n < sod.length; n += 37) {
        expect(
          () => parseAsn1(Uint8List.sublistView(sod, 0, n)),
          returnsNormally,
        );
      }
    });

    test('sequence parse rejects trailing bytes', () {
      expect(parseAsn1Sequence(_hx('020101ff')), isNull);
      expect(parseAsn1Sequence(_hx('020101020102'))!.length, 2);
      expect(parseAsn1Sequence(Uint8List(0)), isEmpty);
    });
  });

  group('content decoders', () {
    test('OID', () {
      expect(oidOf(parseAsn1(Der.oid('2.23.136.1.1.1'))), '2.23.136.1.1.1');
      expect(
        oidOf(parseAsn1(Der.oid('1.2.840.113549.1.1.11'))),
        '1.2.840.113549.1.1.11',
      );
      expect(
        oidOf(parseAsn1(Der.oid('0.4.0.127.0.7.2.2.1.2'))),
        '0.4.0.127.0.7.2.2.1.2',
      );
      expect(oidOf(parseAsn1(_hx('020101'))), isNull); // not an OID
      expect(decodeOidContent(const [0x80]), isNull); // unterminated arc
      expect(decodeOidContent(const []), isNull);
    });

    test('INTEGER is two\'s complement', () {
      expect(integerOf(parseAsn1(_hx('020100'))), BigInt.zero);
      expect(integerOf(parseAsn1(_hx('0201ff'))), BigInt.from(-1));
      expect(integerOf(parseAsn1(_hx('020200ff'))), BigInt.from(255));
      expect(integerOf(parseAsn1(_hx('0500'))), isNull);
    });

    test('BIT STRING payload and flag list', () {
      expect(bitStringBytes(parseAsn1(_hx('030300abcd'))), [0xAB, 0xCD]);
      expect(bitStringBytes(parseAsn1(_hx('030301abcd'))), isNull); // unused≠0
      // keyUsage 06 with one unused bit -> keyCertSign(5), cRLSign(6).
      final flags = bitStringFlags(parseAsn1(_hx('03020106')))!;
      expect(flags.length, 7);
      expect(flags[5], isTrue);
      expect(flags[6], isTrue);
      expect(flags[0], isFalse);
    });

    test('BOOLEAN tolerates any non-zero (BER)', () {
      expect(booleanOf(parseAsn1(_hx('0101ff'))), isTrue);
      expect(booleanOf(parseAsn1(_hx('010101'))), isTrue);
      expect(booleanOf(parseAsn1(_hx('010100'))), isFalse);
    });

    test('UTCTime pivots at 50 (RFC 5280 §4.1.2.5.1)', () {
      expect(
        decodeAsn1Time(parseAsn1(_hx('170d3230303130313030303030305a'))),
        DateTime.utc(2020, 1, 1),
      );
      // "491231235959Z" -> 2049, "500101000000Z" -> 1950.
      expect(
        decodeAsn1Time(parseAsn1(Der.tagged(0x17, '491231235959Z'.codeUnits))),
        DateTime.utc(2049, 12, 31, 23, 59, 59),
      );
      expect(
        decodeAsn1Time(parseAsn1(Der.tagged(0x17, '500101000000Z'.codeUnits))),
        DateTime.utc(1950, 1, 1),
      );
    });

    test('GeneralizedTime, offsets and fractional seconds', () {
      expect(
        decodeAsn1Time(
          parseAsn1(Der.tagged(0x18, '21260101000000Z'.codeUnits)),
        ),
        DateTime.utc(2126, 1, 1),
      );
      expect(
        decodeAsn1Time(
          parseAsn1(Der.tagged(0x18, '20200101010000+0100'.codeUnits)),
        ),
        DateTime.utc(2020, 1, 1),
      );
      expect(
        decodeAsn1Time(
          parseAsn1(Der.tagged(0x18, '20200101000000.5Z'.codeUnits)),
        ),
        DateTime.utc(2020, 1, 1),
      );
      expect(
        decodeAsn1Time(parseAsn1(Der.tagged(0x17, 'nonsense'.codeUnits))),
        isNull,
      );
      expect(decodeAsn1Time(parseAsn1(_hx('020101'))), isNull);
    });

    test('strings: UTF-8, PrintableString, BMPString', () {
      expect(
        decodeAsn1String(parseAsn1(Der.printableString('UTOPIA'))),
        'UTOPIA',
      );
      expect(decodeAsn1String(parseAsn1(Der.utf8String('Ünïcøde'))), 'Ünïcøde');
      expect(
        decodeAsn1String(parseAsn1(Der.tagged(0x1E, [0x00, 0x41, 0x00, 0x42]))),
        'AB',
      );
      expect(decodeAsn1String(parseAsn1(_hx('020101'))), isNull);
      // Invalid UTF-8 falls back to latin-1 rather than throwing.
      expect(
        decodeAsn1String(parseAsn1(Der.tagged(0x0C, const [0xFF]))),
        isNotNull,
      );
    });
  });

  test(
    'in-place content parsing keeps slices pointing at the original buffer',
    () {
      final inner = Der.seq([Der.int32(7)]);
      final wrapper = Der.octetString(inner);
      final node = parseAsn1(wrapper)!;
      final parsedInner = parseAsn1Inside(node)!;
      expect(parsedInner.encoded, inner);
      expect(identical(parsedInner.source, node.source), isTrue);
      expect(parseAsn1Content(node)!.single.encoded, inner);
    },
  );
}
