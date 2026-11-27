/// SecureMessaging unit tests for behavior the vectors don't already pin:
/// the byte-wise SSC (increment, carry, the 0xFF...FF wrap upstream traps
/// on, and the top-bit-set value that would explode a `binToInt`
/// round-trip), the 8-byte SSC constructor guard, upstream's
/// increment-on-error ordering, and dedicated checks that the AES response
/// MAC is verified (a security fix), beyond the shared sm_aes cases.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/mac.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/response_apdu.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:flutter_test/flutter_test.dart';

List<int> _hx(String s) => [
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];

String _h(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// App D.3 session keys (pre-parity 24-byte forms) + SSC.
final _ksenc = _hx('969ec03b1cbfe9ddd11ab1fed206ebe4969ec03b1cbfe9dd');
final _ksmac = _hx('f0ca1e1eb5adf208816b88dd579cc1f8f0ca1e1eb5adf208');

// sm_aes.json frozen-reference keys.
final _aesKsenc = _hx('f5f0e35c0d7161ee6724ee513a0d9a7f');
final _aesKsmac = _hx('fe251c7858b356b24514b3bd5f4297d1');

SecureMessaging _des(String ssc) =>
    SecureMessaging(ksenc: _ksenc, ksmac: _ksmac, ssc: _hx(ssc));

SecureMessaging _aes(String ssc) => SecureMessaging(
  encryptionAlgorithm: SecureMessagingSupportedAlgorithms.aes,
  ksenc: _aesKsenc,
  ksmac: _aesKsmac,
  ssc: _hx(ssc),
);

void main() {
  group('incSSC (byte-wise, no integer round-trip)', () {
    for (final (start, want) in [
      ('0000000000000000', '0000000000000001'),
      ('00000000000000ff', '0000000000000100'),
      ('887022120c06c226', '887022120c06c227'),
      // Top bit set: a random BAC SSC routinely looks like this; any
      // binToInt/binToHexBytes round-trip would throw (binToInt's guard) or
      // go negative. Byte-wise increment must not care.
      ('ff00000000000000', 'ff00000000000001'),
      ('7fffffffffffffff', '8000000000000000'),
      // The wrap upstream traps on (UInt64 overflow via binToHex + 1):
      // defined here.
      ('ffffffffffffffff', '0000000000000000'),
    ]) {
      test('$start + 1 = $want', () {
        expect(_h(_des(start).incSSC()), want);
      });
    }
  });

  group('SSC construction guard', () {
    for (final bad in ['', '01020304050607', '010203040506070809']) {
      test('${bad.length ~/ 2}-byte SSC rejected', () {
        expect(() => _des(bad), throwsA(isA<InvalidDataPassed>()));
      });
    }
  });

  group('SSC trajectory', () {
    test('protect and unprotect each increment once, in exchange order', () {
      final sm = _des('887022120c06c226');
      sm.protect(
        CommandAPDU.parse(const [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E]),
      );
      expect(_h(sm.ssc), '887022120c06c227');
      sm.unprotect(
        ResponseAPDU(
          Uint8List.fromList(_hx('990290008e08fa855a5d4c50a8ed')),
          0x90,
          0x00,
        ),
      );
      expect(_h(sm.ssc), '887022120c06c228');
    });

    test('non-9000 unprotect returns the raw rapdu after incrementing', () {
      final sm = _des('887022120c06c226');
      final raw = ResponseAPDU(Uint8List(0), 0x69, 0x82);
      final out = sm.unprotect(raw);
      expect(identical(out, raw), isTrue);
      expect(_h(sm.ssc), '887022120c06c227');
    });
  });

  group('AES response MAC actually verified (a security fix)', () {
    // sm_aes.json's unprotect round-trip fixture: valid chip response at
    // SSC 6->7.
    const validResp =
        '87210106b568ca5447c5a94067356bb65e585a39b2793f072b2034'
        '53804278ba8ad797990290008e08a1075bfa55324bde';

    test('valid 16-byte CMAC truncated to 8 and compared: accepts', () {
      final out = _aes(
        '0000000000000006',
      ).unprotect(ResponseAPDU(Uint8List.fromList(_hx(validResp)), 0x90, 0x00));
      expect(_h(out.data), '60145f0104303130365f36063034303030305c026175');
      expect((out.sw1, out.sw2), (0x90, 0x00));
    });

    test('any tampered MAC byte throws InvalidResponseChecksum', () {
      for (final flip in [0, 3, 7]) {
        final bytes = _hx(validResp);
        bytes[bytes.length - 8 + flip] ^= 0xFF;
        expect(
          () => _aes(
            '0000000000000006',
          ).unprotect(ResponseAPDU(Uint8List.fromList(bytes), 0x90, 0x00)),
          throwsA(isA<InvalidResponseChecksum>()),
          reason: 'MAC byte $flip flipped must not verify',
        );
      }
    });

    test('tampered ciphertext throws InvalidResponseChecksum', () {
      final bytes = _hx(validResp);
      bytes[5] ^= 0xFF; // inside the DO87 cryptogram
      expect(
        () => _aes(
          '0000000000000006',
        ).unprotect(ResponseAPDU(Uint8List.fromList(bytes), 0x90, 0x00)),
        throwsA(isA<InvalidResponseChecksum>()),
      );
    });
  });

  group('DO99 wrong-length rejection (fixes an upstream defect)', () {
    test('99 01 DO99 returns SM error (empty data, embedded SW)', () {
      // sm_aes.json's DO99 check-split fixture: MAC valid over the malformed
      // DO99, so the early return is the DO99 length check's doing, not a
      // MAC failure.
      const resp =
          '87210106b568ca5447c5a94067356bb65e585a39b2793f072b203453'
          '804278ba8ad797990190008e08e2339ed17e1518c2';
      final out = _aes(
        '0000000000000006',
      ).unprotect(ResponseAPDU(Uint8List.fromList(_hx(resp)), 0x90, 0x00));
      expect(out.data, isEmpty);
      expect((out.sw1, out.sw2), (0x90, 0x00));
    });
  });
}
