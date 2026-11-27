/// BACHandler unit tests for behavior beyond the shared bac_auth vectors:
/// dedicated checks that the mutual-auth response is authenticated (MAC +
/// RND.IFD echo, a security fix over upstream), the end-to-end handshake
/// over the scripted transceiver (stale session cleared, SecureMessaging
/// installed, injected randomness fully consumed), and the
/// composeMrzKey/mrzCheckDigit helper.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/proto/bac.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/scripted_transceiver.dart';

List<int> _hx(String s) => [
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
];

const _mrzKey = 'L898902C<369080619406236';
const _rndIcc = '4608f91988702212';
const _rndIfd = '781723860c06c226';
const _kifd = '0b795240cb7049b01c19b33e32804f0b';
// App D.3 mutual-auth exchange.
const _cmdData =
    '72c29c2371cc9bdb65b779b8e8d37b29ecc154aa56a8799fae2f498f'
    '76ed92f25f1448eea8ad90a7';
const _maResponse =
    '46b9342a41396cd7386bf5803104d7cedc122b9132139baf2eedc9'
    '4ee178534f2f2d235d074d7449';

/// Handler primed through the App D.3 flow up to the mutual-auth response.
BACHandler _primed({ScriptedTransceiver? transceiver}) {
  final handler = BACHandler(
    tagReader: TagReader(transceiver ?? ScriptedTransceiver(const [])),
    random: FixedRandom(_hx('$_rndIfd$_kifd')),
  );
  handler.deriveDocumentBasicAccessKeys(_mrzKey);
  handler.authentication(_hx(_rndIcc));
  return handler;
}

CommandAPDU _cmd(int cla, int ins, int p1, int p2, List<int> data, int le) =>
    CommandAPDU(
      instructionClass: cla,
      instructionCode: ins,
      p1Parameter: p1,
      p2Parameter: p2,
      data: data,
      expectedResponseLength: le,
    );

void main() {
  group('mutual-auth response authenticated (a security fix)', () {
    test('App D.3 response verifies and derives the session', () {
      final session = _primed().sessionKeys(_hx(_maResponse));
      expect(session.ssc, _hx('887022120c06c226'));
    });

    test('tampered M.ICC throws InvalidResponseChecksum', () {
      final bytes = _hx(_maResponse);
      bytes[39] ^= 0xFF;
      expect(
        () => _primed().sessionKeys(bytes),
        throwsA(isA<InvalidResponseChecksum>()),
      );
    });

    test('tampered E.ICC throws InvalidResponseChecksum', () {
      final bytes = _hx(_maResponse);
      bytes[0] ^= 0xFF;
      expect(
        () => _primed().sessionKeys(bytes),
        throwsA(isA<InvalidResponseChecksum>()),
      );
    });

    test('wrong RND.IFD echo (valid MAC) throws InvalidDataPassed', () {
      // bac_auth.json fixture: R'' = RND.ICC ‖ ff...ff ‖ K.ICC re-encrypted
      // and re-MACed, so only the echo check can reject it.
      const wrongEcho =
          '46b9342a41396cd79c865bebd5b30c59e1207520c68a2936'
          '4c8f06af0dd59165112cc4210736ee87';
      expect(
        () => _primed().sessionKeys(_hx(wrongEcho)),
        throwsA(
          isA<InvalidDataPassed>().having(
            (e) => e.message,
            'message',
            contains('RND.IFD'),
          ),
        ),
      );
    });

    test('short response throws InvalidDataPassed instead of slicing', () {
      expect(
        () => _primed().sessionKeys(_hx(_maResponse).sublist(0, 39)),
        throwsA(isA<InvalidDataPassed>()),
      );
    });
  });

  group('performBACAndGetSessionKeys', () {
    ScriptedTransceiver handshake(String maSw, {String maData = ''}) =>
        ScriptedTransceiver([
          ScriptedStep(
            cmd: _cmd(0x00, 0x84, 0x00, 0x00, const [], 8),
            wire: Uint8List.fromList(_hx('0084000008')),
            response: Uint8List.fromList([..._hx(_rndIcc), 0x90, 0x00]),
          ),
          ScriptedStep(
            cmd: _cmd(0x00, 0x82, 0x00, 0x00, _hx(_cmdData), 256),
            response: Uint8List.fromList([..._hx(maData), ..._hx(maSw)]),
          ),
        ]);

    test('clears a stale session and installs the derived one', () async {
      final transceiver = handshake('9000', maData: _maResponse);
      final reader = TagReader(transceiver);
      // A stale session must be dropped before GET CHALLENGE; the wire
      // assertion on step 1 proves the command went out unprotected.
      reader.secureMessaging = SecureMessaging(
        ksenc: List.filled(16, 1),
        ksmac: List.filled(16, 2),
        ssc: List.filled(8, 0),
      );
      final random = FixedRandom(_hx('$_rndIfd$_kifd'));
      final handler = BACHandler(tagReader: reader, random: random);

      await handler.performBACAndGetSessionKeys(_mrzKey);

      expect(reader.secureMessaging, isA<SecureMessaging>());
      final sm = reader.secureMessaging! as SecureMessaging;
      expect(sm.ssc, _hx('887022120c06c226'));
      expect(
        random.remaining,
        0,
        reason: 'a BAC session consumes exactly 8 + 16 bytes',
      );
      expect(transceiver.exhausted, isTrue);
    });

    test('empty-success mutual-auth response throws InvalidMRZKey '
        '(defense-in-depth)', () async {
      final reader = TagReader(handshake('9000'));
      final handler = BACHandler(
        tagReader: reader,
        random: FixedRandom(_hx('$_rndIfd$_kifd')),
      );
      await expectLater(
        handler.performBACAndGetSessionKeys(_mrzKey),
        throwsA(isA<InvalidMRZKey>()),
      );
      expect(reader.secureMessaging, isNull);
    });

    test('63 00 on EXTERNAL AUTHENTICATE throws InvalidMRZKey', () async {
      final handler = BACHandler(
        tagReader: TagReader(handshake('6300')),
        random: FixedRandom(_hx('$_rndIfd$_kifd')),
      );
      await expectLater(
        handler.performBACAndGetSessionKeys(_mrzKey),
        throwsA(isA<InvalidMRZKey>()),
      );
    });
  });

  group('composeMrzKey / mrzCheckDigit', () {
    test('check digits match ICAO P11 App D.2', () {
      expect(mrzCheckDigit('L898902C<'), 3);
      expect(mrzCheckDigit('690806'), 1);
      expect(mrzCheckDigit('940623'), 6);
    });

    test('all-filler field checks to 0 (Part 3 §4.8/§4.9)', () {
      expect(mrzCheckDigit('<<<<<<'), 0);
    });

    test('composes the App D.2 key', () {
      expect(
        composeMrzKey(
          documentNumber: 'L898902C<',
          dateOfBirth: '690806',
          dateOfExpiry: '940623',
        ),
        _mrzKey,
      );
    });

    test('pads short document numbers with < before the check digit', () {
      expect(
        composeMrzKey(
          documentNumber: 'AB123456',
          dateOfBirth: '690806',
          dateOfExpiry: '940623',
        ),
        'AB123456<469080619406236',
      );
    });

    test('>9-char document number passes through unpadded (TD1 concatenated '
        'form, P11 §9.7.3: the kdf_bac >9-char kmrz variant)', () {
      expect(
        composeMrzKey(
          documentNumber: 'D23145890734',
          dateOfBirth: '340712',
          dateOfExpiry: '950712',
        ),
        'D23145890734934071279507122',
      );
    });

    test('rejects characters outside the MRZ set', () {
      expect(() => mrzCheckDigit('a'), throwsA(isA<InvalidDataPassed>()));
      expect(
        () => composeMrzKey(
          documentNumber: 'L898902C-',
          dateOfBirth: '690806',
          dateOfExpiry: '940623',
        ),
        throwsA(isA<InvalidDataPassed>()),
      );
    });
  });
}
