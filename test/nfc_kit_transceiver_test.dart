/// Exception-mapping contract tests (one per table row, pinned to
/// flutter_nfc_kit 3.6.2) plus channel-mocked end-to-end checks of
/// [NfcKitTransceiver]: payload round-trip, 30 s default timeout forwarding,
/// and PlatformException translation.
library;

import 'dart:convert';
import 'dart:io';

import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/transport/nfc_kit_transceiver.dart';
import 'package:emrtd_core/src/transport/nfc_session.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_nfc_kit/method');

  void mockChannel(Future<Object?> Function(MethodCall call) handler) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, handler);
  }

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('mapNfcKitPlatformException (one test per table row)', () {
    PlatformException pe(String code) => PlatformException(code: code);

    test('406 "No tag polled" -> NoConnectedTag', () {
      expect(mapNfcKitPlatformException(pe('406')), isA<NoConnectedTag>());
    });

    test('503 "Tag already removed" -> ConnectionError', () {
      expect(mapNfcKitPlatformException(pe('503')), isA<ConnectionError>());
    });

    test('500 communication error / tag lost -> ConnectionError', () {
      expect(mapNfcKitPlatformException(pe('500')), isA<ConnectionError>());
    });

    test('408 session timeout -> TimeOutError', () {
      expect(mapNfcKitPlatformException(pe('408')), isA<TimeOutError>());
    });

    test('409 iOS SessionCanceled -> UserCanceled', () {
      expect(mapNfcKitPlatformException(pe('409')), isA<UserCanceled>());
    });

    test('unknown codes wrap in UnknownError', () {
      final original = pe('400');
      final mapped = mapNfcKitPlatformException(original);
      expect(mapped, isA<UnknownError>());
      expect((mapped as UnknownError).cause, same(original));
    });
  });

  group('NfcKitTransceiver over a mocked method channel', () {
    test('round-trips bytes and forwards the 30 s default timeout', () async {
      MethodCall? seen;
      mockChannel((call) async {
        seen = call;
        return Uint8List.fromList([0x60, 0x14, 0x90, 0x00]);
      });

      final result = await NfcKitTransceiver().transceive(
        Uint8List.fromList([0x00, 0xB0, 0x00, 0x00, 0x04]),
      );

      expect(result, [0x60, 0x14, 0x90, 0x00]);
      expect(seen?.method, 'transceive');
      final args = (seen?.arguments as Map).cast<String, Object?>();
      expect(args['data'], [0x00, 0xB0, 0x00, 0x00, 0x04]);
      expect(
        args['timeout'],
        30000,
        reason: '30 s default, not the plugin\'s 5 s',
      );
    });

    test('forwards a constructor-supplied timeout', () async {
      MethodCall? seen;
      mockChannel((call) async {
        seen = call;
        return Uint8List(2);
      });

      await NfcKitTransceiver(
        timeout: const Duration(seconds: 5),
      ).transceive(Uint8List.fromList([0x00, 0x84, 0x00, 0x00, 0x08]));

      expect(
        ((seen?.arguments as Map).cast<String, Object?>())['timeout'],
        5000,
      );
    });

    test('maps a PlatformException from the channel', () async {
      mockChannel((call) async {
        throw PlatformException(code: '500', message: 'Communication error');
      });

      await expectLater(
        NfcKitTransceiver().transceive(Uint8List.fromList([0x00, 0x84])),
        throwsA(isA<ConnectionError>()),
      );
    });

    test('pessimistic capability defaults are overridable', () {
      final defaults = NfcKitTransceiver();
      expect(defaults.maxTransceiveLength, 261);
      expect(defaults.isExtendedLengthApduSupported, isFalse);
      expect(defaults.tagCapabilities, isNull);

      final tuned = NfcKitTransceiver(
        maxTransceiveLength: 0xFFFF,
        isExtendedLengthApduSupported: true,
      );
      expect(tuned.maxTransceiveLength, 0xFFFF);
      expect(tuned.isExtendedLengthApduSupported, isTrue);
    });
  });

  group('FlutterNfcKitNfcSession.poll (capability plumbing)', () {
    const tagJson =
        '{"type":"iso7816","id":"04a1b2c3","standard":"ISO 14443-4 '
        '(Type A)","atqa":"0400","sak":"20","historicalBytes":"80318066b18","'
        'ndefAvailable":false,"ndefWritable":false,"ndefCanMakeReadOnly":false,'
        '"ndefCapacity":0,"ndefType":""';

    void mockPoll(String tail) {
      mockChannel((call) async {
        if (call.method == 'poll') return '$tagJson$tail}';
        return null;
      });
    }

    Future<NfcTransceiver> poll() => FlutterNfcKitNfcSession().poll(
      iosAlertMessage: 'x',
      transceiveTimeout: const Duration(seconds: 7),
    );

    test(
      'the plugin\'s real caps and historical bytes reach the transceiver',
      () async {
        mockPoll(
          ',"maxTransceiveLength":65279,'
          '"isExtendedLengthApduSupported":true,'
          '"historicalBytes":"80318066b184"',
        );
        final transceiver = await poll() as NfcKitTransceiver;
        expect(transceiver.maxTransceiveLength, 65279);
        expect(transceiver.isExtendedLengthApduSupported, isTrue);
        expect(transceiver.historicalBytes, [
          0x80,
          0x31,
          0x80,
          0x66,
          0xB1,
          0x84,
        ]);
        expect(transceiver.timeout, const Duration(seconds: 7));
      },
    );

    test(
      'a tag without the fields keeps the pessimistic capability defaults',
      () async {
        mockPoll(',"historicalBytes":""');
        final transceiver = await poll();
        expect(transceiver.maxTransceiveLength, 261);
        expect(transceiver.isExtendedLengthApduSupported, isFalse);
        expect(
          transceiver.historicalBytes,
          isNull,
          reason: 'the Android plugin emits "" for none',
        );
      },
    );

    test('poll failures map to the EmrtdException hierarchy', () async {
      mockChannel((call) async {
        throw PlatformException(code: '408');
      });
      await expectLater(poll(), throwsA(isA<TimeOutError>()));
    });
  });

  group('FlutterNfcKitNfcSession.poll: TagCapabilities', () {
    /// The plugin's `NFCTag` JSON for one polled tag; [fields] overlays the
    /// three keys every tag carries.
    Future<NfcKitTransceiver> pollTag(Map<String, Object?> fields) async {
      final tag = {'type': 'iso7816', 'id': '04a1b2c3', ...fields};
      mockChannel(
        (call) async => call.method == 'poll' ? jsonEncode(tag) : null,
      );
      return await FlutterNfcKitNfcSession().poll(
            iosAlertMessage: 'x',
            transceiveTimeout: const Duration(seconds: 7),
          )
          as NfcKitTransceiver;
    }

    test(
      'a Type A tag (Android shape): ATQA/SAK carried, Type B fields null',
      () async {
        final t = await pollTag({
          'standard': 'ISO 14443-4 (Type A)',
          'atqa': '0400',
          'sak': '20',
          'historicalBytes': '80318066b184',
          'protocolInfo': '',
          'applicationData': '',
          'hiLayerResponse': '',
        });
        final caps = t.tagCapabilities!;
        expect(caps.type, 'iso7816');
        expect(caps.standard, 'ISO 14443-4 (Type A)');
        expect(caps.atqa, [0x04, 0x00]);
        expect(caps.sak, [0x20]);
        expect(caps.protocolInfo, isNull);
        expect(caps.applicationData, isNull);
        expect(t.historicalBytes, [
          0x80,
          0x31,
          0x80,
          0x66,
          0xB1,
          0x84,
        ], reason: 'historical bytes stay on their own getter');
      },
    );

    test(
      'a Type B tag (Android shape): ATQB fields carried, Type A null',
      () async {
        final t = await pollTag({
          'standard': 'ISO 14443-4 (Type B)',
          'atqa': '',
          'sak': '',
          'historicalBytes': '',
          'protocolInfo': 'a1b2c3',
          'applicationData': '01020304',
          'hiLayerResponse': '',
        });
        final caps = t.tagCapabilities!;
        expect(caps.type, 'iso7816');
        expect(caps.standard, 'ISO 14443-4 (Type B)');
        expect(caps.atqa, isNull);
        expect(caps.sak, isNull);
        expect(caps.protocolInfo, [0xA1, 0xB2, 0xC3]);
        expect(caps.applicationData, [0x01, 0x02, 0x03, 0x04]);
        expect(t.historicalBytes, isNull);
      },
    );

    test(
      'a tag with none of the fields (iOS shape): bytes null, strings set',
      () async {
        final t = await pollTag({'standard': 'ISO 14443'});
        final caps = t.tagCapabilities!;
        expect(caps.type, 'iso7816');
        expect(caps.standard, 'ISO 14443');
        expect(caps.atqa, isNull);
        expect(caps.sak, isNull);
        expect(caps.protocolInfo, isNull);
        expect(caps.applicationData, isNull);
        expect(t.historicalBytes, isNull);
      },
    );

    test(
      'the plugin\'s "unknown" type and standard pass through verbatim',
      () async {
        final t = await pollTag({'type': 'unknown', 'standard': 'unknown'});
        expect(t.tagCapabilities!.type, 'unknown');
        expect(t.tagCapabilities!.standard, 'unknown');
      },
    );

    test(
      'the tag id (UID / PUPI) reaches none of the seven surfaces',
      () async {
        // Every surface populated, so an id leaking into any of them would
        // be visible; protocolInfo is a near-miss suffix of the id.
        final t = await pollTag({
          'standard': 'ISO 14443-4 (Type A)',
          'atqa': '0400',
          'sak': '20',
          'historicalBytes': '80318066b184',
          'protocolInfo': 'a1b2c3',
          'applicationData': '01020304',
        });
        final caps = t.tagCapabilities!;
        const idHex = '04a1b2c3';
        const idBytes = [0x04, 0xA1, 0xB2, 0xC3];
        bool holdsId(Uint8List? bytes) {
          if (bytes == null) return false;
          for (var i = 0; i + idBytes.length <= bytes.length; i++) {
            var match = true;
            for (var j = 0; j < idBytes.length; j++) {
              if (bytes[i + j] != idBytes[j]) {
                match = false;
                break;
              }
            }
            if (match) return true;
          }
          return false;
        }

        expect(caps.type, isNot(contains(idHex)));
        expect(caps.standard, isNot(contains(idHex)));
        for (final surface in [
          caps.atqa,
          caps.sak,
          caps.protocolInfo,
          caps.applicationData,
          t.historicalBytes,
        ]) {
          expect(surface, isNotNull);
          expect(holdsId(surface), isFalse);
        }
      },
    );

    test('the transceiver source never reads the tag id', () {
      // A source pin beside the behavioural one: the identifier must not
      // even be touched, so a future field cannot quietly carry it.
      final source = File(
        'lib/src/transport/nfc_kit_transceiver.dart',
      ).readAsStringSync();
      expect(source.contains('tag.id'), isFalse);
    });
  });

  group('FlutterNfcKitNfcSession.availability (tri-state)', () {
    void mockAvailability(String value) {
      mockChannel((call) async {
        if (call.method == 'getNFCAvailability') return value;
        return null;
      });
    }

    test(
      '"available" -> NfcAvailability.available; isAvailable true',
      () async {
        mockAvailability('available');
        final session = FlutterNfcKitNfcSession();
        expect(await session.availability(), NfcAvailability.available);
        expect(await session.isAvailable(), isTrue);
      },
    );

    test('"disabled" -> NfcAvailability.disabled; isAvailable false', () async {
      mockAvailability('disabled');
      final session = FlutterNfcKitNfcSession();
      expect(await session.availability(), NfcAvailability.disabled);
      expect(await session.isAvailable(), isFalse);
    });

    test(
      '"not_supported" -> NfcAvailability.notSupported; isAvailable false',
      () async {
        mockAvailability('not_supported');
        final session = FlutterNfcKitNfcSession();
        expect(await session.availability(), NfcAvailability.notSupported);
        expect(await session.isAvailable(), isFalse);
      },
    );
  });
}
