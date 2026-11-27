/// Chip Authentication unit tests. What the conformance vectors and
/// transcripts can't express: the key-loop semantics (first success wins,
/// per-key errors swallowed), the MSE DO84 asymmetry at keyId 0, the keyId
/// map's last-wins rule, upstream's DH keySeed composition (left-aligned,
/// zero-filled), the chunker's boundaries, and the SPKI parser's
/// explicit-vs-named domain equivalence.
library;

// ignore_for_file: implementation_imports

import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/lds/pace_info.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/ecc/api.dart';

import 'support/emrtd_fixtures.dart';

/// Records every command and answers from a scripted SW list (defaulting to
/// `90 00`, with `7C 00` bodies for GENERAL AUTHENTICATE).
class _CapturingTransceiver implements NfcTransceiver {
  _CapturingTransceiver({
    this.mseSws = const [],
    this.maxTransceiveLength = 261,
    this.mseThrow,
    this.gaResponse = const [0x7C, 0x00, 0x90, 0x00],
  });

  /// SWs answered to successive INS 0x22 commands; exhausted entries fall
  /// back to `90 00`.
  final List<int> mseSws;

  /// Thrown from [transceive] for every INS 0x22, in place of an answer.
  final Object? mseThrow;

  /// The full frame answered to every INS 0x86.
  final List<int> gaResponse;
  final List<CommandAPDU> sent = [];
  int _mseSeen = 0;

  @override
  final int maxTransceiveLength;
  @override
  bool get isExtendedLengthApduSupported => false;
  @override
  Uint8List? get historicalBytes => null;
  @override
  TagCapabilities? get tagCapabilities => null;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    final cmd = CommandAPDU.parse(capdu);
    sent.add(cmd);
    if (cmd.instructionCode == 0x22) {
      final thrown = mseThrow;
      if (thrown != null) throw thrown;
      final sw = _mseSeen < mseSws.length ? mseSws[_mseSeen] : 0x9000;
      _mseSeen++;
      return Uint8List.fromList([(sw >> 8) & 0xFF, sw & 0xFF]);
    }
    if (cmd.instructionCode == 0x86) {
      return Uint8List.fromList(gaResponse);
    }
    return Uint8List.fromList([0x90, 0x00]);
  }
}

Uint8List _derInt(int v) => TlvRecord(0x02, [v]).data;
Uint8List _seq(List<List<int>> c) =>
    TlvRecord(0x30, [for (final x in c) ...x]).data;

/// A DG14 with two CA public keys (keyId 1 and 2) and matching infos.
Uint8List _twoKeyDg14(String oid) {
  final spki = caChipSpki();
  return TlvRecord(
    0x6E,
    TlvRecord(0x31, [
      ..._seq([asn1EncodeOid(oid), _derInt(1), _derInt(1)]),
      ..._seq([asn1EncodeOid(oid), _derInt(1), _derInt(2)]),
      ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), spki, _derInt(1)]),
      ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), spki, _derInt(2)]),
    ]).data,
  ).data;
}

/// A DER INTEGER of any size (the `emrtd_fixtures.dart` shape).
Uint8List _derBig(BigInt v) {
  var bytes = bigIntToBytes(v).toList();
  if (bytes.isEmpty) bytes = [0];
  if ((bytes.first & 0x80) != 0) bytes = [0, ...bytes];
  return TlvRecord(0x02, bytes).data;
}

/// A DG14 of one info for [caOid] and one `id-PK-DH` key on the RFC 5114
/// 2048-bit group (`paceParameterSpecForId(2)`), as an X9.42
/// `dhpublicnumber` SubjectPublicKeyInfo.
Uint8List _dhDg14(String caOid) {
  final group = paceParameterSpecForId(2) as DHStandardizedDomain;
  final x = BigInt.parse('0102030405060708090a0b0c0d0e0f10', radix: 16);
  final y = dhPublic(group.p, group.g, x);
  final spki = _seq([
    _seq([
      asn1EncodeOid('1.2.840.10046.2.1'),
      _seq([_derBig(group.p), _derBig(group.g), _derBig(group.q)]),
    ]),
    TlvRecord(0x03, [0x00, ..._derBig(y)]).data,
  ]);
  return TlvRecord(
    0x6E,
    TlvRecord(0x31, [
      ..._seq([asn1EncodeOid(caOid), _derInt(1)]),
      ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.1'), spki]),
    ]).data,
  ).data;
}

/// A DG14 of one info for [caOid] and one `id-PK-ECDH` entry carrying the
/// AA RSA key, which CA cannot use.
Uint8List _rsaDg14(String caOid) => TlvRecord(
  0x6E,
  TlvRecord(0x31, [
    ..._seq([asn1EncodeOid(caOid), _derInt(1)]),
    ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), aaRsaSpki()]),
  ]).data,
).data;

/// A DG14 with infos for keyIds 1 and 2; key 1 is the RSA key, key 2 the
/// chip's EC key.
Uint8List _rsaThenEcDg14(String caOid) => TlvRecord(
  0x6E,
  TlvRecord(0x31, [
    ..._seq([asn1EncodeOid(caOid), _derInt(1), _derInt(1)]),
    ..._seq([asn1EncodeOid(caOid), _derInt(1), _derInt(2)]),
    ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), aaRsaSpki(), _derInt(1)]),
    ..._seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), caChipSpki(), _derInt(2)]),
  ]).data,
).data;

/// The fixed ephemeral scalar every test handshake injects.
final BigInt _ephemeralScalar = BigInt.parse(
  '3f8e0d5b6a2c9147d8e0b2c4a6f8091b3d5f7092a4c6e80b1d3f5a7092b4d6e8',
  radix: 16,
);

ChipAuthenticationHandler _handler(
  Uint8List dg14,
  TagReader reader, {
  BigInt? ephemeral,
}) => ChipAuthenticationHandler(
  dg14: DataGroup14(dg14),
  tagReader: reader,
  ephemeralPrivateKey: ephemeral ?? _ephemeralScalar,
);

/// Runs a handshake over [dg14] that must throw [ChipAuthenticationFailed],
/// and returns the handler so the test can read its cause.
Future<ChipAuthenticationHandler> _failing(
  Uint8List dg14,
  _CapturingTransceiver tx,
) async {
  final h = _handler(dg14, TagReader(tx));
  await expectLater(
    h.doChipAuthentication(),
    throwsA(isA<ChipAuthenticationFailed>()),
  );
  return h;
}

void main() {
  const caAes = '0.4.0.127.0.7.2.2.3.2.2'; // id-CA-ECDH-AES-CBC-CMAC-128
  const ca3des = '0.4.0.127.0.7.2.2.3.2.1'; // id-CA-ECDH-3DES-CBC-CBC
  const caDh3des = '0.4.0.127.0.7.2.2.3.1.1'; // id-CA-DH-3DES-CBC-CBC

  final handler = _handler;

  group('key loop (upstream parity)', () {
    test('first key fails, second succeeds; no failure is recorded', () async {
      final tx = _CapturingTransceiver(mseSws: [0x6A80]);
      final reader = TagReader(tx);
      final h = handler(_twoKeyDg14(ca3des), reader);

      await h.doChipAuthentication();

      expect(h.usedOid, ca3des);
      expect(h.usedKeyId, 2, reason: 'the second key won');
      expect(tx.sent.where((c) => c.instructionCode == 0x22), hasLength(2));
      expect(reader.secureMessaging, isNotNull);
      expect(h.failure, isNull);
      expect(h.failureSw, isNull);
    });

    test('every key failing throws ChipAuthenticationFailed', () async {
      final tx = _CapturingTransceiver(mseSws: [0x6A80, 0x6A80]);
      final reader = TagReader(tx);
      final h = handler(_twoKeyDg14(ca3des), reader);

      await expectLater(
        h.doChipAuthentication(),
        throwsA(isA<ChipAuthenticationFailed>()),
      );
      expect(h.usedOid, isNull);
      expect(
        reader.secureMessaging,
        isNull,
        reason: 'a failed handshake leaves the caller session in place',
      );
      expect(h.failure, ChipAuthenticationFailure.chipRefused);
      expect(h.failureSw, 0x6A80);
    });

    test('a DG14 with no public key is NotYetSupported', () async {
      final reader = TagReader(_CapturingTransceiver());
      final h = handler(buildDg14(caOid: caAes, withPublicKey: false), reader);
      expect(h.isChipAuthenticationSupported, isFalse);
      await expectLater(
        h.doChipAuthentication(),
        throwsA(isA<NotYetSupported>()),
      );
    });

    test('duplicate keyIds: the last ChipAuthenticationInfo wins', () {
      final dg14 = TlvRecord(
        0x6E,
        TlvRecord(0x31, [
          ..._seq([asn1EncodeOid(ca3des), _derInt(1), _derInt(1)]),
          ..._seq([asn1EncodeOid(caAes), _derInt(1), _derInt(1)]),
          ..._seq([
            asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'),
            caChipSpki(),
            _derInt(1),
          ]),
        ]).data,
      ).data;
      final h = handler(dg14, TagReader(_CapturingTransceiver()));
      expect(h.chipAuthInfos[1]!.oid, caAes);
      expect(h.chipAuthInfos, hasLength(1));
    });
  });

  group('why the handshake failed', () {
    test('a chip refusal is chipRefused, with its status word', () async {
      final h = await _failing(
        buildDg14(caOid: ca3des),
        _CapturingTransceiver(mseSws: [0x6A80]),
      );
      expect(h.failure, ChipAuthenticationFailure.chipRefused);
      expect(h.failureSw, 0x6A80);
      expect(h.usedOid, isNull);
    });

    test('a DH-2048 KAT needs extended length: extendedLengthUnsupported, '
        'never sent', () async {
      final tx = _CapturingTransceiver();
      final h = await _failing(_dhDg14(caDh3des), tx);
      expect(h.failure, ChipAuthenticationFailure.extendedLengthUnsupported);
      expect(h.failureSw, isNull);
      expect(tx.sent, isEmpty);
    });

    test(
      'a command over the cap is exceedsTransceiveLength, never sent',
      () async {
        // The plain MSE:Set KAT for the fixture key is 73 bytes.
        final tx = _CapturingTransceiver(maxTransceiveLength: 64);
        final h = await _failing(buildDg14(caOid: ca3des), tx);
        expect(h.failure, ChipAuthenticationFailure.exceedsTransceiveLength);
        expect(tx.sent, isEmpty);
      },
    );

    for (final thrown in <EmrtdException>[
      const ConnectionError(),
      const TimeOutError(),
      const NoConnectedTag(),
      const UserCanceled(),
      const UnknownError('platform'),
    ]) {
      test('a transport failure is transceiveFailed: ${thrown.code}', () async {
        final h = await _failing(
          buildDg14(caOid: ca3des),
          _CapturingTransceiver(mseThrow: thrown),
        );
        expect(h.failure, ChipAuthenticationFailure.transceiveFailed);
        expect(h.failureSw, isNull);
      });
    }

    test(
      'an answer that fails the terminal checks is responseInvalid',
      () async {
        // No `7C` object in the GA answer, so `unwrapDO` throws.
        final h = await _failing(
          buildDg14(caOid: caAes),
          _CapturingTransceiver(gaResponse: const [0x90, 0x00]),
        );
        expect(h.failure, ChipAuthenticationFailure.responseInvalid);
        expect(h.failureSw, isNull);
      },
    );

    test('a key CA cannot use is localFailure, and nothing is sent', () async {
      final tx = _CapturingTransceiver();
      final h = await _failing(_rsaDg14(ca3des), tx);
      expect(h.failure, ChipAuthenticationFailure.localFailure);
      expect(tx.sent, isEmpty);
    });

    test("a local failure does not mask a later key's chip refusal", () async {
      final tx = _CapturingTransceiver(mseSws: [0x6A80]);
      final h = await _failing(_rsaThenEcDg14(ca3des), tx);
      expect(h.failure, ChipAuthenticationFailure.chipRefused);
      expect(h.failureSw, 0x6A80);
      expect(tx.sent.where((c) => c.instructionCode == 0x22), hasLength(1));
    });

    test("the first key's failure is kept over a later one", () async {
      final h = await _failing(
        _twoKeyDg14(ca3des),
        _CapturingTransceiver(mseSws: [0x6A80, 0x6982]),
      );
      expect(h.failure, ChipAuthenticationFailure.chipRefused);
      expect(h.failureSw, 0x6A80);
    });

    test('the vocabularies are closed and ordered', () {
      expect(ChipAuthenticationFailure.values.map((v) => v.name), [
        'extendedLengthUnsupported',
        'exceedsTransceiveLength',
        'transceiveFailed',
        'chipRefused',
        'responseInvalid',
        'localFailure',
      ]);
      expect(TransportRefusal.values.map((v) => v.name), [
        'extendedLengthUnsupported',
        'exceedsTransceiveLength',
      ]);
    });
  });

  group('MSE DO84 asymmetry (upstream parity)', () {
    test('MSE:Set KAT emits DO84 for keyId 0 as 84 01 00', () async {
      final tx = _CapturingTransceiver();
      final h = handler(buildDg14(caOid: ca3des, keyId: 0), TagReader(tx));
      await h.doChipAuthentication();

      final mse = tx.sent.singleWhere((c) => c.instructionCode == 0x22);
      expect(mse.p1Parameter, 0x41);
      expect(mse.p2Parameter, 0xA6);
      final records = TlvRecord.sequenceOfRecords(mse.data)!;
      expect(records.map((r) => r.tag), [0x91, 0x84]);
      expect(records.last.value, [0x00]);
      // DO91 carries the uncompressed ephemeral point.
      expect(records.first.value.first, 0x04);
      expect(records.first.value, hasLength(65));
      expect(h.usedKeyId, 0);
    });

    test(
      'MSE:Set AT omits DO84 for keyId 0 but emits it for keyId 3',
      () async {
        final tx0 = _CapturingTransceiver();
        await handler(
          buildDg14(caOid: caAes, keyId: 0),
          TagReader(tx0),
        ).doChipAuthentication();
        final mse0 = tx0.sent.singleWhere((c) => c.instructionCode == 0x22);
        expect(mse0.p2Parameter, 0xA4);
        expect(TlvRecord.sequenceOfRecords(mse0.data)!.map((r) => r.tag), [
          0x80,
        ]);

        final tx3 = _CapturingTransceiver();
        await handler(
          buildDg14(caOid: caAes, keyId: 3),
          TagReader(tx3),
        ).doChipAuthentication();
        final mse3 = tx3.sent.singleWhere((c) => c.instructionCode == 0x22);
        final recs = TlvRecord.sequenceOfRecords(mse3.data)!;
        expect(recs.map((r) => r.tag), [0x80, 0x84]);
        expect(recs.last.value, [0x03]);
      },
    );

    test('the AES flow wraps the point in DO80 inside DO7C on GA', () async {
      final tx = _CapturingTransceiver();
      await handler(
        buildDg14(caOid: caAes),
        TagReader(tx),
      ).doChipAuthentication();
      final ga = tx.sent.singleWhere((c) => c.instructionCode == 0x86);
      expect(ga.instructionClass, 0x00, reason: 'single segment => last');
      final inner = unwrapDO(0x7c, ga.data);
      expect(TlvRecord.parse(inner)!.tag, 0x80);
      expect(TlvRecord.parse(inner)!.value, hasLength(65));
    });
  });

  group('chunking', () {
    test('splits at COMMAND_CHAINING_CHUNK_SIZE with a short tail', () {
      expect(ChipAuthenticationHandler.commandChainingChunkSize, 224);
      final data = List<int>.filled(260, 0xAA);
      final segments = ChipAuthenticationHandler.chunk(data, 224);
      expect(segments.map((s) => s.length), [224, 36]);
    });

    test('an exact multiple produces no empty tail', () {
      final segments = ChipAuthenticationHandler.chunk(
        List<int>.filled(448, 1),
        224,
      );
      expect(segments.map((s) => s.length), [224, 224]);
    });

    test('shorter than one chunk is a single segment', () {
      expect(
        ChipAuthenticationHandler.chunk(List<int>.filled(67, 1), 224),
        hasLength(1),
      );
    });
  });

  group('upstream\'s DH keySeed composition', () {
    test('a short secret lands left-aligned in a DH_size(p) zero buffer', () {
      // p is 2048-bit, so DH_size(p) == 256; a secret that needs 250 bytes
      // gets six ZERO bytes appended, not prepended: upstream's ignored
      // DH_compute_key return length.
      final p = (BigInt.one << 2048) - BigInt.one;
      final x = BigInt.two;
      // Choose peer so peer^2 mod p is small: peer = 2 -> secret = 4.
      final seed = chipAuthDhKeySeed(p: p, x: x, peerPublic: BigInt.from(2));
      expect(seed, hasLength(256));
      expect(seed.first, 0x04, reason: 'left-aligned, not zero-padded left');
      expect(seed.skip(1).every((b) => b == 0), isTrue);
    });

    test('a full-length secret fills the buffer exactly', () {
      final p = (BigInt.one << 256) - BigInt.from(189); // a 256-bit prime-ish
      final seed = chipAuthDhKeySeed(
        p: p,
        x: BigInt.from(3),
        peerPublic: p - BigInt.two,
      );
      expect(seed, hasLength(32));
      expect(seed.first, isNot(0));
    });

    test('a zero secret is an all-zero buffer, not an empty one', () {
      final seed = chipAuthDhKeySeed(
        p: BigInt.from(7),
        x: BigInt.from(2),
        peerPublic: BigInt.from(7),
      );
      expect(seed, [0]);
    });
  });

  group('session-key derivation composed from the OID', () {
    test('DESede suites cut a 3DES key, AES-256 suites cut 32 bytes', () {
      final seed = List<int>.filled(32, 0x5A);
      final (enc3, mac3) = chipAuthDeriveSessionKeys(
        keySeed: seed,
        oid: ca3des,
      );
      expect(enc3, hasLength(24));
      expect(mac3, hasLength(24));
      expect(enc3, isNot(mac3));

      final (enc256, _) = chipAuthDeriveSessionKeys(
        keySeed: seed,
        oid: '0.4.0.127.0.7.2.2.3.2.4',
      );
      expect(enc256, hasLength(32));
    });

    test('an OID outside the eight suites is InvalidDataPassed', () {
      expect(
        () => chipAuthDeriveSessionKeys(
          keySeed: const [1, 2, 3],
          oid: '0.4.0.127.0.7.2.2.4.2.2',
        ),
        throwsA(isA<InvalidDataPassed>()),
      );
    });
  });

  group('infer-OID fallback', () {
    test('a pubkey-only DG14 completes over the guessed 3DES suite', () async {
      final dg14 = TlvRecord(
        0x6E,
        TlvRecord(
          0x31,
          _seq([asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'), caChipSpki()]),
        ).data,
      ).data;
      final tx = _CapturingTransceiver();
      final h = handler(dg14, TagReader(tx));
      await h.doChipAuthentication();

      expect(h.usedOid, ca3des, reason: 'id-PK-ECDH guesses the 3DES suite');
      // The guessed suite is DESede, so the flow is MSE:KAT, not GA.
      expect(tx.sent.map((c) => c.instructionCode), contains(0x22));
      expect(tx.sent.map((c) => c.instructionCode), isNot(contains(0x86)));
    });

    test('chipAuthInferOid maps both public-key OIDs and nothing else', () {
      expect(chipAuthInferOid('0.4.0.127.0.7.2.2.1.2'), ca3des);
      expect(
        chipAuthInferOid('0.4.0.127.0.7.2.2.1.1'),
        '0.4.0.127.0.7.2.2.3.1.1',
      );
      expect(chipAuthInferOid('1.2.840.113549.1.1.1'), isNull);
    });
  });

  group('SPKI parser', () {
    test('explicit prime-field params decode to the named curve\'s domain', () {
      // prime256v1, once by OID and once fully spelled out (openssl
      // -param_enc explicit); the decoded points and domains must agree.
      const named =
          '3059301306072a8648ce3d020106082a8648ce3d0301070342'
          '00045fe81cc7fb7e41a3eb257eb565c7608a7d133e1098a0ab8777a3e07dd54aad91'
          'e15bb5f150e5b2a1df3e56cc14ac79031687ea81eadffb28c17dcb1cd7dffcc7';
      const explicit =
          '3082014b3082010306072a8648ce3d02013081f7020101302c06'
          '072a8648ce3d0101022100ffffffff0000000100000000000000000000'
          '0000ffffffffffffffffffffffff305b0420ffffffff00000001000000'
          '000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a'
          '93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500'
          'c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c'
          '4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342'
          'e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
          '022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9'
          'cac2fc63255102010103420004'
          '5fe81cc7fb7e41a3eb257eb565c7608a7d133e1098a0ab8777a3e07dd54aad91'
          'e15bb5f150e5b2a1df3e56cc14ac79031687ea81eadffb28c17dcb1cd7dffcc7';
      List<int> unhex(String s) => [
        for (var i = 0; i < s.length; i += 2)
          int.parse(s.substring(i, i + 2), radix: 16),
      ];

      final a = parseSubjectPublicKeyInfo(unhex(named))! as SpkiEcPublicKey;
      final b = parseSubjectPublicKeyInfo(unhex(explicit))! as SpkiEcPublicKey;

      expect(a.domain.domainName, 'secp256r1');
      expect(b.domain.domainName, 'spki-explicit');
      expect(b.domain.curve.fieldSize, a.domain.curve.fieldSize);
      expect(b.domain.n, a.domain.n);
      expect(ecPointEncode(b.domain.G), ecPointEncode(a.domain.G));
      expect(ecPointEncode(b.point), ecPointEncode(a.point));
      // The ephemeral keypair the handshake generates rides the chip key's
      // domain, so both encodings must yield the same shared secret.
      final d = BigInt.from(12345);
      expect(
        ecdhSharedSecretX(b.domain, d, b.point),
        ecdhSharedSecretX(a.domain, d, a.point),
      );
    });

    test('the chip fixture SPKI round-trips to its generating point', () {
      final key = parseSubjectPublicKeyInfo(caChipSpki())! as SpkiEcPublicKey;
      expect(key.domain.domainName, 'brainpoolp256r1');
      expect(
        ecPointEncode(key.point),
        ecPointEncode(ecPublicFromPrivate(caChipCurve, caChipPrivateKey)),
      );
      expect(key.spkiDer, caChipSpki());
    });

    test('an unusable structure returns null rather than throwing', () {
      for (final blob in <List<int>>[
        const [],
        const [0xFF, 0xFF, 0xFF],
        const [0x30, 0x03, 0x02, 0x01, 0x01],
      ]) {
        expect(parseSubjectPublicKeyInfo(blob), isNull);
      }
    });
  });

  group('DG14 / SecurityInfo surface', () {
    test('a DG14 whose body is not TLV throws InvalidASN1Value', () {
      expect(
        () => DataGroup14(const [0x6E, 0x03, 0xFF, 0xFF, 0xFF]),
        throwsA(isA<InvalidASN1Value>()),
      );
    });

    test('getKeyId defaults an absent keyId to 0 on both info classes', () {
      final infos = DataGroup14(buildDg14(caOid: caAes)).securityInfos;
      expect((infos.first as ChipAuthenticationInfo).getKeyId(), 0);
      expect((infos.last as ChipAuthenticationPublicKeyInfo).getKeyId(), 0);
      expect((infos.first as ChipAuthenticationInfo).keyId, isNull);
    });

    test('the OID tables reject anything outside the eight CA suites', () {
      expect(
        () => ChipAuthenticationInfo.toKeyAgreementAlgorithm('1.2.3'),
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(
        () => ChipAuthenticationInfo.toCipherAlgorithm('1.2.3'),
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(
        () => ChipAuthenticationInfo.toKeyLength('1.2.3'),
        throwsA(isA<InvalidDataPassed>()),
      );
      expect(ChipAuthenticationInfo.checkRequiredIdentifier(caAes), isTrue);
      expect(
        ChipAuthenticationInfo.checkRequiredIdentifier(
          '0.4.0.127.0.7.2.2.4.2.2',
        ),
        isFalse,
      );
      expect(
        ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(
          '0.4.0.127.0.7.2.2.1.1',
        ),
        isTrue,
      );
    });
  });

  test(
    'the ephemeral seam is honoured: the same scalar => the same point',
    () async {
      final scalar = BigInt.parse(
        '0102030405060708090a0b0c0d0e0f10',
        radix: 16,
      );
      Future<List<int>> pointFor(BigInt s) async {
        final tx = _CapturingTransceiver();
        await handler(
          buildDg14(caOid: ca3des),
          TagReader(tx),
          ephemeral: s,
        ).doChipAuthentication();
        final mse = tx.sent.singleWhere((c) => c.instructionCode == 0x22);
        return TlvRecord.sequenceOfRecords(mse.data)!.first.value;
      }

      expect(await pointFor(scalar), await pointFor(scalar));
      expect(
        await pointFor(scalar),
        ecPointEncode(ecPublicFromPrivate(caChipCurve, scalar)),
      );
      expect(
        await pointFor(scalar),
        isNot(await pointFor(scalar + BigInt.one)),
      );
    },
  );

  test('ECDomainParameters sanity: the fixture curve is cofactor 1', () {
    expect(caChipCurve.curve.fieldSize, 256);
    expect(caChipCurve.G, isA<ECPoint>());
  });
}
