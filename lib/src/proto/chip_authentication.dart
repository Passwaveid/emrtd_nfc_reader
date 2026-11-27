// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/ChipAuthenticationHandler.swift @ 3bf5456 (2.3.2)
//   The folded OpenSSLUtils helpers (`getPublicKeyData`/`computeSharedSecret`,
//   OpenSSLUtils.swift:592-727) come in as private helpers composed from
//   `crypto/ec_dh.dart`, as the PACE port does. Not ported:
//   `restartSecureMessaging`'s unused `maxTranceiveLength`/`shouldCheckMAC`
//   parameters and the never-called
//   `inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation` duplicate
//   (`crypto/kdf.dart` owns the live copy).

/// Chip Authentication: TR-03110 CA over the chip's DG14 static key.
/// Generates an ephemeral keypair on the *chip key's own* domain parameters,
/// sends the public half (MSE:Set KAT for the DESede suites, MSE:Set AT +
/// chained GENERAL AUTHENTICATE for the AES suites), derives the shared
/// secret, and restarts secure messaging with the CA session keys.
///
/// Quirks preserved, each pinned by a vector or transcript:
/// - the infer-OID fallback for pubkey-only DG14s (French-passport
///   accommodation): unknown pubkey OID skips the key rather than erroring;
/// - the first-success key loop with per-key errors swallowed;
/// - the MSE DO84 asymmetry (KAT emits it for keyId 0, Set AT does not);
/// - keyId map last-wins on duplicates;
/// - the DH keySeed composition ([chipAuthDhKeySeed]);
/// - SSC reset to eight zero bytes on restart.
///
/// Beyond upstream: the key loop still swallows each key's error, but
/// classifies it first, and a handshake that fails records why on
/// [ChipAuthenticationHandler.failure].
///
/// Spec-conformance gaps inherited from upstream and left as they are:
/// **no explicit key confirmation**: the MSE:KAT response body and the GA
/// responses are never inspected, so a key-agreement mismatch surfaces as the
/// *next* SM-protected command failing; and **v1/v2 conflation**: the CA
/// version is stored but never consulted, the flow is selected by the OID's
/// cipher alone.
library;

import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';

import '../crypto/ec_dh.dart';
import '../crypto/kdf.dart';
import '../crypto/mac.dart';
import '../crypto/rng.dart';
import '../errors.dart';
import '../lds/chip_authentication_info.dart';
import '../lds/chip_authentication_public_key_info.dart';
import '../lds/data_group14.dart';
import '../lds/security_info.dart';
import '../lds/subject_public_key_info.dart';
import '../lds/tlv.dart';
import '../logging.dart';
import '../utils.dart';
import 'secure_messaging.dart';
import 'tag_reader.dart';

/// Why a Chip Authentication handshake failed. A closed set, so a
/// trace can carry it without free text. The first two mean a declared
/// transport cap refused the command, so it was never sent.
enum ChipAuthenticationFailure {
  /// A handshake command needed extended length and the transport does not
  /// declare support for it.
  extendedLengthUnsupported,

  /// A handshake command was longer than the transport's
  /// `maxTransceiveLength`.
  exceedsTransceiveLength,

  /// The transport failed while carrying a handshake command: the tag was
  /// lost, the command timed out or was cancelled, or the platform failed.
  transceiveFailed,

  /// The chip answered a handshake command with an error status word.
  chipRefused,

  /// The chip's answer to a handshake command failed the terminal's checks:
  /// a secure-messaging MAC or structure error, or a missing `7C` object.
  responseInvalid,

  /// The terminal's own side failed with no command at fault: a key CA
  /// cannot use (RSA), or generating the ephemeral key pair, the key
  /// agreement or the session-key derivation threw.
  localFailure,
}

/// Upstream `ChipAuthenticationHandler`.
class ChipAuthenticationHandler {
  /// Upstream `init(dg14:tagReader:)` plus the [random] and
  /// [ephemeralPrivateKey] injection seams.
  ///
  /// [ephemeralPrivateKey] bypasses RNG sampling for the ephemeral keypair
  /// (deterministic transcripts): CA generates exactly one keypair per
  /// attempted chip key, and the injected scalar is reused across the key
  /// loop; absent, the scalar is sampled from [random] (default
  /// [SystemRandom]).
  ChipAuthenticationHandler({
    required DataGroup14 dg14,
    required this.tagReader,
    EmrtdRandom? random,
    this.ephemeralPrivateKey,
  }) : random = random ?? SystemRandom() {
    for (final secInfo in dg14.securityInfos) {
      if (secInfo is ChipAuthenticationInfo) {
        // Last wins on duplicate keyIds.
        chipAuthInfos[secInfo.getKeyId()] = secInfo;
      } else if (secInfo is ChipAuthenticationPublicKeyInfo) {
        chipAuthPublicKeyInfos.add(secInfo);
      }
    }

    if (chipAuthPublicKeyInfos.isNotEmpty) {
      isChipAuthenticationSupported = true;
    }
  }

  final TagReader tagReader;
  final EmrtdRandom random;

  /// Injection seam for deterministic transcripts. Null on the live path.
  final BigInt? ephemeralPrivateKey;

  /// Upstream `COMMAND_CHAINING_CHUNK_SIZE`.
  static const int commandChainingChunkSize = 224;

  /// Upstream `chipAuthInfos`, keyed by `keyId ?? 0`.
  final Map<int, ChipAuthenticationInfo> chipAuthInfos = {};

  /// Upstream `chipAuthPublicKeyInfos`, in DG14 file order.
  final List<ChipAuthenticationPublicKeyInfo> chipAuthPublicKeyInfos = [];

  /// Upstream `gaSegments`.
  List<Uint8List> gaSegments = [];

  /// Upstream `isChipAuthenticationSupported`.
  bool isChipAuthenticationSupported = false;

  /// The CA protocol OID the successful handshake used, null until
  /// [doChipAuthentication] succeeds. No upstream analogue; the reader lifts
  /// it into its trace.
  String? usedOid;

  /// The chip key id the successful handshake used (`keyId` as DG14 carried
  /// it: null when the entry had none).
  int? usedKeyId;

  /// Why the handshake failed, null until [doChipAuthentication] throws
  /// [ChipAuthenticationFailed]. With several DG14 keys it is the
  /// first failure that involved the chip or the transport, and
  /// [ChipAuthenticationFailure.localFailure] only when none did.
  ChipAuthenticationFailure? failure;

  /// The status word the chip refused with, `SW1 << 8 | SW2`, when [failure]
  /// is [ChipAuthenticationFailure.chipRefused]; null otherwise.
  int? failureSw;

  /// Upstream `doChipAuthentication()`.
  ///
  /// Tries every public key in DG14 order; per-key failures are swallowed and
  /// the next key attempted. Throws [ChipAuthenticationFailed] when
  /// none succeeded, having recorded why on [failure], [NotYetSupported]
  /// when DG14 carried no public key at all
  /// (unreachable from the reader, which checks
  /// [isChipAuthenticationSupported] first: upstream parity).
  Future<void> doChipAuthentication() async {
    chipAuthLog.info(
      'Performing Chip Authentication - number of public keys '
      'found - ${chipAuthPublicKeyInfos.length}',
    );
    if (!isChipAuthenticationSupported) {
      throw const NotYetSupported('ChipAuthentication not supported');
    }

    var success = false;
    ({ChipAuthenticationFailure cause, int? sw})? first;
    for (final pubKey in chipAuthPublicKeyInfos) {
      try {
        success = await _doChipAuthenticationWith(pubKey);
        if (success) {
          break;
        }
      } on Object catch (e) {
        // try next key (upstream comment)
        if (first == null ||
            first.cause == ChipAuthenticationFailure.localFailure) {
          first = _classify(e);
        }
      }
    }

    if (!success) {
      failure = first?.cause;
      failureSw = first?.sw;
      throw const ChipAuthenticationFailed();
    }
  }

  /// A throw from outside the command phase is the terminal's own;
  /// inside it, a transport refusal wins, then the error's type decides.
  ({ChipAuthenticationFailure cause, int? sw}) _classify(Object e) {
    if (e is! _HandshakeCommandError) {
      return (cause: ChipAuthenticationFailure.localFailure, sw: null);
    }
    final refusal = tagReader.lastRefusal;
    if (refusal != null) {
      return (
        cause: switch (refusal) {
          TransportRefusal.extendedLengthUnsupported =>
            ChipAuthenticationFailure.extendedLengthUnsupported,
          TransportRefusal.exceedsTransceiveLength =>
            ChipAuthenticationFailure.exceedsTransceiveLength,
        },
        sw: null,
      );
    }
    return switch (e.error) {
      ResponseError(:final sw1, :final sw2) => (
        cause: ChipAuthenticationFailure.chipRefused,
        sw: (sw1 << 8) | sw2,
      ),
      ConnectionError() ||
      TimeOutError() ||
      NoConnectedTag() ||
      UserCanceled() ||
      UnknownError() => (
        cause: ChipAuthenticationFailure.transceiveFailed,
        sw: null,
      ),
      _ => (cause: ChipAuthenticationFailure.responseInvalid, sw: null),
    };
  }

  /// Upstream `doChipAuthentication(with:)`.
  Future<bool> _doChipAuthenticationWith(
    ChipAuthenticationPublicKeyInfo chipAuthPublicKeyInfo,
  ) async {
    // So it turns out that some passports don't have ChipAuthInfo items.
    // So if we do have a ChipAuthInfo the we take the keyId (if present) and
    // OID from there, BUT if we don't then we will try to infer the OID from
    // the public key (upstream comment).
    final keyId = chipAuthPublicKeyInfo.keyId;
    final String chipAuthInfoOID;
    final chipAuthInfo = chipAuthInfos[keyId ?? 0];
    if (chipAuthInfo != null) {
      chipAuthInfoOID = chipAuthInfo.oid;
    } else {
      final oid = chipAuthInferOid(chipAuthPublicKeyInfo.oid);
      if (oid == null) {
        return false;
      }
      chipAuthInfoOID = oid;
    }

    await _doCA(
      keyId: keyId,
      oid: chipAuthInfoOID,
      publicKey: chipAuthPublicKeyInfo.pubKey,
    );
    usedOid = chipAuthInfoOID;
    usedKeyId = keyId;
    return true;
  }

  /// Upstream `doCA(keyId:encryptionDetailsOID:publicKey:)`.
  Future<void> _doCA({
    required int? keyId,
    required String oid,
    required SubjectPublicKey publicKey,
  }) async {
    // Generate Ephemeral Keypair from parameters from DG14 Public key.
    // This should work for both EC and DH keys (upstream comment); upstream
    // does it with EVP_PKEY_keygen off a ctx of the chip's key.
    final ephemeral = _generateEphemeral(publicKey);

    // Send the public key to the passport.
    try {
      await _sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeral);
    } on Object catch (e) {
      throw _HandshakeCommandError(e);
    }

    chipAuthLog.fine('Public Key successfully sent to passport!');

    // Use our ephemeral private key and the passports public key to generate
    // a shared secret (the passport with do the same thing with their private
    // key and our public key) (upstream comment).
    final sharedSecret = _computeSharedSecret(ephemeral, publicKey);

    // Now try to restart Secure Messaging using the new shared secret and
    // (upstream comment, sentence unfinished upstream).
    _restartSecureMessaging(oid: oid, sharedSecret: sharedSecret);
  }

  /// Upstream `sendPublicKey(oid:keyId:pcdPublicKey:)`.
  Future<void> _sendPublicKey({
    required String oid,
    required int? keyId,
    required _EphemeralKeyPair pcdPublicKey,
  }) async {
    final cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
    final keyData = pcdPublicKey.publicKeyData;

    if (cipherAlg.startsWith('DESede')) {
      var idData = <int>[];
      if (keyId != null) {
        // DO84 is emitted for keyId 0 too; intToBytes short-circuits
        // `0 -> [0]` before any padding strip, so it encodes `84 01 00`
        // rather than collapsing to empty.
        idData = wrapDO(0x84, intToBytes(keyId, removePadding: true));
      }
      final wrappedKeyData = wrapDO(0x91, keyData);
      await tagReader.sendMSEKAT(keyData: wrappedKeyData, idData: idData);
    } else if (cipherAlg.startsWith('AES')) {
      await tagReader.sendMSESetATIntAuth(oid: oid, keyId: keyId);
      final data = wrapDO(0x80, keyData);
      gaSegments = chunk(data, commandChainingChunkSize);
      await _handleGeneralAuthentication();
    } else {
      // Unreachable: toCipherAlgorithm returns only DESede/AES. Kept for
      // upstream parity.
      throw InvalidDataPassed('Cipher Algorithm $cipherAlg not supported');
    }
  }

  /// Upstream `handleGeneralAuthentication()` (command chaining): every
  /// segment but the last goes out with CLA `0x10`. GA responses (`7C 00`)
  /// are received and discarded.
  Future<void> _handleGeneralAuthentication() async {
    do {
      // Pull next segment from list (upstream comment).
      final segment = gaSegments.removeAt(0);
      final isLast = gaSegments.isEmpty;

      // send it (upstream comment).
      await tagReader.sendGeneralAuthenticate(data: segment, isLast: isLast);
    } while (gaSegments.isNotEmpty);
  }

  /// Upstream `restartSecureMessaging(oid:sharedSecret:maxTranceiveLength:
  /// shouldCheckMAC:)`: the last two parameters are accepted and unused
  /// upstream, so they are not ported.
  void _restartSecureMessaging({
    required String oid,
    required List<int> sharedSecret,
  }) {
    final cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
    final (ksEnc, ksMac) = chipAuthDeriveSessionKeys(
      keySeed: sharedSecret,
      oid: oid,
    );

    // Start secure messaging (upstream comment). SSC = eight zero bytes,
    // exactly as the PACE handoff does.
    final ssc = List.filled(8, 0);
    if (cipherAlg.startsWith('DESede')) {
      chipAuthLog.info('Restarting secure messaging using DESede encryption');
      tagReader.secureMessaging = SecureMessaging(
        encryptionAlgorithm: SecureMessagingSupportedAlgorithms.des,
        ksenc: ksEnc,
        ksmac: ksMac,
        ssc: ssc,
      );
    } else if (cipherAlg.startsWith('AES')) {
      chipAuthLog.info('Restarting secure messaging using AES encryption');
      tagReader.secureMessaging = SecureMessaging(
        encryptionAlgorithm: SecureMessagingSupportedAlgorithms.aes,
        ksenc: ksEnc,
        ksmac: ksMac,
        ssc: ssc,
      );
    } else {
      // Unreachable, as above; kept for upstream parity.
      chipAuthLog.severe(
        'Not restarting secure messaging as unsupported '
        'cipher algorithm requested - $cipherAlg',
      );
      throw InvalidDataPassed('Unsupported cipher algorithm $cipherAlg');
    }
  }

  /// Upstream `EVP_PKEY_keygen` off a ctx of the chip's key: the ephemeral
  /// keypair lives on the chip key's own domain parameters.
  _EphemeralKeyPair _generateEphemeral(SubjectPublicKey publicKey) {
    switch (publicKey) {
      case SpkiEcPublicKey(:final domain):
        final injected = ephemeralPrivateKey;
        if (injected != null) {
          return _EcEphemeral(
            domain,
            injected,
            ecPublicFromPrivate(domain, injected),
          );
        }
        final kp = ecGenerateKeyPair(domain, random);
        return _EcEphemeral(domain, kp.d, kp.q);
      case SpkiDhPublicKey(:final p, :final g, :final q):
        final injected = ephemeralPrivateKey;
        if (injected != null) {
          return _DhEphemeral(p, injected, dhPublic(p, g, injected));
        }
        final kp = dhGenerateKeyPair(p: p, g: g, q: q, rng: random);
        return _DhEphemeral(p, kp.x, kp.y);
      case SpkiRsaPublicKey():
        // CA has no RSA flow. Upstream reaches the same dead end by a longer
        // route: `d2i_PUBKEY` happily returns an RSA `EVP_PKEY`, and
        // `getPublicKeyData` then falls through both of its branches and
        // yields `[]`, so the MSE it sends is malformed and the chip refuses
        // it. Either way this key fails and the loop tries the next one
        // (the throw is swallowed by doChipAuthentication).
        throw const InvalidDataPassed(
          'Chip Authentication does not support RSA public keys',
        );
    }
  }

  /// Upstream `OpenSSLUtils.computeSharedSecret(privateKeyPair:publicKey:)`
  /// composed from the `crypto/ec_dh.dart` primitives.
  Uint8List _computeSharedSecret(
    _EphemeralKeyPair ephemeral,
    SubjectPublicKey publicKey,
  ) {
    switch (ephemeral) {
      case _EcEphemeral(:final domain, :final d):
        if (publicKey is! SpkiEcPublicKey) {
          throw const InvalidDataPassed(
            'Chip Authentication key type mismatch (EC ephemeral)',
          );
        }
        // EVP_PKEY_derive parity: x-coordinate, zero-padded to field length.
        return ecdhSharedSecretX(domain, d, publicKey.point);
      case _DhEphemeral(:final p, :final x):
        if (publicKey is! SpkiDhPublicKey) {
          throw const InvalidDataPassed(
            'Chip Authentication key type mismatch (DH ephemeral)',
          );
        }
        return chipAuthDhKeySeed(p: p, x: x, peerPublic: publicKey.y);
    }
  }

  /// Upstream `chunk(data:segmentSize:)`.
  static List<Uint8List> chunk(List<int> data, int segmentSize) {
    final out = <Uint8List>[];
    for (var i = 0; i < data.length; i += segmentSize) {
      final end = i + segmentSize < data.length ? i + segmentSize : data.length;
      out.add(Uint8List.fromList(data.sublist(i, end)));
    }
    return out;
  }
}

/// Upstream `inferOID(fromPublicKeyOID:)`: "Infer OID from public key type -
/// Best guess seems to be to use 3DES_CBC_CBC for both ECDH and DH keys.
/// Apparently works for French passports" (upstream comment). Returns null
/// for any other public-key OID, which skips that key.
///
/// Top-level so conformance can pin it (upstream keeps it private on the
/// handler).
String? chipAuthInferOid(String fromPublicKeyOID) {
  if (fromPublicKeyOID == SecurityInfo.ID_PK_ECDH_OID) {
    chipAuthLog.warning(
      'No ChipAuthenticationInfo - guessing its id-CA-ECDH-3DES-CBC-CBC',
    );
    return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID;
  } else if (fromPublicKeyOID == SecurityInfo.ID_PK_DH_OID) {
    chipAuthLog.warning(
      'No ChipAuthenticationInfo - guessing its id-CA-DH-3DES-CBC-CBC',
    );
    return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID;
  }

  chipAuthLog.warning(
    'No ChipAuthenticationInfo and unsupported '
    'ChipAuthenticationPublicKeyInfo public key OID $fromPublicKeyOID',
  );
  return null;
}

/// The CA session keys for [oid] over [keySeed]: the
/// `SecureMessagingSessionKeyGenerator` KDF driven with the OID's cipher
/// algorithm and key length (ENC then MAC mode). Top-level so conformance can
/// pin the composition without installing a session.
(Uint8List ksEnc, Uint8List ksMac) chipAuthDeriveSessionKeys({
  required List<int> keySeed,
  required String oid,
}) {
  final cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid);
  final keyLength = ChipAuthenticationInfo.toKeyLength(oid);
  const smskg = SecureMessagingSessionKeyGenerator();
  final ksEnc = smskg.deriveKey(
    keySeed: keySeed,
    cipherAlgName: cipherAlg,
    keyLength: keyLength,
    mode: SMSMode.encMode,
  );
  final ksMac = smskg.deriveKey(
    keySeed: keySeed,
    cipherAlgName: cipherAlg,
    keyLength: keyLength,
    mode: SMSMode.macMode,
  );
  return (ksEnc, ksMac);
}

/// The CA-DH keySeed, reproducing upstream's quirk byte-for-byte.
///
/// `computeSharedSecret` allocates a `DH_size(p)`-byte **pre-zeroed** buffer
/// and ignores `DH_compute_key`'s return length, so a secret whose big-endian
/// form has leading zero bytes lands **left-aligned** with trailing zero fill
/// instead of being right-aligned in a p-sized field. The derived keys are
/// therefore upstream's, not the spec's, whenever the secret is short; both
/// runners agree because both reproduce the same quirk.
Uint8List chipAuthDhKeySeed({
  required BigInt p,
  required BigInt x,
  required BigInt peerPublic,
}) {
  final stripped = bigIntToBytes(dhSharedSecret(p, x, peerPublic));
  final out = Uint8List((p.bitLength + 7) >> 3); // DH_size(p)
  out.setRange(0, stripped.length, stripped);
  return out;
}

/// Marks a throw from the command phase of a handshake, so the key loop can
/// tell it from the terminal's own failures.
final class _HandshakeCommandError {
  const _HandshakeCommandError(this.error);

  final Object error;
}

/// The ephemeral keypair the handshake generates on the chip key's domain.
sealed class _EphemeralKeyPair {
  const _EphemeralKeyPair();

  /// Upstream `OpenSSLUtils.getPublicKeyData(from:)`.
  Uint8List get publicKeyData;
}

final class _EcEphemeral extends _EphemeralKeyPair {
  const _EcEphemeral(this.domain, this.d, this.q);

  final ECDomainParameters domain;
  final BigInt d;
  final ECPoint q;

  /// `EC_POINT_point2oct` in the key's conversion form, always uncompressed
  /// here (real DG14 keys are uncompressed, so upstream's inherited
  /// conversion form matches).
  @override
  Uint8List get publicKeyData => ecPointEncode(q);
}

final class _DhEphemeral extends _EphemeralKeyPair {
  const _DhEphemeral(this.p, this.x, this.y);

  final BigInt p;
  final BigInt x;
  final BigInt y;

  /// `BN_bn2bin(pub)`: minimal big-endian, leading zeros stripped.
  @override
  Uint8List get publicKeyData => bigIntToBytes(y);
}
