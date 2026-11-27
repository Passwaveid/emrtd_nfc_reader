// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/PACEHandler.swift @ 3bf5456 (2.3.2)
//   minus the dead `handleError`/`paceError` (never called; sole writer of a
//   field nothing reads) and the OpenSSL error-queue formatting; the folded
//   OpenSSLUtils helpers (getPublicKeyData/decodePublicKeyFromBytes/
//   computeSharedSecret, OpenSSLUtils.swift:592-727) come in as private
//   helpers composed from crypto/ec_dh.dart.

/// PACE: Password Authenticated Connection Establishment. Runs the MSE:Set
/// AT + four GENERAL AUTHENTICATE rounds through `TagReader`, derives the
/// session keys and installs an AES/DES `SecureMessaging` session. Section
/// numbers refer to ICAO 9303 Part 11, written P11, unless another document
/// is named.
///
/// Coverage: **ECDH-GM and DH-GM both complete end-to-end**, **Integrated
/// Mapping is implemented for all eight IM OIDs**, and **Chip Authentication
/// Mapping extracts, decrypts and exposes the DO8A chip-authentication
/// data**, beyond upstream (the DG14-key verification itself lives in
/// `PassportReader`). Upstream aborts DH-GM at step 3, stubs IM out and
/// receives-and-ignores the DO8A; those failure surfaces survive as
/// swift-side conformance pins only. All four PACE passwords are live
/// (MRZ/CAN/PIN/CUK: [PacePassword]) where upstream's non-MRZ path is inert.
/// Debugging center is the ECDH pointycastle composition.
///
/// Upstream's lenient step-4 token tag and its message strings are kept
/// verbatim. Its crashes and force-unwraps become typed errors, credential
/// material stays out of the logs, secure messaging restarts with a zero SSC
/// as upstream's does, and the ephemeral keys and the IM nonce can be
/// injected for deterministic transcripts. Dart-only divergences: DH steps
/// 3-4 exist at all, received DH public keys are range/subgroup validated,
/// the step-4 DH shared secret is left-padded to the group length instead of
/// carrying upstream's zero relocation, IM rejects curves with p ≢ 3 (mod 4),
/// the CAM chip-authentication data is decrypted and verified, and the
/// CAN/PIN/CUK passwords are live. See UPSTREAM.md, Divergences.
library;

// Upstream key-reference const names kept verbatim, for diffability.
// ignore_for_file: constant_identifier_names

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

import '../crypto/ciphers.dart';
import '../crypto/ec_dh.dart';
import '../crypto/hashes.dart';
import '../crypto/kdf.dart';
import '../crypto/mac.dart';
import '../crypto/rng.dart';
import '../errors.dart';
import '../lds/card_access.dart';
import '../lds/pace_info.dart';
import '../lds/tlv.dart';
import '../logging.dart';
import '../utils.dart';
import 'secure_messaging.dart';
import 'tag_reader.dart';

/// Upstream `PACEHandler`.
class PACEHandler {
  /// Upstream `init(cardAccess:tagReader:)` plus three injection seams.
  ///
  /// [mappingPrivateKey]/[ephemeralPrivateKey] bypass RNG sampling for the
  /// step-2 mapping keypair and the step-3 ephemeral keypair respectively
  /// (deterministic transcripts); [imNonce] does the same for the Integrated
  /// Mapping's PCD nonce t. Absent, all three are sampled from
  /// [random] (default [SystemRandom]). Throws [NotYetSupported] when
  /// EF.CardAccess carries no `PACEInfo`.
  PACEHandler({
    required this.cardAccess,
    required this.tagReader,
    EmrtdRandom? random,
    this.mappingPrivateKey,
    this.ephemeralPrivateKey,
    this.imNonce,
  }) : random = random ?? SystemRandom(),
       paceInfo =
           cardAccess.paceInfo ??
           (throw const NotYetSupported('PACE not supported'));

  final CardAccess cardAccess;
  final TagReader tagReader;
  final EmrtdRandom random;

  /// Injection seams for deterministic transcripts. Null on the live path.
  final BigInt? mappingPrivateKey;
  final BigInt? ephemeralPrivateKey;

  /// Third injection seam: the Integrated Mapping's PCD nonce t.
  /// Null on the live path (t is sampled from [random]); when injected its
  /// length must be exactly the block cipher's key size in bytes.
  final Uint8List? imNonce;

  /// The selected `PACEInfo` (first in EF.CardAccess file order).
  final PACEInfo paceInfo;

  /// Always true after construction (the ctor throws otherwise); kept for
  /// upstream field parity.
  bool isPACESupported = true;

  // Key-reference consts (SecurityInfo.swift). All four are live; the const
  // names stay upstream's, so "CUK" reads where TR-03110-3 says PUK.
  static const int MRZ_PACE_KEY_REFERENCE = 0x01;
  static const int CAN_PACE_KEY_REFERENCE = 0x02;
  static const int PIN_PACE_KEY_REFERENCE = 0x03;
  static const int CUK_PACE_KEY_REFERENCE = 0x04;

  // Params used (set in doPACE before their first read, mirroring upstream).
  Uint8List _paceKey = Uint8List(0);
  int paceKeyType = 0;
  String paceOID = '';
  PACEMappingType? mappingType;
  String agreementAlg = '';
  String cipherAlg = '';
  String digestAlg = '';
  int keyLength = -1;

  /// The chip's mapping public key PK_Map,IC, retained from step 2 for the
  /// CAM verification. Only populated on a CAM session: the GM/IM paths
  /// consume the DO82 locally and drop it, as upstream does.
  Uint8List? _camMappingPublicKey;

  /// The CAM chip-authentication data the final GA response carried, null
  /// unless a CAM session reached step 4. Verifying it against the chip's
  /// DG14 key is the reader's job; the handler only extracts and decrypts,
  /// and never fails PACE over it.
  PaceCamData? camData;

  /// Upstream `doPACE(mrzKey:)`: the MRZ convenience over
  /// [doPACEWithPassword]. On success sets
  /// [TagReader.secureMessaging].
  Future<void> doPACE(String mrzKey) =>
      doPACEWithPassword(PacePassword.mrz(mrzKey));

  /// The real implementation behind [doPACE]: PACE with any of the four
  /// passwords P11 §9.7.3 Table 14 / TR-03110-3 Table 5 define.
  ///
  /// [password] supplies both halves the protocol needs: the DO83 key
  /// reference the MSE:Set AT emits and f(π), the seed K_π derives from. The
  /// derivation itself is password-type-independent (KDF_π(π) = KDF(f(π), 3)),
  /// which is why `deriveKey`'s `paceKeyReference` argument stays inert (the
  /// password type matters here, at the call site, not in `kdf.dart`).
  ///
  /// Caution for PIN/PUK documents: a wrong attempt decrements the chip's
  /// retry counter, and this package does **not** manage counters; tracking
  /// remaining attempts and any RESET RETRY COUNTER flow is consumer
  /// responsibility.
  ///
  /// On success sets [TagReader.secureMessaging].
  Future<void> doPACEWithPassword(PacePassword password) async {
    if (!isPACESupported) {
      throw const NotYetSupported('PACE not supported');
    }

    paceLog.info('Performing PACE with ${paceInfo.getProtocolOIDString()}');

    paceOID = paceInfo.getObjectIdentifier();
    // Resolves (and validates) the standardized domain parameters up front,
    // as upstream does; the value itself is re-fetched inside createMappingKey.
    paceInfo.getParameterSpec();

    mappingType = paceInfo.getMappingType(); // GM, CAM, or IM
    agreementAlg = paceInfo.getKeyAgreementAlgorithm(); // DH or ECDH
    cipherAlg = paceInfo.getCipherAlgorithm(); // DESede or AES
    digestAlg = paceInfo.getDigestAlgorithm(); // SHA-1 or SHA-256
    keyLength = paceInfo.getKeyLength(); // 128, 192, or 256

    paceKeyType = password.keyReference;
    _paceKey = createPaceKey(password);

    // Upstream's debug lines printing mrzKey and paceKey are dropped
    // (long-lived credential material), and the same redaction covers
    // PacePassword.keySeed; no password value of any type is ever logged.
    // Session-ephemeral intermediates stay logged, for log parity with
    // upstream.
    paceLog.fine(
      'doPACE - paceOID $paceOID, mappingType '
      '${mappingType?.description()}, agreementAlg $agreementAlg, cipherAlg '
      '$cipherAlg, digestAlg $digestAlg, keyLength $keyLength',
    );

    // DO84 (parameterId) emitted in MSE:Set AT when the PACEInfo carries a
    // parameterId (a Dart-only addition); upstream never sends it.
    await tagReader.sendMSESetATMutualAuth(
      oid: paceOID,
      keyType: paceKeyType,
      parameterId: paceInfo.getParameterId(),
    );

    final decryptedNonce = await doStep1();
    final ephemeralParams = await doStep2(decryptedNonce);
    final (ephemeralKeyPair, passportPublicKey) = await doStep3KeyExchange(
      ephemeralParams,
    );
    final (encKey, macKey) = await doStep4KeyAgreement(
      pcdKeyPair: ephemeralKeyPair,
      passportPublicKey: passportPublicKey,
    );
    paceCompleted(encKey, macKey);
    paceLog.fine('PACE SUCCESSFUL');
  }

  /// Upstream `doStep1()`. Receive the encrypted nonce and decrypt it with
  /// the PACE key (all-zero IV, unpadded ICAO `z`).
  Future<Uint8List> doStep1() async {
    paceLog.fine('Doing PACE Step1...');
    final response = await tagReader.sendGeneralAuthenticate(
      data: const [],
      isLast: false,
    );
    final encryptedNonce = unwrapDO(0x80, response.data);
    paceLog.fine(
      'Encrypted nonce - ${binToHexRep(encryptedNonce, asArray: true)}',
    );

    final Uint8List decryptedNonce;
    if (cipherAlg == 'DESede') {
      decryptedNonce = tripleDESDecrypt(
        _paceKey,
        encryptedNonce,
        List.filled(8, 0),
      );
    } else if (cipherAlg == 'AES') {
      decryptedNonce = aesDecrypt(_paceKey, encryptedNonce, List.filled(16, 0));
    } else {
      throw const UnsupportedCipherAlgorithm();
    }

    paceLog.fine(
      'Decrypted nonce - ${binToHexRep(decryptedNonce, asArray: true)}',
    );
    return decryptedNonce;
  }

  /// Upstream `doStep2(passportNonce:)`: GM/CAM route through the GM path,
  /// IM through [doPACEStep2IM] (a throwing stub upstream).
  Future<PACEEphemeralParams> doStep2(List<int> passportNonce) async {
    paceLog.fine('Doing PACE Step2...');
    switch (mappingType) {
      case PACEMappingType.CAM:
      case PACEMappingType.GM:
        paceLog.fine('   Using General Mapping (GM)...');
        return doPACEStep2GM(passportNonce);
      case PACEMappingType.IM:
        paceLog.fine('   Using Integrated Mapping (IM)...');
        return doPACEStep2IM(passportNonce);
      case null:
        throw const PACEError('Step2GM', 'Unsupported Mapping Type');
    }
  }

  /// Upstream `doPACEStep2GM(passportNonce:)`.
  Future<PACEEphemeralParams> doPACEStep2GM(List<int> passportNonce) async {
    final mappingKey = paceInfo.createMappingKey(
      random: random,
      privateKey: mappingPrivateKey,
    );

    final pcdMappingEncodedPublicKey = _getPublicKeyData(mappingKey.publicKey);
    paceLog.fine(
      'public mapping key - '
      '${binToHexRep(pcdMappingEncodedPublicKey, asArray: true)}',
    );

    final step2Data = wrapDO(0x81, pcdMappingEncodedPublicKey);
    final response = await tagReader.sendGeneralAuthenticate(
      data: step2Data,
      isLast: false,
    );

    final piccMappingEncodedPublicKey = unwrapDO(0x82, response.data);
    paceLog.fine(
      'Received passports public mapping key - '
      '${binToHexRep(piccMappingEncodedPublicKey, asArray: true)}',
    );

    // CAM verifies PK_Map,IC = KA(CA_IC, PK_IC, D_IC) after the protocol
    // ends, so the chip's mapping public key is retained here (as bytes; it
    // is decoded on the PACE domain at verify time). GM/IM sessions drop it,
    // as upstream does.
    if (mappingType == PACEMappingType.CAM) {
      _camMappingPublicKey = piccMappingEncodedPublicKey;
    }

    final nonce = bytesToBigInt(passportNonce);
    if (agreementAlg == 'DH') {
      paceLog.fine('Doing DH Mapping agreement');
      return doDHMappingAgreement(
        mappingKey: mappingKey,
        passportPublicKeyData: piccMappingEncodedPublicKey,
        nonce: nonce,
      );
    } else if (agreementAlg == 'ECDH') {
      paceLog.fine('Doing ECDH Mapping agreement');
      return doECDHMappingAgreement(
        mappingKey: mappingKey,
        passportPublicKeyData: piccMappingEncodedPublicKey,
        nonce: nonce,
      );
    } else {
      throw const PACEError('Step2GM', 'Unsupported agreement algorithm');
    }
  }

  /// Upstream `doPACEStep2IM(passportNonce:)`, a stub there that throws after
  /// MSE:AT and the step-1 nonce exchange have already hit the chip.
  /// Implemented here per P11 §4.4.3.3.2: a nonce-t round on the wire, then
  /// the pseudo-random mapping R_p(s,t) followed by f_g (DH) or f_G (ECDH,
  /// App B.2 affine).
  ///
  /// The Swift stub throw survives as a swift-side conformance pin
  /// (`transcripts/pace_session_im_partial.json`).
  Future<PACEEphemeralParams> doPACEStep2IM(List<int> passportNonce) async {
    // The parameter guard runs at entry, *before* the t round; the same wire
    // point the upstream stub aborts at (MSE:AT + GA1 have hit the chip, GA2
    // is never sent).
    final spec = paceInfo.getParameterSpec();
    final imCipher = _PaceImCipher.forSuite(cipherAlg, keyLength);
    if (agreementAlg == 'ECDH') {
      if (spec is! ECStandardizedDomain) {
        throw const PACEError('Step2IM', 'Unable to create EC mapping key');
      }
      // P11 §9.5.1 Table 12 footnote / App B: the point encoding requires
      // p ≡ 3 (mod 4). Only parameterId 10 (NIST P-224) fails it among the
      // standardized domains, but the test is written on p itself so any
      // future curve is covered.
      final p = _fpFieldPrime(spec.domain);
      if (p % _four != _three) {
        throw PACEError(
          'Step2IM',
          'Integrated Mapping is not defined for ${spec.domain.domainName}: '
              'the App B point encoding requires p = 3 mod 4 (P11 §9.5.1 '
              'Table 12 footnote; parameterId 10 / NIST P-224)',
        );
      }
    } else if (agreementAlg == 'DH') {
      if (spec is! DHStandardizedDomain) {
        throw const PACEError('Step2IM', 'Unable to create DH mapping key');
      }
    } else {
      throw const PACEError('Step2IM', 'Unsupported agreement algorithm');
    }

    // §4.4.3.3: t is k bits wide, k = the key size of the block cipher E
    // (3DES counts as 128). Injected for deterministic replay, otherwise
    // sampled.
    final Uint8List t;
    if (imNonce != null) {
      if (imNonce!.length != imCipher.keyBytes) {
        throw PACEError(
          'Step2IM',
          'Injected IM nonce is ${imNonce!.length} bytes, expected '
              '${imCipher.keyBytes} for $cipherAlg-$keyLength',
        );
      }
      t = imNonce!;
    } else {
      t = random.nextBytes(imCipher.keyBytes);
    }
    paceLog.fine('IM nonce t - ${binToHexRep(t, asArray: true)}');

    // §4.4.5.2.2: "The nonce t SHALL be encoded as octet string." The chip's
    // DO82 "SHALL be empty": nothing in the response is consumed, so both
    // `7C 00` and `7C 02 82 00` shapes are tolerated without parsing.
    await tagReader.sendGeneralAuthenticate(
      data: wrapDO(0x81, t),
      isLast: false,
    );

    final BigInt p = switch (spec) {
      DHStandardizedDomain(:final p) => p,
      ECStandardizedDomain(:final domain) => _fpFieldPrime(domain),
    };
    final x = paceImPseudoRandom(
      s: passportNonce,
      t: t,
      p: p,
      cipherAlg: cipherAlg,
      keyLength: keyLength,
    );
    paceLog.fine(
      'IM R_p(s,t) - ${binToHexRep(bigIntToBytes(x.value), asArray: true)}',
    );

    switch (spec) {
      case DHStandardizedDomain(:final p, :final q, :final g):
        // f_g(x) = x^((p-1)/q) mod p, with the §4.4.3.3.2 MUST ĝ ≠ 1 check.
        final ghat = paceImMapDh(p: p, q: q, x: x.value);
        paceLog.fine(
          'IM mapped generator ĝ - '
          '${binToHexRep(bigIntToBytes(ghat), asArray: true)}',
        );
        // g is unused past the mapping (the ephemeral round runs over ĝ), but
        // the group's own generator stays out of the returned params exactly
        // as in the GM path.
        assert(g > BigInt.zero);
        return DhEphemeralParams(p: p, q: q, g: ghat);
      case ECStandardizedDomain(:final domain):
        final ghat = paceImMapEcdh(domain: domain, x: x.value);
        paceLog.fine(
          'IM mapped generator Ĝ - '
          '${binToHexRep(ecPointEncode(ghat), asArray: true)}',
        );
        // As on the GM path: the mapped domain carries the curve's true
        // cofactor (1 for every PACE standardized curve).
        final mapped = ECDomainParametersImpl(
          'pace-im-mapped-${domain.domainName}',
          domain.curve,
          ghat,
          domain.n,
          BigInt.one,
        );
        return EcdhEphemeralParams(mapped);
    }
  }

  /// Upstream `doStep3KeyExchange(ephemeralParams:)`, completed for DH; the
  /// arm switches exhaustively on the sealed [PACEEphemeralParams], and the
  /// EC branch is the straight port.
  ///
  /// Upstream treats the mapped params as EC unconditionally, so
  /// `EVP_PKEY_get0_EC_KEY` returns nil for DH and it throws "Failed to
  /// generate EC key"; every `ID_PACE_DH_*` suite dead-ends there. That abort
  /// is deleted here and survives only as a swift-side conformance pin
  /// (`transcripts/pace_session_dh_gm_partial.json`).
  Future<(PACEMappingKeyPair, PACEPublicKey)> doStep3KeyExchange(
    PACEEphemeralParams ephemeralParams,
  ) async {
    paceLog.fine('Doing PACE Step3 - Key Exchange');

    final PACEMappingKeyPair ephemeralKeyPair;
    switch (ephemeralParams) {
      case EcdhEphemeralParams(:final domain):
        final BigInt d;
        final ECPoint q;
        if (ephemeralPrivateKey != null) {
          d = ephemeralPrivateKey!;
          q = ecPublicFromPrivate(domain, d);
        } else {
          final kp = ecGenerateKeyPair(domain, random);
          d = kp.d;
          q = kp.q;
        }
        ephemeralKeyPair = EcdhMappingKeyPair(
          domain: domain,
          d: d,
          publicPoint: q,
        );
      case DhEphemeralParams(:final p, :final q, :final g):
        // The ephemeral keypair lives in the *mapped* group (p, q, ĝ).
        final BigInt x;
        final BigInt y;
        if (ephemeralPrivateKey != null) {
          x = ephemeralPrivateKey!;
          y = dhPublic(p, g, x);
        } else {
          final kp = dhGenerateKeyPair(p: p, g: g, q: q, rng: random);
          x = kp.x;
          y = kp.y;
        }
        ephemeralKeyPair = DhMappingKeyPair(p: p, q: q, g: g, x: x, y: y);
    }

    final publicKey = _getPublicKeyData(ephemeralKeyPair.publicKey);
    paceLog.fine(
      'Ephemeral public key - ${binToHexRep(publicKey, asArray: true)}',
    );

    final step3Data = wrapDO(0x83, publicKey);
    final response = await tagReader.sendGeneralAuthenticate(
      data: step3Data,
      isLast: false,
    );

    // A missing/mis-tagged DO84 crashes upstream (try? swallowed into a
    // force-unwrap); let unwrapDO's InvalidASN1Value propagate.
    final passportEncodedPublicKey = unwrapDO(0x84, response.data);
    final passportPublicKey = _decodePublicKeyFromBytes(
      passportEncodedPublicKey,
      ephemeralParams,
    );
    if (passportPublicKey == null) {
      // Upstream's nil-return path (EC); the DH range/subgroup rejects take
      // the same message.
      throw const PACEError(
        'Step3 KeyEx',
        'Unable to decode passports ephemeral key',
      );
    }
    paceLog.fine(
      'Received passports ephemeral public key - '
      '${binToHexRep(passportEncodedPublicKey, asArray: true)}',
    );

    return (ephemeralKeyPair, passportPublicKey);
  }

  /// Upstream `doStep4KeyAgreement(pcdKeyPair:passportPublicKey:)`.
  Future<(Uint8List, Uint8List)> doStep4KeyAgreement({
    required PACEMappingKeyPair pcdKeyPair,
    required PACEPublicKey passportPublicKey,
  }) async {
    paceLog.fine('Doing PACE Step4 Key Agreement...');

    final sharedSecret = _computeSharedSecret(
      privateKeyPair: pcdKeyPair,
      publicKey: passportPublicKey,
    );
    paceLog.fine('Shared secret - ${binToHexRep(sharedSecret, asArray: true)}');

    const gen = SecureMessagingSessionKeyGenerator();
    // Upstream's `try!` here is unreachable-failure (cipherAlg pre-checked in
    // step 1); the port lets deriveKey propagate normally.
    final encKey = gen.deriveKey(
      keySeed: sharedSecret,
      cipherAlgName: cipherAlg,
      keyLength: keyLength,
      mode: SMSMode.encMode,
    );
    final macKey = gen.deriveKey(
      keySeed: sharedSecret,
      cipherAlgName: cipherAlg,
      keyLength: keyLength,
      mode: SMSMode.macMode,
    );
    paceLog.fine('encKey - ${binToHexRep(encKey, asArray: true)}');
    paceLog.fine('macKey - ${binToHexRep(macKey, asArray: true)}');

    final pcdAuthToken = generateAuthenticationToken(
      publicKey: passportPublicKey,
      macKey: macKey,
    );
    paceLog.fine(
      'authentication token - ${binToHexRep(pcdAuthToken, asArray: true)}',
    );

    final step4Data = wrapDO(0x85, pcdAuthToken);
    final response = await tagReader.sendGeneralAuthenticate(
      data: step4Data,
      isLast: true,
    );

    // Upstream force-unwraps sequenceOfRecords and indexes [0] on a
    // possibly-empty list; the port uses the nullable API and throws.
    final tvlResp = TlvRecord.sequenceOfRecords(response.data);
    if (tvlResp == null || tvlResp.isEmpty) {
      throw const InvalidASN1Value();
    }
    if (tvlResp[0].tag != 0x86) {
      // Upstream formats the tag with UInt8(tag). A two-byte tag (e.g. 7F49)
      // traps mid-log; the port logs the full tag and continues to use the
      // value as the token.
      paceLog.warning(
        'Was expecting tag 0x86, found: '
        '0x${tvlResp[0].tag.toRadixString(16)}',
      );
    }

    // Upstream's misleading "Step3 KeyAgreement" step label kept verbatim.
    final expectedPICCToken = generateAuthenticationToken(
      publicKey: pcdKeyPair.publicKey,
      macKey: macKey,
    );

    final piccToken = tvlResp[0].value;
    if (!_bytesEqual(piccToken, expectedPICCToken)) {
      throw PACEError(
        'Step3 KeyAgreement',
        'Error PICC Token mismatch!\npicToken - '
            '${_intList(piccToken)}\nexpectedPICCToken - '
            '${_intList(expectedPICCToken)}',
      );
    }
    paceLog.fine('Auth token from passport matches expected token!');

    // Beyond upstream: on CAM the same response carries a DO8A "Encrypted
    // Chip Authentication Data" record, which upstream receives and ignores
    // (its extraction is a commented-out block indexing tvlResp[1]). The
    // port scans for the tag instead (§4.4.5 Table 4 lets the conditional
    // DO87/DO88 CARs sit between DO86 and DO8A) and decrypts it here;
    // verifying it against the chip's DG14 key is the reader's job.
    //
    // Nothing on this path can fail PACE: the token already verified,
    // so the session is good whatever the DO8A looks like. A CAM session
    // whose DO8A is absent (a §4.4.5 MUST violation) or undecryptable
    // records a cause and lets the reader surface it.
    if (mappingType == PACEMappingType.CAM) {
      _extractCamData(tvlResp, encKey);
    }

    return (encKey, macKey);
  }

  /// The handler's half of the CAM completion: tag-scan, decrypt, record.
  /// Never throws: every failure becomes a [PaceCamData.cause].
  void _extractCamData(List<TlvRecord> tvlResp, Uint8List encKey) {
    final mappingPublicKey = _camMappingPublicKey;
    final spec = paceInfo.getParameterSpec();
    if (mappingPublicKey == null || spec is! ECStandardizedDomain) {
      // Unreachable: CAM is ECDH-only (§4.4.3 Note 1, enforced by the OID
      // table) and always maps through doPACEStep2GM, which retains the key.
      paceLog.warning(
        'CAM session reached step 4 without a retained mapping '
        'public key: no chip-authentication data recorded',
      );
      return;
    }
    final domain = spec.domain;

    TlvRecord? do8a;
    for (final rec in tvlResp) {
      if (rec.tag == 0x8A) {
        do8a = rec;
        break;
      }
    }
    if (do8a == null) {
      paceLog.warning(
        'CAM session carried no DO8A: P11 §4.4.5 makes '
        'Encrypted Chip Authentication Data mandatory under CAM',
      );
      camData = PaceCamData(
        domain: domain,
        mappingPublicKey: mappingPublicKey,
        cause: PaceCamFailure.missing,
      );
      return;
    }

    final caIc = paceCamDecryptChipAuthenticationData(
      ksEnc: encKey,
      encryptedData: do8a.value,
      groupOrder: domain.n,
    );
    if (caIc == null) {
      paceLog.warning(
        'CAM DO8A did not decrypt to a well-formed CA_IC '
        '(${do8a.value.length}-byte payload)',
      );
      camData = PaceCamData(
        domain: domain,
        mappingPublicKey: mappingPublicKey,
        cause: PaceCamFailure.malformed,
      );
      return;
    }
    paceLog.fine(
      'CAM decrypted chip authentication data - '
      '${binToHexRep(caIc, asArray: true)}',
    );
    camData = PaceCamData(
      domain: domain,
      mappingPublicKey: mappingPublicKey,
      chipAuthenticationData: caIc,
      chipAuthenticationValue: bytesToBigInt(caIc),
    );
  }

  /// Upstream `paceCompleted(ksEnc:ksMac:)`: restart secure messaging with an
  /// 8-byte zero SSC. DESede -> DES-mode SM, AES -> AES-mode SM.
  void paceCompleted(List<int> ksEnc, List<int> ksMac) {
    final ssc = List.filled(8, 0);
    if (cipherAlg.startsWith('DESede')) {
      paceLog.info('Restarting secure messaging using DESede encryption');
      tagReader.secureMessaging = SecureMessaging(
        encryptionAlgorithm: SecureMessagingSupportedAlgorithms.des,
        ksenc: ksEnc,
        ksmac: ksMac,
        ssc: ssc,
      );
    } else if (cipherAlg.startsWith('AES')) {
      paceLog.info('Restarting secure messaging using AES encryption');
      tagReader.secureMessaging = SecureMessaging(
        encryptionAlgorithm: SecureMessagingSupportedAlgorithms.aes,
        ksenc: ksEnc,
        ksmac: ksMac,
        ssc: ssc,
      );
    } else {
      throw PACEError(
        'PACECompleted',
        'Not restarting secure messaging as unsupported cipher algorithm '
            'requested - $cipherAlg',
      );
    }
  }

  /// Upstream `doDHMappingAgreement(...)`, with two departures: h is taken at
  /// its true integer value (upstream's zero relocation is gone) and the
  /// received DO82 mapping key is range/subgroup validated before it is used.
  PACEEphemeralParams doDHMappingAgreement({
    required PACEMappingKeyPair mappingKey,
    required List<int> passportPublicKeyData,
    required BigInt nonce,
  }) {
    final mk = mappingKey as DhMappingKeyPair;
    // Upstream feeds arbitrary bytes to DH_compute_key unvalidated; the port
    // applies the RFC 2631 check §4.4.3.3.1's DH note calls for. This is
    // the DH analogue of ecPointDecode's on-curve validation on the EC path.
    if (!paceValidateDhPublicKey(
      p: mk.p,
      q: mk.q,
      y: bytesToBigInt(passportPublicKeyData),
    )) {
      throw const PACEError(
        'Step2GM',
        'Unable to decode passports public mapping key',
      );
    }
    final ghat = paceDhMappedGenerator(
      p: mk.p,
      g: mk.g,
      mappingPrivateKey: mk.x,
      peerPublicKeyData: passportPublicKeyData,
      nonce: nonce,
    );
    return DhEphemeralParams(p: mk.p, q: mk.q, g: ghat);
  }

  /// Upstream `doECDHMappingAgreement(...)`.
  PACEEphemeralParams doECDHMappingAgreement({
    required PACEMappingKeyPair mappingKey,
    required List<int> passportPublicKeyData,
    required BigInt nonce,
  }) {
    final mk = mappingKey as EcdhMappingKeyPair;

    final h = computeECDHMappingKeyPoint(
      privateKey: mk,
      inputKey: passportPublicKeyData,
    );
    if (h == null) {
      // Upstream throws the DH path's "Unable to create ephemeral params" in
      // the ECDH case (line 456); here the ECDH mapping has its own failure
      // surface.
      throw const PACEError(
        'ECDHKeyAgreementError',
        'Failed to compute new shared secret mapping point from mapping key '
            'and passport public mapping key',
      );
    }

    // Ĝ = s·G + H (upstream EC_POINT_mul(group, out, nonce, H, BN_value_one())).
    final ghat = ecMulAdd(mk.domain, nonce, mk.domain.G, h);

    // Every PACE standardized curve has cofactor 1, so the mapped
    // domain's true cofactor is 1, not upstream's cofactor-0 (its ||-for-&&
    // guard never fetches it, and no later op consumes it).
    final mapped = ECDomainParametersImpl(
      'pace-mapped-${mk.domain.domainName}',
      mk.domain.curve,
      ghat,
      mk.domain.n,
      BigInt.one,
    );
    return EcdhEphemeralParams(mapped);
  }

  /// Upstream `computeECDHMappingKeyPoint(privateKey:inputKey:)`: H = d·P as
  /// a full point (upstream works around `computeSharedSecret` returning only
  /// the x-coordinate). Returns null on a decode failure, matching upstream's
  /// nil return when `oct2point` fails (`ecPointDecode` validates on-curve).
  ECPoint? computeECDHMappingKeyPoint({
    required PACEMappingKeyPair privateKey,
    required List<int> inputKey,
  }) {
    final mk = privateKey as EcdhMappingKeyPair;
    try {
      final peer = ecPointDecode(mk.domain, inputKey);
      return ecPointMul(mk.domain, mk.d, peer);
    } on InvalidDataPassed {
      return null;
    }
  }

  /// Upstream `generateAuthenticationToken(publicKey:macKey:)`: 8-byte
  /// truncated retail-MAC (DESede) or CMAC (AES) over the TR-SAC `7F49`
  /// encoding of [publicKey].
  Uint8List generateAuthenticationToken({
    required PACEPublicKey publicKey,
    required List<int> macKey,
  }) => paceGenerateAuthenticationToken(
    oid: paceOID,
    cipherAlg: cipherAlg,
    publicKey: publicKey,
    macKey: macKey,
  );

  /// Upstream `encodePublicKey(oid:key:)`: TR-SAC 1.01 §4.5 `7F49` structure.
  Uint8List encodePublicKey({
    required String oid,
    required PACEPublicKey key,
  }) => paceEncodePublicKey(oid, key);

  /// Upstream `createPaceKey(from:)`, generalized to any password:
  /// K_π = KDF(f(π), 3) over [PacePassword.keySeed] in PACE_MODE.
  ///
  /// The [SecureMessagingSessionKeyGenerator.deriveKey] `paceKeyReference`
  /// argument is passed for signature parity and **remains inert**: per P11
  /// §9.7.3 / TR-03110-3 A.2.3 the derivation is password-type-independent,
  /// so the password type is a call-site concern (which seed, which DO83
  /// byte), not a KDF one.
  Uint8List createPaceKey(PacePassword password) => paceCreatePaceKey(
    password: password,
    cipherAlgName: cipherAlg,
    keyLength: keyLength,
  );

  // --- folded OpenSSLUtils helpers (OpenSSLUtils.swift:592-727) -------------

  /// Upstream `OpenSSLUtils.getPublicKeyData(from:)`. EC -> uncompressed
  /// `04‖X‖Y` fixed-length (`point2oct`); DH -> minimal `BN_bn2bin` (leading
  /// zeros stripped).
  Uint8List _getPublicKeyData(PACEPublicKey key) => switch (key) {
    EcdhPublicKey(:final point) => ecPointEncode(point),
    DhPublicKey(:final y) => bigIntToBytes(y),
  };

  /// Upstream `OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData:params:)`.
  /// EC -> `oct2point`, which validates on-curve; DH -> `BN_bin2bn` plus the
  /// range/subgroup validation upstream never performs. A decode or
  /// validation failure returns null (upstream's nil-return).
  PACEPublicKey? _decodePublicKeyFromBytes(
    List<int> data,
    PACEEphemeralParams params,
  ) {
    switch (params) {
      case EcdhEphemeralParams(:final domain):
        try {
          return EcdhPublicKey(
            domain: domain,
            point: ecPointDecode(domain, data),
          );
        } on InvalidDataPassed {
          return null;
        }
      case DhEphemeralParams(:final p, :final q):
        final y = bytesToBigInt(data);
        // The mapped group has the same p and subgroup order q as the
        // standardized group (ĝ = g^s·h and ĝ = f_g(x) both live in <g>).
        if (!paceValidateDhPublicKey(p: p, q: q, y: y)) {
          return null;
        }
        return DhPublicKey(p: p, y: y);
    }
  }

  /// Upstream `OpenSSLUtils.computeSharedSecret(privateKeyPair:publicKey:)`.
  /// ECDH -> x-coordinate zero-padded to the field byte length
  /// (`EVP_PKEY_derive`). DH -> the secret left-padded to byteLen(p) (I2OS
  /// fixed-length per TR-03111 §3.1.2, symmetric with the EC path;
  /// upstream's zero *relocation* is gone).
  Uint8List _computeSharedSecret({
    required PACEMappingKeyPair privateKeyPair,
    required PACEPublicKey publicKey,
  }) {
    switch (privateKeyPair) {
      case EcdhMappingKeyPair(:final domain, :final d):
        final peer = (publicKey as EcdhPublicKey).point;
        return ecdhSharedSecretX(domain, d, peer);
      case DhMappingKeyPair(:final p, :final x):
        final peerY = (publicKey as DhPublicKey).y;
        return paceDhSharedSecretBytes(p: p, x: x, peerPublic: peerY);
    }
  }
}

// --- PACE passwords (P11 §9.7.3 Table 14 / TR-03110-3 Table 5) ------------

/// The password a PACE run authenticates with, in the two halves the protocol
/// consumes: the DO83 key reference the MSE:Set AT emits, and f(π) (the key
/// seed [PACEHandler.createPaceKey] derives K_π from).
///
/// P11 §9.7.3 Table 14 and TR-03110-3 Table 5 define f(π) per password type,
/// and that is the *only* place the type shows: KDF_π(π) = KDF(f(π), 3) is
/// password-type-independent, so no key derivation branches on the reference
/// byte (the `deriveKey` parameter is inert by spec, not by omission).
///
/// Both fields are computed at construction, so a malformed password is
/// rejected before any APDU reaches the chip.
///
/// Upstream ships the four reference constants but only ever sets MRZ, so
/// CAN/PIN/CUK are a Dart-only capability (UPSTREAM.md Divergences).
final class PacePassword {
  const PacePassword._(this.keyReference, this.keySeed);

  /// MRZ (`0x01`): f(π) = SHA-1(MRZ_information). [mrzKey] is the composed
  /// document-number ‖ date-of-birth ‖ date-of-expiry string with its check
  /// digits (`composeMrzKey`); it is deliberately **unguarded**, since it is
  /// hashed rather than encoded, and reproduces upstream's MRZ seed byte for
  /// byte.
  factory PacePassword.mrz(String mrzKey) => PacePassword._(
    PACEHandler.MRZ_PACE_KEY_REFERENCE,
    calcSHA1Hash(utf8.encode(mrzKey)),
  );

  /// CAN (`0x02`): the Card Access Number printed on the document. f(π) is
  /// the ISO/IEC 8859-1 octets of [can], unhashed (Table 14).
  factory PacePassword.can(String can) =>
      PacePassword._(PACEHandler.CAN_PACE_KEY_REFERENCE, _characterSeed(can));

  /// PIN (`0x03`): TR-03110-3 Table 5, same character-string encoding.
  factory PacePassword.pin(String pin) =>
      PacePassword._(PACEHandler.PIN_PACE_KEY_REFERENCE, _characterSeed(pin));

  /// PUK (`0x04`): TR-03110-3 Table 5, same character-string encoding. Named
  /// `cuk` for parity with upstream's constant spelling.
  factory PacePassword.cuk(String cuk) =>
      PacePassword._(PACEHandler.CUK_PACE_KEY_REFERENCE, _characterSeed(cuk));

  /// The DO83 password reference: one of the [PACEHandler] `*_PACE_KEY_
  /// REFERENCE` constants (0x01-0x04).
  final int keyReference;

  /// f(π): the KDF input. Long-lived credential material: never logged.
  final Uint8List keySeed;

  /// Redacted by construction: the seed never reaches a log line.
  @override
  String toString() =>
      'PacePassword(keyReference: 0x${keyReference.toRadixString(16)})';
}

/// Folded `PACEHandler.createPaceKey` core (pure; no handler state), so
/// conformance ops can drive it directly: K_π = KDF(f(π), 3) at the suite's
/// cipher and key length.
///
/// The `paceKeyReference` argument is handed to `deriveKey` for signature
/// parity and is inert there by spec (see [PACEHandler.createPaceKey]).
Uint8List paceCreatePaceKey({
  required PacePassword password,
  required String cipherAlgName,
  required int keyLength,
}) => const SecureMessagingSessionKeyGenerator().deriveKey(
  keySeed: password.keySeed,
  cipherAlgName: cipherAlgName,
  keyLength: keyLength,
  mode: SMSMode.paceMode,
  paceKeyReference: password.keyReference,
);

/// TR-03110-3 D.2.1.4: CAN/PIN/PUK are "Character String" values encoded in
/// ISO/IEC 8859-1, in which the code points `0x00`-`0x1F` and `0x7F`-`0x9F`
/// are unassigned and MUST NOT be used. Anything outside that alphabet throws
/// [InvalidDataPassed] from the factory, before any APDU.
Uint8List _characterSeed(String value) {
  final out = Uint8List(value.length);
  for (var i = 0; i < value.length; i++) {
    final unit = value.codeUnitAt(i);
    if (unit > 0xFF) {
      throw InvalidDataPassed(
        'PACE password character at index $i is not ISO/IEC 8859-1 '
        '(TR-03110-3 D.2.1.4)',
      );
    }
    if (unit <= 0x1F || (unit >= 0x7F && unit <= 0x9F)) {
      throw InvalidDataPassed(
        'PACE password character at index $i is an unassigned ISO/IEC '
        '8859-1 code point (TR-03110-3 D.2.1.4)',
      );
    }
    out[i] = unit;
  }
  return out;
}

// --- Chip Authentication Mapping (P11 §4.4.3.5, §4.4.5.6) ------------------

/// Why a CAM session produced no usable chip-authentication data.
enum PaceCamFailure {
  /// The final GA response carried no DO8A at all: a §4.4.5 MUST violation
  /// on a CAM session.
  missing,

  /// A DO8A was there but did not decrypt to a well-formed CA_IC: not a block
  /// multiple, no ISO 9797-1 method-2 padding, an unpadded length other than
  /// byteLen(n) (§4.4.5.6 is fixed-length FE2OS), or a value outside [1, n-1].
  malformed,
}

/// What a CAM session yielded past the mutual authentication:
/// the chip's mapping public key PK_Map,IC (retained from step 2) plus either
/// the decrypted CA_IC or the [cause] that stopped it.
///
/// The §4.4.3.5.2 verification (PK_Map,IC = KA(CA_IC, PK_IC, D_IC) against a
/// chip key from EF.DG14) is the reader's step, because the key
/// only arrives with DG14, long after PACE ends;
/// [paceCamVerifyChipAuthenticationData] is the math it runs.
///
/// Note (§4.4.3.5.2): CAM proves possession of the private key matching a
/// public key; it says nothing about that key's authenticity until the file
/// carrying it is passively authenticated.
final class PaceCamData {
  const PaceCamData({
    required this.domain,
    required this.mappingPublicKey,
    this.chipAuthenticationData,
    this.chipAuthenticationValue,
    this.cause,
  });

  /// The PACE standardized domain: the curve PK_Map,IC, PK_IC and the
  /// group order n all live on.
  final ECDomainParameters domain;

  /// PK_Map,IC exactly as the step-2 DO82 carried it (uncompressed point
  /// bytes), decoded on [domain] at verify time.
  final Uint8List mappingPublicKey;

  /// CA_IC, the decrypted DO8A payload: fixed-length FE2OS to byteLen(n)
  /// (§4.4.5.6). Null iff [cause] is set.
  final Uint8List? chipAuthenticationData;

  /// [chipAuthenticationData] as the scalar the verification multiplies by.
  /// Null iff [cause] is set.
  final BigInt? chipAuthenticationValue;

  /// Null on a clean extraction; otherwise why there is no CA_IC.
  final PaceCamFailure? cause;
}

/// P11 §4.4.3.5.3/.4 + §4.4.5.6: decrypt the DO8A payload A_IC into CA_IC.
///
/// IV = E(KS_Enc, -1), i.e. the encryption of the all-ones block; a single
/// block under CBC with a zero IV is exactly that. The plaintext is then
/// AES-CBC-decrypted under that IV, its ISO 9797-1 **method 2** padding
/// stripped, and accepted only at exactly byteLen(n) bytes with a value in
/// [1, n-1].
///
/// **Total**: every malformed shape returns null rather than throwing; a CAM
/// session's mutual authentication has already succeeded by the time this
/// runs, so nothing here may fail the session. Strictness is deliberate: a
/// chip that strips CA_IC's leading zeros or omits the padding is
/// nonconformant and reads as malformed.
///
/// CAM is AES-only (§4.4.3 Note 1: "3DES no longer recommended"; Table 3 has
/// only the three ECDH-CAM-AES OIDs), so there is no DESede arm. Exposed for
/// conformance testing.
Uint8List? paceCamDecryptChipAuthenticationData({
  required List<int> ksEnc,
  required List<int> encryptedData,
  required BigInt groupOrder,
}) {
  try {
    final iv = aesEncrypt(ksEnc, List.filled(16, 0xFF), List.filled(16, 0));
    final plaintext = aesDecrypt(ksEnc, encryptedData, iv);
    final caIc = unpad(plaintext);
    // `unpad` passes non-padded input through unchanged; §4.4.3.5.3
    // makes the padding mandatory, so a plaintext it did not shorten is
    // malformed.
    if (caIc.length >= plaintext.length) {
      return null;
    }
    if (caIc.length != (groupOrder.bitLength + 7) >> 3) {
      return null; // §4.4.5.6: FE2OS to the octet length of the group order.
    }
    final value = bytesToBigInt(caIc);
    if (value == BigInt.zero || value >= groupOrder) {
      return null; // degenerate scalar: cannot be an inverse mod n
    }
    return caIc;
  } on EmrtdException {
    // aesEncrypt/aesDecrypt reject bad key/IV sizes and non-block-aligned
    // input; `unpad` rejects empty/all-zero plaintext.
    return null;
  }
}

/// P11 §4.4.3.5.2 (the terminal's CAM check): PK_Map,IC = KA(CA_IC, PK_IC,
/// D_IC), i.e. the chip's step-2 mapping public key equals CA_IC·PK_IC.
///
/// Plain scalar multiplication is exact here: every PACE standardized curve
/// has cofactor 1, so ECKA's compatible-cofactor step is the identity.
///
/// Returns false (never throws) when [mappingPublicKey] does not decode on
/// [domain] (`ecPointDecode` validates on-curve and in-range) or the product
/// degenerates. Exposed for conformance testing.
bool paceCamVerifyChipAuthenticationData({
  required ECDomainParameters domain,
  required BigInt chipAuthenticationValue,
  required ECPoint chipPublicKey,
  required List<int> mappingPublicKey,
}) {
  try {
    final expected = ecPointDecode(domain, mappingPublicKey);
    final actual = ecPointMul(domain, chipAuthenticationValue, chipPublicKey);
    return _bytesEqual(ecPointEncode(actual), ecPointEncode(expected));
  } on InvalidDataPassed {
    return false;
  }
}

/// Folded core of `doDHMappingAgreement` (pure): the P11 §4.4.3.3.1 mapped
/// generator ĝ = g^nonce·h mod p, where h = KA(SK_Map,IFD, PK_Map,IC) is the
/// mapping shared secret **at its true integer value**.
///
/// Upstream ignores `DH_compute_key`'s return length, so a secret with k
/// leading zero bytes reaches this multiplication as h·256^k. That
/// relocation is a byte-buffer artifact with no spec basis; it is resolved
/// here and pinned swift-side only. Exposed for conformance testing.
BigInt paceDhMappedGenerator({
  required BigInt p,
  required BigInt g,
  required BigInt mappingPrivateKey,
  required List<int> peerPublicKeyData,
  required BigInt nonce,
}) {
  final peerPublic = bytesToBigInt(peerPublicKeyData);
  final h = dhSharedSecret(p, mappingPrivateKey, peerPublic);
  // bn_g = g^nonce mod p; ĝ = bn_g·h mod p.
  return (g.modPow(nonce, p) * h) % p;
}

/// The step-4 DH shared secret as key-derivation input: the secret
/// left-padded with zeros to byteLen(p); I2OS fixed-length (TR-03111 §3.1.2),
/// symmetric with the EC path's padded x-coordinate (P11 §9.7.1).
///
/// Pinned interpretation, not a quoted MUST: no text the port holds states the
/// DH length rule explicitly, and App G.2's published K has no leading zero so
/// the worked example cannot discriminate. A wrong choice fails closed
/// (token mismatch -> BAC fallback) in the ~0.4 % of sessions whose secret
/// has a leading zero byte. Upstream's *right*-padding is the bug class this
/// replaces; it survives as a swift-side conformance pin.
Uint8List paceDhSharedSecretBytes({
  required BigInt p,
  required BigInt x,
  required BigInt peerPublic,
}) => bigIntToBytes(
  dhSharedSecret(p, x, peerPublic),
  length: (p.bitLength + 7) >> 3,
);

/// Validates a received DH public key y (a dart-only divergence):
/// `2 ≤ y ≤ p-2` and `y^q mod p == 1`, the RFC 2631 check P11 §4.4.3.3.1's DH
/// note calls for. Every PACE standardized DH group (RFC 5114 §2.1-2.3) knows
/// its subgroup order q, so the subgroup test always runs, one extra modexp.
///
/// Upstream feeds arbitrary DO82/DO84 bytes straight to `DH_compute_key`; the
/// split conformance cases pin the difference.
bool paceValidateDhPublicKey({
  required BigInt p,
  required BigInt q,
  required BigInt y,
}) {
  if (y < _two || y > p - _two) {
    return false;
  }
  return y.modPow(q, p) == BigInt.one;
}

/// Folded `PACEHandler.encodePublicKey` core (pure; no handler state), so
/// conformance ops can drive it directly. `7F49 { 06 oid, 86/84 key }`; DH
/// keys tag `0x84`, EC keys tag `0x86` (upstream line 583).
Uint8List paceEncodePublicKey(String oid, PACEPublicKey key) {
  final pubKeyData = switch (key) {
    EcdhPublicKey(:final point) => ecPointEncode(point),
    DhPublicKey(:final y) => bigIntToBytes(y),
  };
  final tag = key is DhPublicKey ? 0x84 : 0x86;

  final encOid = TlvRecord.parse(oidToBytes(oid, replaceTag: false));
  if (encOid == null) {
    throw const InvalidASN1Value();
  }
  final encPub = TlvRecord(tag, pubKeyData);
  return TlvRecord.fromRecords(0x7F49, [encOid, encPub]).data;
}

/// Folded `PACEHandler.generateAuthenticationToken` core (pure). DESede pads
/// the encoding to block size 8 before MACing (upstream line 553); AES CMACs
/// unpadded. Returns the 8-byte truncation.
Uint8List paceGenerateAuthenticationToken({
  required String oid,
  required String cipherAlg,
  required PACEPublicKey publicKey,
  required List<int> macKey,
}) {
  var encoded = paceEncodePublicKey(oid, publicKey);
  if (cipherAlg == 'DESede') {
    encoded = pad(encoded, blockSize: 8);
  }
  final macced = mac(
    algoName: cipherAlg == 'DESede'
        ? SecureMessagingSupportedAlgorithms.des
        : SecureMessagingSupportedAlgorithms.aes,
    key: macKey,
    msg: encoded,
  );
  return Uint8List.fromList(macced.sublist(0, 8));
}

// --- Integrated Mapping (P11 §4.4.3.3.2 + App B) ---------------------------

final BigInt _two = BigInt.two;
final BigInt _three = BigInt.from(3);
final BigInt _four = BigInt.from(4);

/// The §4.4.3.3.2 constants c0/c1, indexed by l (the bit length of s and of
/// each R_p output block): the 128-bit pair for 3DES and AES-128, the 256-bit
/// pair for AES-192 and AES-256.
const List<int> _imC0_128 = [
  0xa6, 0x68, 0x89, 0x2a, 0x7c, 0x41, 0xe3, 0xca, //
  0x73, 0x9f, 0x40, 0xb0, 0x57, 0xd8, 0x59, 0x04,
];
const List<int> _imC1_128 = [
  0xa4, 0xe1, 0x36, 0xac, 0x72, 0x5f, 0x73, 0x8b, //
  0x01, 0xc1, 0xf6, 0x02, 0x17, 0xc1, 0x88, 0xad,
];
const List<int> _imC0_256 = [
  0xd4, 0x63, 0xd6, 0x52, 0x34, 0x12, 0x4e, 0xf7, //
  0x89, 0x70, 0x54, 0x98, 0x6d, 0xca, 0x0a, 0x17,
  0x4e, 0x28, 0xdf, 0x75, 0x8c, 0xba, 0xa0, 0x3f,
  0x24, 0x06, 0x16, 0x41, 0x4d, 0x5a, 0x16, 0x76,
];
const List<int> _imC1_256 = [
  0x54, 0xbd, 0x72, 0x55, 0xf0, 0xaa, 0xf8, 0x31, //
  0xbe, 0xc3, 0x42, 0x3f, 0xcf, 0x39, 0xd6, 0x9b,
  0x6c, 0xbf, 0x06, 0x66, 0x77, 0xd0, 0xfa, 0xae,
  0x5a, 0xad, 0xd9, 0x9d, 0xf8, 0xe5, 0x35, 0x17,
];

/// The block-cipher shape R_p(s,t) is parameterized by (§4.4.3.3.2).
///
/// [keyBits] is k, the key size of E, **128 for 3DES**, which the spec fixes
/// explicitly ("In case of DES, k is considered to be equal to 128 bits, and
/// the output of R(s,t) shall be 128 bits"). [blockBits] is E's block size.
/// [lBits] is l, the smallest multiple of the block size with l ≥ k: 128 for
/// 3DES and AES-128, 256 for AES-192/256; it is both the width of the nonce
/// s and the width of every R_p output block x_i.
class _PaceImCipher {
  const _PaceImCipher._({
    required this.name,
    required this.keyBits,
    required this.blockBits,
  }) : lBits = blockBits == 64
           // 3DES: ⌈128/64⌉·64 = 128.
           ? 128
           : (keyBits <= 128 ? 128 : 256);

  /// Resolves the suite's (cipher, key length) into R_p's parameters.
  factory _PaceImCipher.forSuite(String cipherAlg, int keyLength) {
    switch (cipherAlg) {
      case 'DESede':
        return const _PaceImCipher._(
          name: 'DESede',
          keyBits: 128,
          blockBits: 64,
        );
      case 'AES':
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
          throw PACEError('Step2IM', 'Unsupported AES key length $keyLength');
        }
        return _PaceImCipher._(name: 'AES', keyBits: keyLength, blockBits: 128);
      default:
        throw PACEError('Step2IM', 'Unsupported cipher algorithm $cipherAlg');
    }
  }

  final String name;
  final int keyBits;
  final int blockBits;
  final int lBits;

  int get keyBytes => keyBits >> 3;
  int get blockBytes => blockBits >> 3;
  int get lBytes => lBits >> 3;

  List<int> get c0 => lBits == 128 ? _imC0_128 : _imC0_256;
  List<int> get c1 => lBits == 128 ? _imC1_128 : _imC1_256;

  /// E() in CBC mode with IV = 0 (§4.4.3.3.2, [ISO/IEC 10116]).
  Uint8List encryptCbc(List<int> key, List<int> data) => name == 'AES'
      ? aesEncrypt(key, data, List.filled(16, 0))
      : tripleDESEncrypt(key, data, List.filled(8, 0));

  /// "Where required, the output k_i MUST be truncated to key size k": only
  /// AES-192 needs it (octets 1..24 of a 32-byte CBC output).
  Uint8List truncateToKey(Uint8List block) => block.length == keyBytes
      ? block
      : Uint8List.sublistView(block, 0, keyBytes);

  /// n = the smallest number with n·l ≥ log2(p) + 64.
  int blockCount(BigInt p) => ((p.bitLength + 64) + (lBits - 1)) ~/ lBits;
}

/// The §4.4.3.3.2 pseudo-random function R_p(s,t) (Figure 2): a block cipher E
/// in CBC mode with IV = 0, keyed first by the terminal nonce t over the chip
/// nonce s, then iterated against the constants c0 (next key) and c1 (next
/// output block).
///
/// Returns both halves the worked examples publish: [blocks] is the raw
/// x_1‖x_2‖...‖x_n concatenation (App H's "Pseudo-random R(s,t)") and
/// [value] is `int(blocks) mod p` (App H's "R_p(s,t)"). Exposed for
/// conformance testing.
({Uint8List blocks, BigInt value}) paceImPseudoRandom({
  required List<int> s,
  required List<int> t,
  required BigInt p,
  required String cipherAlg,
  required int keyLength,
}) {
  final e = _PaceImCipher.forSuite(cipherAlg, keyLength);
  if (t.length != e.keyBytes) {
    throw PACEError(
      'Step2IM',
      'IM nonce t is ${t.length} bytes, expected ${e.keyBytes}',
    );
  }
  if (s.isEmpty || s.length % e.blockBytes != 0) {
    throw PACEError(
      'Step2IM',
      'IM nonce s is ${s.length} bytes, expected a non-zero multiple of the '
          '${e.blockBytes}-byte block size (${e.lBytes} per §4.4.3.3)',
    );
  }
  // INIT: k_0 = E(t, s), truncated to the key size.
  var k = e.truncateToKey(e.encryptCbc(t, s));
  final n = e.blockCount(p);
  final out = Uint8List(n * e.lBytes);
  for (var i = 0; i < n; i++) {
    // x_{i+1} = E(k_i, c1); k_{i+1} = E(k_i, c0).
    out.setRange(i * e.lBytes, (i + 1) * e.lBytes, e.encryptCbc(k, e.c1));
    k = e.truncateToKey(e.encryptCbc(k, e.c0));
  }
  return (blocks: out, value: bytesToBigInt(out) % p);
}

/// §4.4.3.3.2 f_g: ĝ = x^((p-1)/q) mod p, where a = (p-1)/q is the cofactor.
/// Enforces the spec's explicit MUST ("Implementations MUST check that
/// ĝ ≠ 1") as a typed [PACEError]. Exposed for conformance testing.
BigInt paceImMapDh({required BigInt p, required BigInt q, required BigInt x}) {
  final ghat = x.modPow((p - BigInt.one) ~/ q, p);
  if (ghat == BigInt.one) {
    throw const PACEError(
      'Step2IM',
      'Integrated Mapping produced ĝ = 1 (P11 §4.4.3.3.2 MUST)',
    );
  }
  return ghat;
}

/// §4.4.3.3.2 f_G via the App B.2 **affine** point encoding (chosen over
/// B.3's Jacobian variant because the codebase has no Jacobian machinery and
/// the extra modexp is irrelevant at terminal scale).
///
/// Requires p ≡ 3 (mod 4): the caller's parameter guard rejects the one
/// standardized curve that fails it (NIST P-224). Exposed for conformance
/// testing.
ECPoint paceImMapEcdh({required ECDomainParameters domain, required BigInt x}) {
  final curve = domain.curve;
  if (curve is! fp.ECCurve) {
    throw PACEError(
      'Step2IM',
      'Integrated Mapping needs a prime-field curve, got ${curve.runtimeType}',
    );
  }
  final p = curve.q!;
  final a = curve.a!.toBigInteger()!;
  final b = curve.b!.toBigInteger()!;
  if (p % _four != _three) {
    throw PACEError(
      'Step2IM',
      'App B point encoding requires p = 3 mod 4 (${domain.domainName})',
    );
  }
  // App B: "takes as input a number t such that 0 < t < p".
  if (x <= BigInt.zero || x >= p) {
    throw const PACEError(
      'Step2IM',
      'App B point encoding requires 0 < R_p(s,t) < p',
    );
  }

  // 1. α = -t² mod p.
  final alpha = (-(x * x)) % p;
  // 2. X₂ = -b·a⁻¹·(1 + (α+α²)⁻¹) mod p.
  final alphaSum = (alpha + alpha * alpha) % p;
  if (alphaSum == BigInt.zero) {
    // α ∈ {0, -1}, i.e. R_p(s,t) ∈ {0, 1, p-1}: the encoding is undefined.
    throw const PACEError(
      'Step2IM',
      'App B point encoding is undefined for this R_p(s,t) (α + α² = 0)',
    );
  }
  final x2 =
      ((-b % p) * a.modInverse(p) % p) *
      ((BigInt.one + alphaSum.modInverse(p)) % p) %
      p;
  // 3. X₃ = α·X₂ mod p.
  final x3 = alpha * x2 % p;
  // 4./5. h_i = X_i³ + a·X_i + b mod p.
  final h2 = (x2.modPow(_three, p) + a * x2 + b) % p;
  final h3 = (x3.modPow(_three, p) + a * x3 + b) % p;
  // 6. U = t³·h₂ mod p.
  final u = x.modPow(_three, p) * h2 % p;
  // 7. A = h₂^(p-1-(p+1)/4) mod p.
  final aExp = p - BigInt.one - (p + BigInt.one) ~/ _four;
  final bigA = h2.modPow(aExp, p);
  // 8./9. A²·h₂ = 1 ⇔ h₂ is a quadratic residue.
  final BigInt px, py;
  if (bigA * bigA % p * h2 % p == BigInt.one) {
    px = x2;
    py = bigA * h2 % p;
  } else {
    px = x3;
    py = bigA * u % p;
    assert(h3 == alpha.modPow(_three, p) * h2 % p);
  }
  ECPoint point = curve.createPoint(px, py);
  // 10. [f](x, y). Every PACE standardized curve has cofactor 1, so this is
  // the identity in practice; applied anyway for spec fidelity.
  final cofactor = domain is ECDomainParametersImpl
      ? (domain.h ?? BigInt.one)
      : BigInt.one;
  if (cofactor != BigInt.one) {
    point = ecPointMul(domain, cofactor, point);
  }
  if (point.isInfinity) {
    throw const PACEError(
      'Step2IM',
      'Integrated Mapping produced the point at infinity',
    );
  }
  return point;
}

/// The field prime of a prime-field [domain]: App B's p.
BigInt _fpFieldPrime(ECDomainParameters domain) {
  final curve = domain.curve;
  if (curve is! fp.ECCurve) {
    throw PACEError(
      'Step2IM',
      'Integrated Mapping needs a prime-field curve, got ${curve.runtimeType}',
    );
  }
  return curve.q!;
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

/// Upstream's `[UInt8](...)` array debug rendering (`[1, 2, 3]`), kept for the
/// token-mismatch message parity.
String _intList(List<int> bytes) => '[${bytes.join(', ')}]';
