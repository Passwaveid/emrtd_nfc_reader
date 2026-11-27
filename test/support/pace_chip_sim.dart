/// Scripted PACE chip (PICC) simulator: the chip side of a PACE handshake,
/// composed from the same crypto primitives the port's [PACEHandler] uses,
/// with fixed injected chip-side keys.
///
/// Coverage: Generic Mapping (and CAM, which maps identically) over ECDH and
/// DH, and Integrated Mapping over ECDH and DH (every mapping/agreement
/// combination the port implements) under any of the four PACE passwords.
/// CAM chips can carry a static Chip Authentication keypair and emit a real
/// 9303-11 §4.4.3.5.1 DO8A.
///
/// Purpose: generate/replay full PACE sessions so each composition is
/// exercised end-to-end (mapping + agreement + mutual token) without a live
/// chip. Its output is only trusted as a frozen fixture after session **S3**
/// proves the instrumented Swift original completes the same scripted
/// handshake, and for DH/IM there is no Swift original at all, so the sim
/// proves *consistency* (Dart terminal vs Dart chip) while the App G.2/H
/// chains and the python-oracle vectors carry correctness.
///
/// Scope: MSE:Set AT + the four GENERAL AUTHENTICATE rounds, plus a minimal
/// SM-protected acknowledgement for the *first* post-PACE command, so a
/// transcript can prove the installed session keys the way the SM-handoff
/// fixtures do. Everything richer than that belongs to
/// `emrtd_chip_sim.dart`.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/ciphers.dart';
import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/kdf.dart';
import 'package:emrtd_core/src/crypto/mac.dart';
import 'package:emrtd_core/src/lds/pace_info.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/pace.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:emrtd_core/src/utils.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

/// How the chip shapes its (mandatorily empty, §4.4.5.2.2) IM mapping
/// response: an empty Dynamic Authentication Data object, or one carrying an
/// explicitly empty DO82. The port must ignore both.
enum ImMappingResponseShape {
  /// `7C 00`: no DO82 at all.
  emptyDynamicAuthObject,

  /// `7C 02 82 00`: the DO82 present and empty, as the note prescribes.
  emptyDo82,
}

/// A scripted PACE chip. Answers the terminal's MSE:Set AT and the four GA
/// rounds; a CAM chip appends the §4.4.5 Table 4 DO8A to the final response.
class PaceChipSimulator implements NfcTransceiver {
  PaceChipSimulator({
    required this.oid,
    required this.password,
    required this.nonce,
    required BigInt chipMappingPrivateKey,
    required BigInt chipEphemeralPrivateKey,
    this.parameterId = PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1,
    this.imResponseShape = ImMappingResponseShape.emptyDo82,
    BigInt? camStaticPrivateKey,
    this._camDataObject,
    this._camPrecedingRecords = const [],
    this.maxTransceiveLength = 261,
    this.isExtendedLengthApduSupported = false,
    this.historicalBytes,
    this.tagCapabilities,
  }) : _chipMappingPriv = chipMappingPrivateKey,
       _chipEphemeralPriv = chipEphemeralPrivateKey,
       _camStaticPriv = camStaticPrivateKey;

  final String oid;

  /// The password the chip encrypted its nonce under: a terminal deriving
  /// anything else fails the step-4 token check.
  final PacePassword password;

  final Uint8List nonce;

  /// The standardized domain the chip runs in: an EC curve id for ECDH
  /// suites, an RFC 5114 group id (0/1/2) for DH suites. Defaults to
  /// Brainpool P-256, the curve of the ECDH worked examples (G.1/H.1/I.1).
  final int parameterId;
  final ImMappingResponseShape imResponseShape;

  final BigInt _chipMappingPriv;
  final BigInt _chipEphemeralPriv;

  /// SK_IC: the chip's static Chip Authentication private key. Set on a CAM
  /// chip to emit a real DO8A: CA_IC = SK_IC⁻¹·SK_Map,IC mod n
  /// (§4.4.3.5.1), encrypted under KS_Enc with IV = E(KS_Enc, -1).
  final BigInt? _camStaticPriv;

  /// A literal DO8A payload, overriding [_camStaticPriv], the malformed-DO8A
  /// shapes the mechanism tests drive. Both null on a CAM chip means the
  /// response carries no DO8A at all (the `missing` shape).
  final List<int>? _camDataObject;

  /// Extra records emitted between the DO86 token and the DO8A: §4.4.5
  /// Table 4's conditional DO87/DO88 CARs. They make the DO8A stop being
  /// `tvlResp[1]`, which is what upstream's commented-out extraction assumed.
  final List<int> _camPrecedingRecords;

  @override
  final int maxTransceiveLength;
  @override
  final bool isExtendedLengthApduSupported;
  @override
  final Uint8List? historicalBytes;
  @override
  final TagCapabilities? tagCapabilities;

  late final String _cipherAlg = PACEInfo.toCipherAlgorithm(oid);
  late final int _keyLength = PACEInfo.toKeyLength(oid);
  late final String _agreementAlg = PACEInfo.toKeyAgreementAlgorithm(oid);
  late final PACEMappingType _mappingType = PACEInfo.toMappingType(oid);
  late final PACEParameterSpec _spec = PACEInfo(
    oid: oid,
    version: 2,
    parameterId: parameterId,
  ).getParameterSpec();
  ECDomainParameters get _domain => (_spec as ECStandardizedDomain).domain;
  DHStandardizedDomain get _group => _spec as DHStandardizedDomain;

  late final Uint8List _paceKey = _createPaceKey();

  // Filled in as the handshake progresses.
  ECDomainParameters? _mapped;
  BigInt? _mappedG;
  late Uint8List _ksMac;
  late Uint8List _ksEnc;

  /// Records the wire APDUs and responses for transcript authoring.
  final List<Uint8List> sentCommands = [];
  final List<Uint8List> sentResponses = [];

  /// The mapped generator the chip derived, asserted against the published
  /// worked examples by the mechanism tests.
  BigInt? get mappedDhGenerator => _mappedG;
  ECPoint? get mappedEcGenerator => _mapped?.G;

  /// PK_IC: the chip's static CA public key, the DG14 counterpart a terminal
  /// verifies the DO8A against. Null unless this is a CAM chip with a static
  /// keypair.
  ECPoint? get camStaticPublicKey => _camStaticPriv == null
      ? null
      : ecPointMul(_domain, _camStaticPriv, _domain.G);

  /// CA_IC as the chip computed it: the value the terminal must recover from
  /// the DO8A. Null until step 4 of a CAM session with a static keypair.
  BigInt? get camChipAuthenticationValue => _camCaIc;
  BigInt? _camCaIc;

  Uint8List _createPaceKey() {
    const smskg = SecureMessagingSessionKeyGenerator();
    return smskg.deriveKey(
      keySeed: password.keySeed,
      cipherAlgName: _cipherAlg,
      keyLength: _keyLength,
      mode: SMSMode.paceMode,
      paceKeyReference: password.keyReference,
    );
  }

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    sentCommands.add(Uint8List.fromList(capdu));
    final cmd = CommandAPDU.parse(capdu);
    final Uint8List resp;
    if (cmd.instructionClass == 0x0c) {
      // The first post-PACE command, protected under the session keys.
      resp = _protectedAcknowledgement();
    } else if (cmd.instructionCode != 0x86) {
      // MSE:Set AT (or any non-GA command) -> 90 00.
      resp = Uint8List.fromList([0x90, 0x00]);
    } else {
      final inner = unwrapDO(0x7c, cmd.data);
      resp = _handleGeneralAuthenticate(inner);
    }
    sentResponses.add(resp);
    return resp;
  }

  /// `99 02 9000 ‖ 8E 08 CC` under the PACE session keys, the chip half of
  /// the SM handoff. SSC starts at zero and steps once per direction, so
  /// the response of the first protected exchange MACs over SSC = 2.
  Uint8List _protectedAcknowledgement() {
    final isDes = _cipherAlg == 'DESede';
    final blockSize = isDes ? 8 : 16;
    final ssc = Uint8List(8)..[7] = 2;
    final paddedSsc = isDes ? ssc : <int>[...List.filled(8, 0), ...ssc];
    const do99 = [0x99, 0x02, 0x90, 0x00];
    var cc = mac(
      algoName: isDes
          ? SecureMessagingSupportedAlgorithms.des
          : SecureMessagingSupportedAlgorithms.aes,
      key: _ksMac,
      msg: pad([...paddedSsc, ...do99], blockSize: blockSize),
    );
    if (cc.length > 8) {
      cc = Uint8List.sublistView(cc, 0, 8);
    }
    return Uint8List.fromList([...do99, 0x8E, cc.length, ...cc, 0x90, 0x00]);
  }

  Uint8List _handleGeneralAuthenticate(List<int> inner) {
    if (inner.isEmpty) {
      return _respond(_step1Nonce());
    }
    switch (inner[0]) {
      case 0x81:
        // GM/CAM: the terminal's mapping public key. IM: the nonce t.
        return _respond(
          _mappingType == PACEMappingType.IM
              ? _step2IntegratedMapping(unwrapDO(0x81, inner))
              : _step2GenericMapping(unwrapDO(0x81, inner)),
        );
      case 0x83:
        return _respond(_step3Ephemeral(unwrapDO(0x83, inner)));
      case 0x85:
        return _respond(_step4Token(unwrapDO(0x85, inner)));
      default:
        return Uint8List.fromList([0x6a, 0x80]);
    }
  }

  /// Wraps [innerDOs] in a `7C` data object and appends `90 00`.
  Uint8List _respond(List<int> innerDOs) =>
      Uint8List.fromList([...wrapDO(0x7c, innerDOs), 0x90, 0x00]);

  List<int> _step1Nonce() {
    final Uint8List enc;
    if (_cipherAlg == 'AES') {
      enc = aesEncrypt(_paceKey, nonce, List.filled(16, 0));
    } else {
      enc = tripleDESEncrypt(_paceKey, nonce, List.filled(8, 0));
    }
    return wrapDO(0x80, enc);
  }

  List<int> _step2GenericMapping(List<int> terminalMappingPub) {
    if (_agreementAlg == 'DH') {
      final g = _group;
      final chipMapPub = dhPublic(g.p, g.g, _chipMappingPriv);
      // h = KA(SK_Map,IC, PK_Map,IFD) at its true integer value (the chip has
      // no zero-relocation quirk to reproduce; that is upstream
      // terminal-side only).
      final h = dhSharedSecret(
        g.p,
        _chipMappingPriv,
        bytesToBigInt(terminalMappingPub),
      );
      _mappedG = g.g.modPow(bytesToBigInt(nonce), g.p) * h % g.p;
      // DH public keys travel BN_bn2bin-stripped (minimal octets, as
      // TR-03110-3 D.2.1.1 requires).
      return wrapDO(0x82, bigIntToBytes(chipMapPub));
    }
    // ecPointMul (not ecPublicFromPrivate) so illustrative spec scalars ≥ n,
    // e.g. App I.1's chip ephemeral key, reduce mod n rather than tripping
    // the terminal-only [1, n-1] guard.
    final chipMapPub = ecPointMul(_domain, _chipMappingPriv, _domain.G);
    // Chip's mapping shared point H = d_chip·terminalMappingPub.
    final terminalPoint = ecPointDecode(_domain, terminalMappingPub);
    final h = ecPointMul(_domain, _chipMappingPriv, terminalPoint);
    final ghat = ecMulAdd(_domain, bytesToBigInt(nonce), _domain.G, h);
    _mapped = ECDomainParametersImpl(
      'pace-mapped-${_domain.domainName}',
      _domain.curve,
      ghat,
      _domain.n,
      BigInt.one,
    );
    return wrapDO(0x82, ecPointEncode(chipMapPub));
  }

  /// P11 §4.4.3.3.2: the chip recomputes R_p(s,t) from the nonce t it just
  /// received and maps it; the mapping is a pure function of (s, t), so no
  /// chip mapping *key* is involved at all. The response DO82 is empty.
  List<int> _step2IntegratedMapping(List<int> t) {
    final BigInt p = switch (_spec) {
      DHStandardizedDomain(:final p) => p,
      ECStandardizedDomain(:final domain) => (domain.curve as fp.ECCurve).q!,
    };
    final x = paceImPseudoRandom(
      s: nonce,
      t: t,
      p: p,
      cipherAlg: _cipherAlg,
      keyLength: _keyLength,
    );
    if (_agreementAlg == 'DH') {
      final g = _group;
      _mappedG = paceImMapDh(p: g.p, q: g.q, x: x.value);
    } else {
      final ghat = paceImMapEcdh(domain: _domain, x: x.value);
      _mapped = ECDomainParametersImpl(
        'pace-im-mapped-${_domain.domainName}',
        _domain.curve,
        ghat,
        _domain.n,
        BigInt.one,
      );
    }
    return switch (imResponseShape) {
      ImMappingResponseShape.emptyDynamicAuthObject => const <int>[],
      ImMappingResponseShape.emptyDo82 => wrapDO(0x82, const <int>[]),
    };
  }

  List<int> _step3Ephemeral(List<int> terminalEphemeralPub) {
    const gen = SecureMessagingSessionKeyGenerator();
    final Uint8List sharedSecret;
    final List<int> chipEphemeralDO;
    final PACEPublicKey terminalKey;

    if (_agreementAlg == 'DH') {
      final p = _group.p;
      final ghat = _mappedG!;
      final chipEphPub = dhPublic(p, ghat, _chipEphemeralPriv);
      final terminalY = bytesToBigInt(terminalEphemeralPub);
      sharedSecret = paceDhSharedSecretBytes(
        p: p,
        x: _chipEphemeralPriv,
        peerPublic: terminalY,
      );
      chipEphemeralDO = wrapDO(0x84, bigIntToBytes(chipEphPub));
      terminalKey = DhPublicKey(p: p, y: terminalY);
    } else {
      final mapped = _mapped!;
      final chipEphPub = ecPointMul(mapped, _chipEphemeralPriv, mapped.G);
      final terminalPoint = ecPointDecode(mapped, terminalEphemeralPub);
      sharedSecret = ecdhSharedSecretX(
        mapped,
        _chipEphemeralPriv,
        terminalPoint,
      );
      chipEphemeralDO = wrapDO(0x84, ecPointEncode(chipEphPub));
      terminalKey = EcdhPublicKey(domain: mapped, point: terminalPoint);
    }

    _ksEnc = gen.deriveKey(
      keySeed: sharedSecret,
      cipherAlgName: _cipherAlg,
      keyLength: _keyLength,
      mode: SMSMode.encMode,
    );
    _ksMac = gen.deriveKey(
      keySeed: sharedSecret,
      cipherAlgName: _cipherAlg,
      keyLength: _keyLength,
      mode: SMSMode.macMode,
    );
    // Chip's token is over the terminal's ephemeral public key.
    _pendingChipToken = paceGenerateAuthenticationToken(
      oid: oid,
      cipherAlg: _cipherAlg,
      publicKey: terminalKey,
      macKey: _ksMac,
    );
    return chipEphemeralDO;
  }

  Uint8List _pendingChipToken = Uint8List(0);

  List<int> _step4Token(List<int> terminalToken) {
    // (The chip would verify terminalToken against its own expectation over
    // its ephemeral public key; the sim trusts the injected terminal.)
    final records = <int>[...wrapDO(0x86, _pendingChipToken)];
    // §4.4.5 Table 4: Encrypted Chip Authentication Data rides the final GA
    // response and is mandatory under CAM. A literal payload wins (the
    // malformed shapes); otherwise a static keypair produces the real thing;
    // with neither, the chip emits nothing, the `missing` shape.
    final camPayload = _camDataObject ?? _camEncryptedData();
    if (camPayload != null) {
      records.addAll(_camPrecedingRecords);
      records.addAll(wrapDO(0x8a, camPayload));
    }
    return records;
  }

  /// §4.4.3.5.1/.3/.4: CA_IC = SK_IC⁻¹·SK_Map,IC mod n, encoded FE2OS to
  /// byteLen(n), ISO 9797-1 method-2 padded and AES-CBC encrypted under
  /// KS_Enc with IV = E(KS_Enc, -1).
  List<int>? _camEncryptedData() {
    final skIc = _camStaticPriv;
    if (skIc == null || _mappingType != PACEMappingType.CAM) {
      return null;
    }
    final n = _domain.n;
    final caIc = skIc.modInverse(n) * _chipMappingPriv % n;
    _camCaIc = caIc;
    final plaintext = pad(
      bigIntToBytes(caIc, length: (n.bitLength + 7) >> 3),
      blockSize: 16,
    );
    final iv = aesEncrypt(_ksEnc, List.filled(16, 0xFF), List.filled(16, 0));
    return aesEncrypt(_ksEnc, plaintext, iv);
  }
}
