/// Scripted eMRTD chip (PICC) simulator for the PassportReader session
/// tests.
///
/// The chip side of a full read session: CardAccess serving, PACE ECDH-GM
/// (adapted from the sibling PaceChipSimulator), BAC mutual authentication,
/// Chip Authentication (MSE:Set KAT for the DESede suites, MSE:Set AT +
/// chained GENERAL AUTHENTICATE for the AES ones, then the session-key
/// restart), Active Authentication (INTERNAL AUTHENTICATE signed with the
/// fixture DG15 private key), and SM-protected file serving (DES post-BAC,
/// AES post-PACE), computed dynamically from the terminal's actual traffic,
/// so no canned wire bytes and no fixed RNG are needed. Error injection
/// hooks drive the per-DG retry-table rows.
///
/// Built on emrtd_core's own crypto primitives (src imports are the
/// test-support pattern, as in pace_chip_sim.dart).
library;

// ignore_for_file: implementation_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:emrtd_core/src/crypto/ciphers.dart';
import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/hashes.dart';
import 'package:emrtd_core/src/crypto/kdf.dart';
import 'package:emrtd_core/src/crypto/mac.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:emrtd_core/src/utils.dart';
import 'package:pointycastle/api.dart' show Digest, PrivateKeyParameter;
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

Uint8List hx(String hex) {
  final clean = hex.replaceAll(' ', '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

/// Parsed view of an incoming command, given to the injection hooks.
class SimCommand {
  const SimCommand({
    required this.ins,
    required this.p1,
    required this.p2,
    required this.isProtected,
    this.fid,
    this.le,
  });

  final int ins;
  final int p1;
  final int p2;
  final bool isProtected;

  /// The currently selected file id (e.g. 0x0101 for DG1) so hooks can
  /// target "the read of DG2" etc.
  final int? fid;

  /// The Le of a READ BINARY (the DO97 value under SM), so hooks can target
  /// "the first 223-byte chunk"; null for other commands.
  final int? le;
}

/// PACE leg configuration (ECDH-GM/CAM suites over Brainpool P-256).
class PaceSimConfig {
  const PaceSimConfig({
    required this.oid,
    required this.nonce,
    required this.chipMappingPrivateKey,
    required this.chipEphemeralPrivateKey,
    this.camStaticPrivateKey,
    this.camDataObject,
  });

  final String oid;
  final Uint8List nonce;
  final BigInt chipMappingPrivateKey;
  final BigInt chipEphemeralPrivateKey;

  /// SK_IC, the chip's static Chip Authentication key. On a CAM [oid] the
  /// final GA response then carries a real DO8A
  /// (CA_IC = SK_IC⁻¹·SK_Map,IC mod n, §4.4.3.5.1). Point it at
  /// `caChipPrivateKey` and the DG14 the chip serves verifies; point it
  /// elsewhere and the reader reports `failed`, the clone shape.
  final BigInt? camStaticPrivateKey;

  /// A literal DO8A payload, overriding [camStaticPrivateKey], the
  /// undecryptable shape. Both null on a CAM session means no DO8A at all.
  final Uint8List? camDataObject;
}

/// Chip Authentication leg configuration. The chip's static CA key
/// lives here; the matching `ChipAuthenticationPublicKeyInfo` must be in the
/// DG14 file handed to [EmrtdChipSim.files] under fid `0x010E`.
///
/// Note on chaining (an upstream defect): `SecureMessaging.maskClassAndPad`
/// masks the CLA to the literal `0x0C`, so the `0x10` command-chaining bit
/// never reaches the chip under SM, and `sendGeneralAuthenticate` unwraps a
/// DO7C from *every* response. This sim therefore reassembles segments by
/// watching for a complete DO80 and answers `7C 00` to intermediate ones,
/// the idealized chip upstream's code implicitly assumes.
class CaSimConfig {
  const CaSimConfig({
    required this.oid,
    required this.chipPrivateKey,
    this.curve,
    this.p,
    this.g,
    this.mseSw = 0x9000,
  });

  /// The CA protocol OID DG14 advertises (picks DESede vs AES flow).
  final String oid;

  final BigInt chipPrivateKey;

  /// Set for the ECDH suites.
  final ECDomainParameters? curve;

  /// Set for the DH suites.
  final BigInt? p;
  final BigInt? g;

  /// SW answered to MSE:Set KAT / MSE:Set AT: anything but `0x9000` fails
  /// the handshake (the `ca_failure_6a80` shape).
  final int mseSw;
}

/// Active Authentication leg configuration. Exactly one of the RSA or
/// EC halves is set; the matching public key must be the SubjectPublicKeyInfo
/// inside the DG15 file handed to [EmrtdChipSim.files] under fid `0x010F`.
///
/// The RSA side composes the ISO 9796-2-shaped recovered block forward
/// (`6A ‖ filler ‖ H(filler‖challenge) ‖ trailer`) and raises it to `d`; the
/// EC side signs the challenge and emits fixed-width plain `r‖s`, exactly
/// what a real chip returns.
class AaSimConfig {
  const AaSimConfig.rsa({
    required this.modulus,
    required this.privateExponent,
    this.trailer = const [0xBC],
    this.hashAlgorithm = 'SHA1',
    this.corruptSignature = false,
  }) : curve = null,
       privateKey = null,
       exponent = null;

  const AaSimConfig.ecdsa({
    required this.curve,
    required BigInt this.privateKey,
    this.hashAlgorithm = 'SHA256',
    this.corruptSignature = false,
  }) : modulus = null,
       privateExponent = null,
       exponent = null,
       trailer = const [];

  /// RSA half.
  final BigInt? modulus;
  final BigInt? privateExponent;
  final BigInt? exponent;

  /// ISO 9796-2 trailer bytes appended to the recovered block (`BC`, or
  /// `xx CC`); [hashAlgorithm] must agree with it.
  final List<int> trailer;

  /// EC half.
  final ECDomainParameters? curve;
  final BigInt? privateKey;

  /// `SHA1`...`SHA512`: the digest the block/signature is built with.
  final String hashAlgorithm;

  /// Flips a byte of the emitted signature: the chip answers `90 00` with a
  /// signature that cannot verify (the verify-failure session row).
  final bool corruptSignature;
}

class EmrtdChipSim implements NfcTransceiver {
  EmrtdChipSim({
    required this.mrzKey,
    required this.files,
    this.cardAccess,
    this.pace,
    this.ca,
    this.aa,
    this.mfSelectSw = 0x9000,
    this.aidSelectSw = 0x9000,
    this.getChallengeSw = 0x9000,
    this.mutualAuthSw = 0x9000,
    this.paceMseSw = 0x6A80,
    this.paceTokenSw = 0x9000,
    Uint8List? rndIcc,
    Uint8List? kicc,
    this.injectSw,
    this.injectThrow,
    this.corruptMac,
    this.malformDo87,
    this.injectDelay,
    this.maxTransceiveLength = 261,
    this.isExtendedLengthApduSupported = false,
    this.historicalBytes,
    this.tagCapabilities,
  }) : rndIcc = rndIcc ?? hx('4608f91988702212'),
       kicc = kicc ?? hx('0b795240cb7049b01c19b33e32804f0b');

  final String mrzKey;

  /// File id -> full file bytes (0x0101 DG1, 0x0102 DG2, 0x011D SOD).
  final Map<int, Uint8List> files;

  /// EF.CardAccess bytes; null = BAC-only chip (SELECT 011C -> 6A 82).
  final Uint8List? cardAccess;

  /// When set, MSE:Set AT + the four GA rounds complete a real ECDH-GM
  /// handshake and SM continues under AES. When null, MSE gets [paceMseSw].
  final PaceSimConfig? pace;

  /// When set, the chip answers the Chip Authentication commands and swaps
  /// its SM side to the CA session keys. When null, they get `6A 80`.
  final CaSimConfig? ca;

  /// When set, the chip answers INTERNAL AUTHENTICATE with a real signature
  /// over the challenge. When null, INS `0x88` gets `6D 00`, the
  /// "instruction not supported" a chip without AA answers.
  final AaSimConfig? aa;

  final int mfSelectSw;
  final int aidSelectSw;
  final int getChallengeSw;
  final int mutualAuthSw;
  final int paceMseSw;

  /// Status word for the final GENERAL AUTHENTICATE (the token round) in
  /// place of the chip's token; `0x9000` completes the handshake. The sim
  /// never checks the terminal's token, so a refused password has to be
  /// scripted here: `0x6300` is the ISO "password wrong" answer.
  final int paceTokenSw;
  final Uint8List rndIcc;
  final Uint8List kicc;

  /// Returns an SW to inject as a bare error response (once-only logic is
  /// the hook's job); null = no injection.
  final int? Function(SimCommand cmd)? injectSw;

  /// Returns an exception to throw at the transport layer (tag pulled,
  /// user canceled...); null = none.
  final Object? Function(SimCommand cmd)? injectThrow;

  /// Returns true to corrupt the DO8E MAC of this protected response.
  final bool Function(SimCommand cmd)? corruptMac;

  /// Returns true to send this protected response's DO87 with padding
  /// indicator `02` instead of `01`, which the terminal rejects as
  /// `D087Malformed` before it checks the MAC. Only a response carrying data
  /// has a DO87.
  final bool Function(SimCommand cmd)? malformDo87;

  /// Returns how long to hold this command before answering it; null answers
  /// at once.
  final Duration? Function(SimCommand cmd)? injectDelay;

  @override
  final int maxTransceiveLength;
  @override
  final bool isExtendedLengthApduSupported;
  @override
  final Uint8List? historicalBytes;
  @override
  final TagCapabilities? tagCapabilities;

  // Session state.
  bool _smActive = false;
  SecureMessagingSupportedAlgorithms _algo =
      SecureMessagingSupportedAlgorithms.des;
  Uint8List _ksenc = Uint8List(0);
  Uint8List _ksmac = Uint8List(0);
  Uint8List _ssc = Uint8List(8);
  int? _currentFid;
  Uint8List? _currentFile;

  // PACE handshake state.
  ECDomainParameters? _paceMapped;
  Uint8List _pacePendingToken = Uint8List(0);
  Uint8List _paceKsEnc = Uint8List(0);
  Uint8List _paceKsMac = Uint8List(0);

  // Chip Authentication state.
  final List<int> _caGaBuffer = [];

  /// Observability for assertions.
  int getChallengeCount = 0;
  int mseSetAtCount = 0;

  /// MSE:Set KAT / MSE:Set AT-for-internal-auth commands seen.
  int caMseCount = 0;

  /// GENERAL AUTHENTICATE commands seen inside the CA handshake:
  /// >1 means command chaining was exercised.
  int caGaCount = 0;

  /// INTERNAL AUTHENTICATE commands seen.
  int internalAuthCount = 0;

  /// The challenge bytes of the last INTERNAL AUTHENTICATE.
  Uint8List? lastAaChallenge;
  final List<int> plainInsLog = [];

  /// Every SELECT-EF-by-file-id the terminal issued, in order, whether the
  /// file exists or not: the read list the session actually walked, which
  /// is what the extras knob must leave untouched by default.
  final List<int> selectedFids = [];

  /// Every command APDU the terminal sent, verbatim and in order: the
  /// comparand for the "a null `trustStore` leaves the APDU stream
  /// byte-identical" regression pin.
  final List<Uint8List> commandLog = [];

  /// Every READ BINARY the terminal issued, plain or protected, injected
  /// errors included: the file it targeted, its offset and its Le, the
  /// chunk sequence a `ReadProfile` produces.
  final List<({int fid, int offset, int le})> readBinaryLog = [];

  int get _padLength =>
      _algo == SecureMessagingSupportedAlgorithms.des ? 8 : 16;

  List<int> get _paddedSSC => _algo == SecureMessagingSupportedAlgorithms.des
      ? _ssc
      : [...List.filled(8, 0), ..._ssc];

  void _incSSC() {
    for (var i = _ssc.length - 1; i >= 0; i--) {
      _ssc[i] = (_ssc[i] + 1) & 0xFF;
      if (_ssc[i] != 0) break;
    }
  }

  static Uint8List _sw(int sw) =>
      Uint8List.fromList([(sw >> 8) & 0xFF, sw & 0xFF]);

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    commandLog.add(Uint8List.fromList(capdu));
    if (capdu[0] == 0x0C) return _handleProtected(capdu);
    return _handlePlain(capdu);
  }

  // ---------------------------------------------------------------------
  // Plain (pre-secure-messaging) commands.
  // ---------------------------------------------------------------------

  Future<Uint8List> _handlePlain(Uint8List capdu) async {
    final ins = capdu[1];
    final p1 = capdu[2];
    final p2 = capdu[3];
    plainInsLog.add(ins);
    final plainLe = ins == 0xB0 ? _plainLe(capdu) : null;
    final cmd = SimCommand(
      ins: ins,
      p1: p1,
      p2: p2,
      isProtected: false,
      fid: _currentFid,
      le: plainLe,
    );
    if (plainLe != null) {
      readBinaryLog.add((
        fid: _currentFid ?? 0,
        offset: (p1 << 8) | p2,
        le: plainLe,
      ));
    }
    final delay = injectDelay?.call(cmd);
    if (delay != null) await Future<void>.delayed(delay);
    final thrown = injectThrow?.call(cmd);
    if (thrown != null) throw thrown;
    final injected = injectSw?.call(cmd);
    if (injected != null) return _sw(injected);

    switch (ins) {
      case 0xA4:
        final data = _plainData(capdu);
        if (p1 == 0x00) return _sw(mfSelectSw); // MF select (any dialect)
        if (p1 == 0x04) return _sw(aidSelectSw); // eMRTD application
        // SELECT EF by FID.
        final fid = (data[0] << 8) | data[1];
        selectedFids.add(fid);
        if (fid == 0x011C) {
          final ca = cardAccess;
          if (ca == null) return _sw(0x6A82);
          _currentFid = fid;
          _currentFile = ca;
          return _sw(0x9000);
        }
        final file = files[fid];
        if (file == null) return _sw(0x6A82);
        _currentFid = fid;
        _currentFile = file;
        return _sw(0x9000);
      case 0xB0: // plain READ BINARY (EF.CardAccess only in this flow)
        final file = _currentFile;
        if (file == null) return _sw(0x6986);
        final offset = (p1 << 8) | p2;
        final le = _plainLe(capdu);
        if (offset >= file.length) return _sw(0x6B00);
        final end = (offset + le) > file.length ? file.length : (offset + le);
        return Uint8List.fromList([...file.sublist(offset, end), 0x90, 0x00]);
      case 0x84: // GET CHALLENGE: starts/restarts BAC, clears SM
        getChallengeCount++;
        if (getChallengeSw != 0x9000) return _sw(getChallengeSw);
        _smActive = false;
        return Uint8List.fromList([...rndIcc, 0x90, 0x00]);
      case 0x82: // EXTERNAL AUTHENTICATE (BAC mutual auth)
        if (mutualAuthSw != 0x9000) return _sw(mutualAuthSw);
        return _bacMutualAuth(_plainData(capdu));
      case 0x22: // MSE:Set AT (PACE)
        mseSetAtCount++;
        if (pace == null) return _sw(paceMseSw);
        return _sw(0x9000);
      case 0x86: // GENERAL AUTHENTICATE (PACE rounds)
        final config = pace;
        if (config == null) return _sw(0x6A80);
        return _paceGeneralAuthenticate(config, _plainData(capdu));
      default:
        return _sw(0x6D00);
    }
  }

  static Uint8List _plainData(Uint8List capdu) {
    if (capdu.length <= 5) return Uint8List(0);
    final lc = capdu[4];
    return Uint8List.sublistView(capdu, 5, 5 + lc);
  }

  static int _plainLe(Uint8List capdu) {
    // Short-form reads in this flow: either header-only (no body, Le last)
    // or the extended-parse header-read `00 B0 00 00 00 00 04`.
    if (capdu.length == 5) return capdu[4] == 0 ? 256 : capdu[4];
    if (capdu.length == 7 && capdu[4] == 0x00) {
      final le = (capdu[5] << 8) | capdu[6];
      return le == 0 ? 65536 : le;
    }
    final le = capdu.last;
    return le == 0 ? 256 : le;
  }

  // ---------------------------------------------------------------------
  // BAC.
  // ---------------------------------------------------------------------

  Uint8List _bacMutualAuth(Uint8List data) {
    final kseed = calcSHA1Hash(utf8.encode(mrzKey)).sublist(0, 16);
    const gen = SecureMessagingSessionKeyGenerator();
    final kenc = gen.deriveKey(keySeed: kseed, mode: SMSMode.encMode);
    final kmac = gen.deriveKey(keySeed: kseed, mode: SMSMode.macMode);

    // Terminal sent E(S) || MAC with S = RND.IFD || RND.ICC || K.IFD.
    final s = tripleDESDecrypt(kenc, data.sublist(0, 32), List.filled(8, 0));
    final rndIfd = s.sublist(0, 8);
    final kifd = s.sublist(16, 32);

    // Chip response: R = RND.ICC || RND.IFD || K.ICC.
    final r = [...rndIcc, ...rndIfd, ...kicc];
    final eicc = tripleDESEncrypt(kenc, r, List.filled(8, 0));
    final micc = desMAC(key: kmac, msg: pad(eicc, blockSize: 8));

    // Session keys + SSC, mirroring the terminal derivation.
    final sessionSeed = xor(kifd, kicc);
    _ksenc = gen.deriveKey(keySeed: sessionSeed, mode: SMSMode.encMode);
    _ksmac = gen.deriveKey(keySeed: sessionSeed, mode: SMSMode.macMode);
    _ssc = Uint8List.fromList([...rndIcc.sublist(4), ...rndIfd.sublist(4)]);
    _algo = SecureMessagingSupportedAlgorithms.des;
    _smActive = true;

    return Uint8List.fromList([...eicc, ...micc, 0x90, 0x00]);
  }

  // ---------------------------------------------------------------------
  // PACE (ECDH-GM over Brainpool P-256; logic mirrors the package's
  // PaceChipSimulator, extended to derive KSenc and hand off to SM).
  // ---------------------------------------------------------------------

  late final ECDomainParameters _paceDomain =
      (PACEInfo(
                oid: pace!.oid,
                version: 2,
                parameterId: PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1,
              ).getParameterSpec()
              as ECStandardizedDomain)
          .domain;

  Uint8List _pacePassword() {
    final hash = calcSHA1Hash(utf8.encode(mrzKey));
    const gen = SecureMessagingSessionKeyGenerator();
    return gen.deriveKey(
      keySeed: hash,
      cipherAlgName: PACEInfo.toCipherAlgorithm(pace!.oid),
      keyLength: PACEInfo.toKeyLength(pace!.oid),
      mode: SMSMode.paceMode,
      paceKeyReference: PACEHandler.MRZ_PACE_KEY_REFERENCE,
    );
  }

  Uint8List _paceGeneralAuthenticate(PaceSimConfig config, Uint8List data) {
    final inner = unwrapDO(0x7c, data);
    List<int> records;
    if (inner.isEmpty) {
      final enc = aesEncrypt(_pacePassword(), config.nonce, List.filled(16, 0));
      records = wrapDO(0x80, enc);
    } else {
      switch (inner[0]) {
        case 0x81:
          final terminalPoint = ecPointDecode(
            _paceDomain,
            unwrapDO(0x81, inner),
          );
          final chipMapPub = ecPointMul(
            _paceDomain,
            config.chipMappingPrivateKey,
            _paceDomain.G,
          );
          final h = ecPointMul(
            _paceDomain,
            config.chipMappingPrivateKey,
            terminalPoint,
          );
          final ghat = ecMulAdd(
            _paceDomain,
            bytesToBigInt(config.nonce),
            _paceDomain.G,
            h,
          );
          _paceMapped = ECDomainParametersImpl(
            'pace-mapped-${_paceDomain.domainName}',
            _paceDomain.curve,
            ghat,
            _paceDomain.n,
            BigInt.one,
          );
          records = wrapDO(0x82, ecPointEncode(chipMapPub));
        case 0x83:
          final mapped = _paceMapped!;
          final terminalPoint = ecPointDecode(mapped, unwrapDO(0x83, inner));
          final chipEphPub = ecPointMul(
            mapped,
            config.chipEphemeralPrivateKey,
            mapped.G,
          );
          final shared = ecdhSharedSecretX(
            mapped,
            config.chipEphemeralPrivateKey,
            terminalPoint,
          );
          const gen = SecureMessagingSessionKeyGenerator();
          final cipherAlg = PACEInfo.toCipherAlgorithm(config.oid);
          final keyLength = PACEInfo.toKeyLength(config.oid);
          _paceKsEnc = gen.deriveKey(
            keySeed: shared,
            cipherAlgName: cipherAlg,
            keyLength: keyLength,
            mode: SMSMode.encMode,
          );
          _paceKsMac = gen.deriveKey(
            keySeed: shared,
            cipherAlgName: cipherAlg,
            keyLength: keyLength,
            mode: SMSMode.macMode,
          );
          _pacePendingToken = paceGenerateAuthenticationToken(
            oid: config.oid,
            cipherAlg: cipherAlg,
            publicKey: EcdhPublicKey(domain: mapped, point: terminalPoint),
            macKey: _paceKsMac,
          );
          records = wrapDO(0x84, ecPointEncode(chipEphPub));
        case 0x85:
          if (paceTokenSw != 0x9000) return _sw(paceTokenSw);
          records = wrapDO(0x86, _pacePendingToken);
          // Under CAM the same response carries the DO8A (§4.4.5 Table 4).
          // A literal payload wins; otherwise a static keypair produces the
          // real CA_IC = SK_IC⁻¹·SK_Map,IC mod n; with neither the response
          // has no DO8A at all.
          if (PACEInfo.toMappingType(config.oid) == PACEMappingType.CAM) {
            final literal = config.camDataObject;
            final skIc = config.camStaticPrivateKey;
            if (literal != null) {
              records = [...records, ...wrapDO(0x8a, literal)];
            } else if (skIc != null) {
              final n = _paceDomain.n;
              final caIc =
                  skIc.modInverse(n) * config.chipMappingPrivateKey % n;
              final plaintext = pad(
                bigIntToBytes(caIc, length: (n.bitLength + 7) >> 3),
                blockSize: 16,
              );
              final iv = aesEncrypt(
                _paceKsEnc,
                List.filled(16, 0xFF),
                List.filled(16, 0),
              );
              records = [
                ...records,
                ...wrapDO(0x8a, aesEncrypt(_paceKsEnc, plaintext, iv)),
              ];
            }
          }
          // paceCompleted on the terminal restarts SM (AES, SSC = 0);
          // mirror it chip-side.
          _ksenc = _paceKsEnc;
          _ksmac = _paceKsMac;
          _ssc = Uint8List(8);
          _algo = SecureMessagingSupportedAlgorithms.aes;
          _smActive = true;
        default:
          return _sw(0x6A80);
      }
    }
    return Uint8List.fromList([...wrapDO(0x7c, records), 0x90, 0x00]);
  }

  // ---------------------------------------------------------------------
  // Secure-messaging-protected commands.
  // ---------------------------------------------------------------------

  Future<Uint8List> _handleProtected(Uint8List capdu) async {
    if (!_smActive) return _sw(0x6987);
    _incSSC(); // command counterpart of the terminal's protect() increment

    final ins = capdu[1];
    final p1 = capdu[2];
    final p2 = capdu[3];
    final lc = capdu[4];
    final body = capdu.sublist(5, 5 + lc);

    Uint8List? do87Payload;
    var le = 256;
    var i = 0;
    while (i < body.length) {
      final tag = body[i];
      final (len, lenBytes) = asn1Length(body.sublist(i + 1));
      final value = body.sublist(i + 1 + lenBytes, i + 1 + lenBytes + len);
      if (tag == 0x87) {
        final cipher = value.sublist(1); // strip the 0x01 padding marker
        final Uint8List dec;
        if (_algo == SecureMessagingSupportedAlgorithms.des) {
          dec = tripleDESDecrypt(_ksenc, cipher, List.filled(8, 0));
        } else {
          final iv = aesECBEncrypt(_ksenc, [...List.filled(8, 0), ..._ssc]);
          dec = aesDecrypt(_ksenc, cipher, iv);
        }
        do87Payload = unpad(dec);
      } else if (tag == 0x97) {
        final raw = binToInt(value);
        le = raw == 0 ? 256 : raw;
      }
      i += 1 + lenBytes + len;
    }

    // SELECT tracks the file BEFORE hooks so hooks can key on the target.
    if (ins == 0xA4 && p1 == 0x02 && do87Payload != null) {
      _currentFid = (do87Payload[0] << 8) | do87Payload[1];
      selectedFids.add(_currentFid!);
    }

    final cmd = SimCommand(
      ins: ins,
      p1: p1,
      p2: p2,
      isProtected: true,
      fid: _currentFid,
      le: ins == 0xB0 ? le : null,
    );
    if (ins == 0xB0) {
      readBinaryLog.add((
        fid: _currentFid ?? 0,
        offset: (p1 << 8) | p2,
        le: le,
      ));
    }
    final delay = injectDelay?.call(cmd);
    if (delay != null) await Future<void>.delayed(delay);
    final thrown = injectThrow?.call(cmd);
    if (thrown != null) throw thrown;
    final injected = injectSw?.call(cmd);
    if (injected != null) {
      _incSSC(); // the terminal's unprotect() increments before bailing raw
      return _sw(injected);
    }

    switch (ins) {
      case 0xA4:
        if (p1 == 0x04) {
          if (aidSelectSw != 0x9000) {
            _incSSC();
            return _sw(aidSelectSw);
          }
          return _protectedResponse(cmd);
        }
        final file = files[_currentFid];
        if (file == null) {
          _incSSC();
          return _sw(0x6A82);
        }
        _currentFile = file;
        return _protectedResponse(cmd);
      case 0xB0:
        final file = _currentFile;
        if (file == null) {
          _incSSC();
          return _sw(0x6986);
        }
        final offset = (p1 << 8) | p2;
        if (offset >= file.length) {
          _incSSC();
          return _sw(0x6B00);
        }
        final end = (offset + le) > file.length ? file.length : (offset + le);
        return _protectedResponse(cmd, data: file.sublist(offset, end));
      case 0x22: // Chip Authentication MSE (KAT for DESede, Set AT for AES)
        return _caMse(cmd, p1: p1, p2: p2, data: do87Payload);
      case 0x86: // Chip Authentication GENERAL AUTHENTICATE
        return _caGeneralAuthenticate(cmd, data: do87Payload);
      case 0x88: // INTERNAL AUTHENTICATE (Active Authentication)
        return _internalAuthenticate(cmd, data: do87Payload);
      default:
        _incSSC();
        return _sw(0x6D00);
    }
  }

  // ---------------------------------------------------------------------
  // Chip Authentication.
  // ---------------------------------------------------------------------

  Uint8List _caMse(
    SimCommand cmd, {
    required int p1,
    required int p2,
    Uint8List? data,
  }) {
    caMseCount++;
    final config = ca;
    if (config == null || p1 != 0x41) {
      _incSSC();
      return _sw(0x6A80);
    }
    if (config.mseSw != 0x9000) {
      _incSSC();
      return _sw(config.mseSw);
    }
    if (p2 == 0xA6) {
      // MSE:Set KAT: data is DO91(keyData) [|| DO84(keyId)]; the DESede
      // suites carry the whole handshake in this one command.
      final records = TlvRecord.sequenceOfRecords(data ?? Uint8List(0));
      if (records == null || records.isEmpty || records.first.tag != 0x91) {
        _incSSC();
        return _sw(0x6A80);
      }
      final session = _caDeriveSession(records.first.value);
      final response = _protectedResponse(cmd);
      _installCaSession(session);
      return response;
    }
    if (p2 == 0xA4) {
      // MSE:Set AT for internal authentication: the AES suites' first step;
      // the key material follows over GENERAL AUTHENTICATE.
      _caGaBuffer.clear();
      return _protectedResponse(cmd);
    }
    _incSSC();
    return _sw(0x6A80);
  }

  Uint8List _caGeneralAuthenticate(SimCommand cmd, {Uint8List? data}) {
    caGaCount++;
    final config = ca;
    if (config == null || data == null) {
      _incSSC();
      return _sw(0x6A80);
    }
    final Uint8List inner;
    try {
      inner = unwrapDO(0x7c, data);
    } on Object {
      _incSSC();
      return _sw(0x6A80);
    }
    _caGaBuffer.addAll(inner);

    // The SM CLA mask drops the 0x10 chaining bit, so completeness is
    // decided by the accumulated DO80 rather than by the command class.
    final assembled = TlvRecord.parse(_caGaBuffer);
    if (assembled == null ||
        assembled.tag != 0x80 ||
        assembled.data.length != _caGaBuffer.length) {
      // Intermediate segment: `7C 00`, which is exactly what upstream's
      // unconditional unwrapDO expects to find.
      return _protectedResponse(cmd, data: wrapDO(0x7c, const []));
    }

    final session = _caDeriveSession(assembled.value);
    _caGaBuffer.clear();
    final response = _protectedResponse(cmd, data: wrapDO(0x7c, const []));
    _installCaSession(session);
    return response;
  }

  ({Uint8List ksenc, Uint8List ksmac, SecureMessagingSupportedAlgorithms algo})
  _caDeriveSession(Uint8List terminalKeyData) {
    final config = ca!;
    final curve = config.curve;
    final Uint8List keySeed;
    if (curve != null) {
      keySeed = ecdhSharedSecretX(
        curve,
        config.chipPrivateKey,
        ecPointDecode(curve, terminalKeyData),
      );
    } else {
      // Upstream's DH keySeed composition, mirrored chip-side so both ends
      // derive the same (upstream-shaped) keys.
      keySeed = chipAuthDhKeySeed(
        p: config.p!,
        x: config.chipPrivateKey,
        peerPublic: bytesToBigInt(terminalKeyData),
      );
    }
    final (ksenc, ksmac) = chipAuthDeriveSessionKeys(
      keySeed: keySeed,
      oid: config.oid,
    );
    return (
      ksenc: ksenc,
      ksmac: ksmac,
      algo: ChipAuthenticationInfo.toCipherAlgorithm(config.oid) == 'DESede'
          ? SecureMessagingSupportedAlgorithms.des
          : SecureMessagingSupportedAlgorithms.aes,
    );
  }

  void _installCaSession(
    ({
      Uint8List ksenc,
      Uint8List ksmac,
      SecureMessagingSupportedAlgorithms algo,
    })
    session,
  ) {
    _ksenc = session.ksenc;
    _ksmac = session.ksmac;
    _ssc = Uint8List(8);
    _algo = session.algo;
    _smActive = true;
  }

  // ---------------------------------------------------------------------
  // Active Authentication.
  // ---------------------------------------------------------------------

  Uint8List _internalAuthenticate(SimCommand cmd, {Uint8List? data}) {
    internalAuthCount++;
    final config = aa;
    if (config == null || data == null) {
      _incSSC();
      return _sw(0x6D00); // no AA on this chip
    }
    lastAaChallenge = Uint8List.fromList(data);
    final signature = _aaSign(config, data);
    return _protectedResponse(cmd, data: signature);
  }

  List<int> _aaSign(AaSimConfig config, Uint8List challenge) {
    final List<int> out;
    final modulus = config.modulus;
    if (modulus != null) {
      // Compose the recovered block the verifier walks, then raise it to d.
      final k = (modulus.bitLength + 7) >> 3;
      final hashLen = calcHash(const [], config.hashAlgorithm).length;
      final msgLen = k - 1 - hashLen - config.trailer.length;
      final message = List<int>.generate(
        msgLen,
        (i) => 0x40 + (i % 0x30),
        growable: false,
      );
      final block = <int>[
        0x6A,
        ...message,
        ...calcHash([...message, ...challenge], config.hashAlgorithm),
        ...config.trailer,
      ];
      out = bigIntToBytes(
        bytesToBigInt(block).modPow(config.privateExponent!, modulus),
        length: k,
      );
    } else {
      final curve = config.curve!;
      // RFC 6979 deterministic k (the HMAC arm of pointycastle's signer): the
      // sim needs no RNG seam and every session test signs reproducibly.
      final signer =
          ECDSASigner(
            _digestFor(config.hashAlgorithm),
            HMac(
              _digestFor(config.hashAlgorithm),
              _hmacBlockLength(config.hashAlgorithm),
            ),
          )..init(
            true,
            PrivateKeyParameter<ECPrivateKey>(
              ECPrivateKey(config.privateKey, curve),
            ),
          );
      final sig = signer.generateSignature(challenge) as ECSignature;
      final fieldLen = (curve.n.bitLength + 7) >> 3;
      out = [
        ...bigIntToBytes(sig.r, length: fieldLen),
        ...bigIntToBytes(sig.s, length: fieldLen),
      ];
    }
    if (config.corruptSignature) {
      final broken = Uint8List.fromList(out);
      broken[broken.length - 1] ^= 0xFF;
      return broken;
    }
    return out;
  }

  static int _hmacBlockLength(String name) =>
      name == 'SHA384' || name == 'SHA512' ? 128 : 64;

  static Digest _digestFor(String name) => switch (name) {
    'SHA1' => SHA1Digest(),
    'SHA224' => SHA224Digest(),
    'SHA256' => SHA256Digest(),
    'SHA384' => SHA384Digest(),
    'SHA512' => SHA512Digest(),
    _ => throw ArgumentError('unsupported AA digest $name'),
  };

  Uint8List _protectedResponse(SimCommand cmd, {List<int> data = const []}) {
    _incSSC(); // response counterpart of the terminal's unprotect()
    var do87 = <int>[];
    if (data.isNotEmpty) {
      final padded = pad(data, blockSize: _padLength);
      final Uint8List enc;
      if (_algo == SecureMessagingSupportedAlgorithms.des) {
        enc = tripleDESEncrypt(_ksenc, padded, List.filled(8, 0));
      } else {
        final iv = aesECBEncrypt(_ksenc, [...List.filled(8, 0), ..._ssc]);
        enc = aesEncrypt(_ksenc, padded, iv);
      }
      final indicator = (malformDo87?.call(cmd) ?? false) ? 0x02 : 0x01;
      final cipher = [indicator, ...enc];
      do87 = [0x87, ...toAsn1Length(cipher.length), ...cipher];
    }
    final do99 = [0x99, 0x02, 0x90, 0x00];
    final n = pad([..._paddedSSC, ...do87, ...do99], blockSize: _padLength);
    var cc = mac(algoName: _algo, key: _ksmac, msg: n);
    if (cc.length > 8) cc = cc.sublist(0, 8);
    if (corruptMac?.call(cmd) ?? false) {
      cc = Uint8List.fromList(cc);
      cc[0] ^= 0xFF;
    }
    final do8e = [0x8E, cc.length, ...cc];
    return Uint8List.fromList([...do87, ...do99, ...do8e, 0x90, 0x00]);
  }
}
