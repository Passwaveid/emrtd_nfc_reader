// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/SecureMessaging.swift @ 3bf5456 (2.3.2)
//   (its `SecureMessagingSupportedAlgorithms` enum lives in
//    crypto/mac.dart)

/// Secure messaging. `TagReader` carries an optional session and calls
/// `protect` before transceiving / `unprotect` on the accumulated response,
/// exactly as upstream's `SecureMessaging?` property.
///
/// Upstream's quirks and its size-guard salvage are preserved. Two upstream
/// defects are fixed: the AES response-MAC check, which upstream makes
/// compare the received MAC with itself (a security fix), and the DO99 `&&`
/// check. Chip-declared lengths are bounds-checked, throwing typed errors
/// where upstream crashes, and the SSC is incremented byte-wise. See
/// UPSTREAM.md, Divergences.
library;

import 'dart:typed_data';

import '../crypto/ciphers.dart';
import '../crypto/mac.dart';
import '../errors.dart';
import '../lds/tlv.dart';
import '../logging.dart';
import '../utils.dart';
import 'command_apdu.dart';
import 'response_apdu.dart';

abstract class SecureMessagingSession {
  /// Cipher block size the session pads to: 8 for 3DES, 16 for AES. The
  /// read loop sizes its chunks from it (`fitReadLength`).
  int get padLength;

  /// Wraps [apdu] into its protected form. [useExtendedMode] mirrors
  /// upstream's `protect(apdu:useExtendedMode:)` signature; always false in
  /// ported scope (the flag existed for Active Authentication).
  CommandAPDU protect(CommandAPDU apdu, {bool useExtendedMode = false});

  /// Unwraps a protected response (after GET RESPONSE accumulation: the
  /// whole response is unprotected once).
  ResponseAPDU unprotect(ResponseAPDU rapdu);
}

/// Upstream `SecureMessaging`, the doc9303 secure-messaging layer between
/// `TagReader` and the wire (BAC/PACE session keys + SSC).
class SecureMessaging implements SecureMessagingSession {
  /// Upstream `init(encryptionAlgorithm:ksenc:ksmac:ssc:)`.
  ///
  /// Dart-only guard: [ssc] must be exactly 8 bytes; the SSC is 8 bytes
  /// throughout (BAC: 9303-11 §9.8.6.3; the AES paths prepend `0^8` to reach
  /// the 16-byte block). Upstream accepts any length and misbehaves.
  SecureMessaging({
    this.encryptionAlgorithm = SecureMessagingSupportedAlgorithms.des,
    required List<int> ksenc,
    required List<int> ksmac,
    required List<int> ssc,
  }) : _ksenc = Uint8List.fromList(ksenc),
       _ksmac = Uint8List.fromList(ksmac),
       _ssc = Uint8List.fromList(ssc),
       padLength = encryptionAlgorithm == SecureMessagingSupportedAlgorithms.des
           ? 8
           : 16 {
    if (_ssc.length != 8) {
      throw InvalidDataPassed('SSC must be 8 bytes, got ${_ssc.length}');
    }
  }

  final SecureMessagingSupportedAlgorithms encryptionAlgorithm;

  /// Upstream `padLength`: DES pads to 8, AES to 16.
  @override
  final int padLength;

  final Uint8List _ksenc;
  final Uint8List _ksmac;
  Uint8List _ssc;

  /// Current SSC (copy). Private upstream; readable here so unit tests and
  /// conformance ops can pin its trajectory.
  Uint8List get ssc => Uint8List.fromList(_ssc);

  /// The MAC-input SSC is the raw 8 bytes for DES, `0^8 ‖ SSC` for AES
  /// (9303-11 §9.8.2 sizes the SSC at the cipher block; §9.8.7.2 prepends
  /// all 16 bytes to the CMAC input). Recomputed by both `protect` and
  /// `unprotect`.
  List<int> get _paddedSSC =>
      encryptionAlgorithm == SecureMessagingSupportedAlgorithms.des
      ? _ssc
      : [...List.filled(8, 0), ..._ssc];

  /// Protect the apdu following the doc9303 specification. (upstream comment)
  @override
  CommandAPDU protect(CommandAPDU apdu, {bool useExtendedMode = false}) {
    secureMessagingLog.fine('\t\tSSC: ${binToHexRep(_ssc)}');
    _ssc = incSSC();
    final paddedSSC = _paddedSSC;
    secureMessagingLog.fine('\tIncrement SSC with 1');
    secureMessagingLog.fine('\t\tSSC: ${binToHexRep(_ssc)}');

    final cmdHeader = maskClassAndPad(apdu);
    var do87 = <int>[];
    var do97 = <int>[];

    var tmp = 'Concatenate CmdHeader';
    if (apdu.data.isNotEmpty) {
      tmp += ' and DO87';
      do87 = buildD087(apdu);
    }

    final isMSE = apdu.instructionCode == 0x22;
    if (apdu.expectedResponseLength > 0 &&
        (isMSE ? apdu.expectedResponseLength < 256 : true)) {
      tmp += ' and DO97';
      do97 = buildD097(apdu);
    }

    final m = [...cmdHeader, ...do87, ...do97];
    secureMessagingLog.fine(tmp);
    secureMessagingLog.fine('\tM: ${binToHexRep(m)}');

    secureMessagingLog.fine('Compute MAC of M');

    final n = pad([...paddedSSC, ...m], blockSize: padLength);
    secureMessagingLog.fine('\tConcatenate SSC and M and add padding');
    secureMessagingLog.fine('\t\tN: ${binToHexRep(n)}');

    var cc = mac(algoName: encryptionAlgorithm, key: _ksmac, msg: n);
    if (cc.length > 8) {
      cc = cc.sublist(0, 8);
    }
    secureMessagingLog.fine('\tCompute MAC over N with KSmac');
    secureMessagingLog.fine('\t\tCC: ${binToHexRep(cc)}');

    final do8e = buildD08E(cc);

    // If dataSize > 255 then it will be encoded in 3 bytes with the first
    // byte being 0x00, otherwise its a single byte of size (upstream comment)
    final size = do87.length + do97.length + do8e.length;
    // If the data is more that 255, specify the we are using extended length
    // (0x00, 0x00). Thanks to @filom for the fix! (upstream comment)
    final extended =
        size > 255 || (useExtendedMode && apdu.expectedResponseLength > 231);
    final dataSize = extended
        ? [0x00, ...intToBin(size, pad: 4)]
        : intToBin(size);
    final protectedAPDU = [
      ...cmdHeader.sublist(0, 4),
      ...dataSize,
      ...do87,
      ...do97,
      ...do8e,
      ...extended ? const [0x00, 0x00] : const [0x00],
    ];
    secureMessagingLog.fine('Construct and send protected APDU');
    secureMessagingLog.fine('\tProtectedAPDU: ${binToHexRep(protectedAPDU)}');

    return CommandAPDU.parse(protectedAPDU);
  }

  /// Unprotect the APDU following the iso7816 specification. (upstream
  /// comment)
  @override
  ResponseAPDU unprotect(ResponseAPDU rapdu) {
    var needCC = false;
    var do87 = <int>[];
    var do87Data = <int>[];
    var do99 = <int>[];
    var offset = 0;

    _ssc = incSSC();
    final paddedSSC = _paddedSSC;
    secureMessagingLog.fine('\tIncrement SSC with 1');
    secureMessagingLog.fine('\t\tSSC: ${binToHexRep(_ssc)}');

    // Check for a SM error (raw return, but the SSC increment above has
    // already happened; the chip incremented on its side too).
    if (rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00) {
      return rapdu;
    }

    final rapduBin = [...rapdu.data, rapdu.sw1, rapdu.sw2];
    secureMessagingLog.fine("Receive response APDU of MRTD's chip");
    secureMessagingLog.fine('\tRAPDU: ${binToHexRep(rapduBin)}');

    // DO'87'
    // Mandatory if data is returned, otherwise absent (upstream comment)
    if (rapduBin[0] == 0x87) {
      final (int, int) decoded;
      try {
        decoded = asn1Length(rapduBin.sublist(1));
      } on CannotDecodeASN1Length {
        // Upstream crashes on a length form its codec rejects.
        throw const InvalidDataPassed('DO87 length malformed');
      }
      final (encDataLength, o) = decoded;
      offset = 1 + o;

      // Every slice below trusts chip-declared lengths upstream and crashes
      // on truncated/hostile input (bounds-checked typed throws).
      if (offset >= rapduBin.length) {
        throw const InvalidDataPassed('DO87 truncated');
      }
      if (rapduBin[offset] != 0x1) {
        throw const D087Malformed();
      }
      if (encDataLength < 1 || offset + encDataLength > rapduBin.length) {
        throw const InvalidDataPassed('DO87 length exceeds response');
      }

      do87 = rapduBin.sublist(0, offset + encDataLength);
      do87Data = rapduBin.sublist(offset + 1, offset + encDataLength);
      offset += encDataLength;
      needCC = true;
    }

    // DO'99'
    // Mandatory, only absent if SM error occurs (upstream comment)
    if (rapduBin.length < offset + 5) {
      // Upstream's salvage. Reconstruct a status from whatever bytes
      // exist (possibly 0), empty data. Preserved exactly.
      secureMessagingLog.severe('size error');
      final returnSw1 = rapduBin.length >= offset + 3
          ? rapduBin[offset + 2]
          : 0;
      final returnSw2 = rapduBin.length >= offset + 4
          ? rapduBin[offset + 3]
          : 0;
      return ResponseAPDU(Uint8List(0), returnSw1, returnSw2);
    }

    do99 = rapduBin.sublist(offset, offset + 4);
    final sw1 = rapduBin[offset + 2];
    final sw2 = rapduBin[offset + 3];
    offset += 4;
    needCC = true;

    // `||`, not upstream's `&&`, which lets a right-tag/wrong-length DO99
    // through to MAC verification.
    if (do99[0] != 0x99 || do99[1] != 0x02) {
      // SM error, return the error code (upstream comment)
      return ResponseAPDU(Uint8List(0), sw1, sw2);
    }

    // DO'8E'
    // Mandatory if DO'87' and/or DO'99' is present (upstream comment)
    if (rapduBin[offset] == 0x8E) {
      if (offset + 2 > rapduBin.length) {
        throw const InvalidDataPassed('DO8E truncated');
      }
      final ccLength = binToHex(rapduBin[offset + 1]);
      if (offset + 2 + ccLength > rapduBin.length) {
        throw const InvalidDataPassed('DO8E MAC length exceeds response');
      }
      final cc = rapduBin.sublist(offset + 2, offset + 2 + ccLength);

      // CheckCC (upstream comment)
      var tmp = '';
      if (do87.isNotEmpty) {
        tmp += " DO'87";
      }
      if (do99.isNotEmpty) {
        tmp += " DO'99";
      }
      secureMessagingLog.fine('Verify RAPDU CC by computing MAC of $tmp');

      final k = pad([...paddedSSC, ...do87, ...do99], blockSize: padLength);
      secureMessagingLog.fine('\tConcatenate SSC and $tmp and add padding');
      secureMessagingLog.fine('\t\tK: ${binToHexRep(k)}');

      secureMessagingLog.fine('\tCompute MAC with KSmac');
      var ccB = mac(algoName: encryptionAlgorithm, key: _ksmac, msg: k);
      if (ccB.length > 8) {
        // A security fix: upstream truncates the *received* CC here
        // (`CCb = CC[0..<8]`), making the AES comparison self-comparing, so
        // responses pass MAC verification unconditionally. Truncate the
        // computed MAC.
        ccB = ccB.sublist(0, 8);
      }
      secureMessagingLog.fine('\t\tCC: ${binToHexRep(ccB)}');

      final res = _bytesEqual(cc, ccB);
      secureMessagingLog.fine("\tCompare CC with data of DO'8E of RAPDU");
      secureMessagingLog.fine(
        '\t\t${binToHexRep(cc)}  == ${binToHexRep(ccB)} ? $res',
      );

      if (!res) {
        throw const InvalidResponseChecksum();
      }
    } else if (needCC) {
      throw const MissingMandatoryFields();
    }

    var data = Uint8List(0);
    if (do87Data.isNotEmpty) {
      final Uint8List dec;
      if (encryptionAlgorithm == SecureMessagingSupportedAlgorithms.des) {
        dec = tripleDESDecrypt(_ksenc, do87Data, List.filled(8, 0));
      } else {
        // for AES the IV is the ssc with AES/EBC/NOPADDING (upstream
        // comment; IV = E(KSEnc, SSC), 9303-11 §9.8.7.1)
        final paddedssc = [...List.filled(8, 0), ..._ssc];
        final iv = aesECBEncrypt(_ksenc, paddedssc);
        dec = aesDecrypt(_ksenc, do87Data, iv);
      }

      // There is a payload (upstream comment)
      data = unpad(dec);
      secureMessagingLog.fine("Decrypt data of DO'87 with KSenc");
      secureMessagingLog.fine('\tDecryptedData: ${binToHexRep(data)}');
    }

    secureMessagingLog.fine(
      'Unprotected APDU: [${binToHexRep(data)}] '
      '${binToHexRepByte(sw1)} ${binToHexRepByte(sw2)}',
    );
    return ResponseAPDU(data, sw1, sw2);
  }

  /// Upstream `maskClassAndPad`: CLA masked to the literal `0x0C`, header
  /// padded to the cipher block.
  Uint8List maskClassAndPad(CommandAPDU apdu) {
    secureMessagingLog.fine('Mask class byte and pad command header');
    final res = pad([
      0x0c,
      apdu.instructionCode,
      apdu.p1Parameter,
      apdu.p2Parameter,
    ], blockSize: padLength);
    secureMessagingLog.fine('\tCmdHeader: ${binToHexRep(res)}');
    return res;
  }

  /// Upstream `buildD087`: `87 L 01 ‖ E(KSenc, pad(data))`.
  Uint8List buildD087(CommandAPDU apdu) {
    final cipher = [0x01, ...padAndEncryptData(apdu)];
    final res = [0x87, ...toAsn1Length(cipher.length), ...cipher];
    secureMessagingLog.fine("Build DO'87");
    secureMessagingLog.fine('\tDO87: ${binToHexRep(res)}');
    return Uint8List.fromList(res);
  }

  /// Upstream `padAndEncryptData`: pad the data, encrypt with KSenc (DES:
  /// zero IV; AES: IV = E(KSenc, `0^8 ‖ SSC`)).
  Uint8List padAndEncryptData(CommandAPDU apdu) {
    final paddedData = pad(apdu.data, blockSize: padLength);

    final Uint8List enc;
    if (encryptionAlgorithm == SecureMessagingSupportedAlgorithms.des) {
      enc = tripleDESEncrypt(_ksenc, paddedData, List.filled(8, 0));
    } else {
      // for AES the IV is the ssc with AES/EBC/NOPADDING (upstream comment)
      final paddedssc = [...List.filled(8, 0), ..._ssc];
      final iv = aesECBEncrypt(_ksenc, paddedssc);
      enc = aesEncrypt(_ksenc, paddedData, iv);
    }

    secureMessagingLog.fine('Pad data');
    secureMessagingLog.fine('\tData: ${binToHexRep(paddedData)}');
    secureMessagingLog.fine('Encrypt data with KSenc');
    secureMessagingLog.fine('\tEncryptedData: ${binToHexRep(enc)}');
    return enc;
  }

  /// Upstream `incSSC`, re-implemented: an 8-byte big-endian increment with
  /// carry; the SSC never round-trips through an integer (a BAC SSC
  /// routinely has its top bit set, the signed-Int64 trap upstream walks
  /// into via `binToHex + 1`). `0xFF...FF` wraps to `0x00...00` (upstream
  /// traps there); byte-identical to upstream for every value a session
  /// reaches.
  Uint8List incSSC() {
    final next = Uint8List.fromList(_ssc);
    for (var i = next.length - 1; i >= 0; i--) {
      next[i] = (next[i] + 1) & 0xFF;
      if (next[i] != 0) {
        break;
      }
    }
    return next;
  }

  /// Upstream `buildD08E`: `8E L ‖ mac`.
  Uint8List buildD08E(List<int> mac) {
    final res = [0x8E, mac.length, ...mac];
    secureMessagingLog.fine("Build DO'8E");
    secureMessagingLog.fine('\tDO8E: ${binToHexRep(res)}');
    return Uint8List.fromList(res);
  }

  /// Upstream `buildD097`: `97 L ‖ Le`, with `256 -> 00` and
  /// `65536 -> 00 00`. Other Le > 255 fall into `intToBin`, latent upstream
  /// (in-scope Le is ≤ 256 or 65536); here `intToBin` encodes them at even
  /// width, where upstream's formats odd-width hex and mangles the bytes.
  Uint8List buildD097(CommandAPDU apdu) {
    final le = apdu.expectedResponseLength;
    var binLe = intToBin(le);
    if (le == 256 || le == 65536) {
      binLe = Uint8List.fromList([0x00, if (le > 256) 0x00]);
    }

    final res = [0x97, ...toAsn1Length(binLe.length), ...binLe];
    secureMessagingLog.fine("Build DO'97");
    secureMessagingLog.fine('\tDO97: $res');
    return Uint8List.fromList(res);
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
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
}
