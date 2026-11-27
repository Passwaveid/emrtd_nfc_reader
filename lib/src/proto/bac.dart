// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/BACHandler.swift @ 3bf5456 (2.3.2)
//   minus the unused `KENC`/`KMAC` consts and the commented-out
//   `keyDerivation` (dropped; the KDF lives in crypto/kdf.dart), and the
//   for-testing-only no-tagReader `init()`.

/// BAC: Basic Access Control. Derives the document basic access keys from
/// the MRZ key, runs GET CHALLENGE + EXTERNAL AUTHENTICATE through
/// `TagReader`, derives the session keys and installs the DES
/// `SecureMessaging` session.
///
/// Upstream's key-derivation slices are kept verbatim. The mutual-auth
/// response, which upstream never authenticates, is verified (a security
/// fix; see `sessionKeys`). A wrong MRZ key surfaces as `63 XX` ->
/// `InvalidMRZKey` from `TagReader.send`'s status check, with an
/// empty-success guard kept as defense-in-depth. `composeMrzKey` is a
/// Dart-only addition.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/ciphers.dart';
import '../crypto/hashes.dart';
import '../crypto/kdf.dart';
import '../crypto/mac.dart';
import '../crypto/rng.dart';
import '../errors.dart';
import '../logging.dart';
import '../utils.dart';
import 'secure_messaging.dart';
import 'tag_reader.dart';

/// Upstream `BACHandler`.
class BACHandler {
  /// Upstream `init(tagReader:)`. [random] is the randomness seam upstream
  /// lacks (`generateRandomUInt8Array`/arc4random baked in): BAC consumes
  /// 8 (RND.IFD) + 16 (K.IFD) bytes per session, and deterministic
  /// transcripts inject a [FixedRandom].
  BACHandler({required this.tagReader, EmrtdRandom? random})
    : random = random ?? SystemRandom();

  final TagReader tagReader;
  final EmrtdRandom random;

  Uint8List ksenc = Uint8List(0);
  Uint8List ksmac = Uint8List(0);

  Uint8List _rndIcc = Uint8List(0);
  Uint8List _rndIfd = Uint8List(0);
  Uint8List kifd = Uint8List(0);

  Future<void> performBACAndGetSessionKeys(String mrzKey) async {
    bacLog.fine('BACHandler - deriving Document Basic Access Keys');
    deriveDocumentBasicAccessKeys(mrzKey);

    // Make sure we clear secure messaging (could happen if we read an
    // invalid DG or we hit a secure error (upstream comment)
    tagReader.secureMessaging = null;

    // get Challenge
    bacLog.fine('BACHandler - Getting initial challenge');
    final response = await tagReader.getChallenge();
    bacLog.fine('DATA - ${response.data}');

    bacLog.fine('BACHandler - Doing mutual authentication');
    final cmdData = authentication(response.data);
    final maResponse = await tagReader.doMutualAuthentication(cmdData);
    bacLog.fine('DATA - ${maResponse.data}');
    // A `63 XX` EXTERNAL AUTHENTICATE failure has already thrown
    // `InvalidMRZKey` inside send(), whose status check upstream gets
    // wrong. This guard is retained as defense-in-depth: it catches
    // pathological empty-success responses (the Belarusian-ID shape).
    if (maResponse.data.isEmpty) {
      throw const InvalidMRZKey();
    }

    final session = sessionKeys(maResponse.data);
    tagReader.secureMessaging = SecureMessaging(
      ksenc: session.ksenc,
      ksmac: session.ksmac,
      ssc: session.ssc,
    );
    bacLog.fine('BACHandler - complete');
  }

  ({Uint8List ksenc, Uint8List ksmac}) deriveDocumentBasicAccessKeys(
    String mrz,
  ) {
    final kseed = generateInitialKseed(mrz);

    bacLog.fine(
      'Calculate the Basic Access Keys (Kenc and Kmac) using TR-SAC 1.01, '
      '4.2',
    );
    const smskg = SecureMessagingSessionKeyGenerator();
    ksenc = smskg.deriveKey(keySeed: kseed, mode: SMSMode.encMode);
    ksmac = smskg.deriveKey(keySeed: kseed, mode: SMSMode.macMode);

    return (ksenc: ksenc, ksmac: ksmac);
  }

  /// Calculate the kseed from the kmrz: SHA-1 of the kmrz, most significant
  /// 16 bytes (upstream doc).
  Uint8List generateInitialKseed(String kmrz) {
    bacLog.fine('Calculate the SHA-1 hash of MRZ_information');
    bacLog.fine('\tMRZ KEY - $kmrz');
    final hash = calcSHA1Hash(utf8.encode(kmrz));

    bacLog.fine('\tsha1(MRZ_information): ${binToHexRep(hash)}');

    final subHash = hash.sublist(0, 16);
    bacLog.fine('Take the most significant 16 bytes to form the Kseed');
    bacLog.fine('\tKseed: ${binToHexRep(subHash)}');

    return subHash;
  }

  /// Construct the command data for the mutual authentication:
  /// `eifd = TDES(rnd_ifd ‖ rnd_icc ‖ kifd, Kenc)`,
  /// `mifd = mac(pad(eifd))`, returns `eifd ‖ mifd` (upstream doc).
  ///
  /// Consumes exactly 8 + 16 bytes from [random], in that order.
  Uint8List authentication(List<int> rndIcc) {
    _rndIcc = Uint8List.fromList(rndIcc);

    bacLog.fine("Request an 8 byte random number from the MRTD's chip");
    bacLog.fine("\tRND.ICC: '${binToHexRep(_rndIcc)}");

    final rndIfd = random.nextBytes(8);
    final kifd = random.nextBytes(16);

    bacLog.fine('Generate an 8 byte random and a 16 byte random');
    bacLog.fine('\tRND.IFD: ${binToHexRep(rndIfd)}');
    bacLog.fine('\tRND.Kifd: ${binToHexRep(kifd)}');

    final s = [...rndIfd, ...rndIcc, ...kifd];

    bacLog.fine('Concatenate RND.IFD, RND.ICC and Kifd');
    bacLog.fine('\tS: ${binToHexRep(s)}');

    final iv = List.filled(8, 0);
    final eifd = tripleDESEncrypt(ksenc, s, iv);

    bacLog.fine('Encrypt S with TDES key Kenc as calculated in Appendix 5.2');
    bacLog.fine('\tEifd: ${binToHexRep(eifd)}');

    final mifd = mac(
      algoName: SecureMessagingSupportedAlgorithms.des,
      key: ksmac,
      msg: pad(eifd, blockSize: 8),
    );

    bacLog.fine(
      'Compute MAC over eifd with TDES key Kmac as calculated in-Appendix '
      '5.2',
    );
    bacLog.fine('\tMifd: ${binToHexRep(mifd)}');
    // Construct APDU

    final cmdData = [...eifd, ...mifd];
    bacLog.fine('Construct command data for MUTUAL AUTHENTICATE');
    bacLog.fine('\tcmd_data: ${binToHexRep(cmdData)}');

    _rndIfd = rndIfd;
    this.kifd = kifd;

    return Uint8List.fromList(cmdData);
  }

  /// Calculate the session keys (KSenc, KSmac) and the SSC from the data
  /// received by the mutual authenticate command (upstream doc).
  ///
  /// A security fix over upstream: performs the ICAO 9303 P11 §4.3.1
  /// step-4 checks upstream's docstring claims but never does. Verify the
  /// response's retail MAC over `E.ICC` with the derived Kmac
  /// ([InvalidResponseChecksum] on mismatch) and compare the echoed RND.IFD
  /// against the sent value ([InvalidDataPassed] on mismatch). A response
  /// shorter than the 40-byte `E.ICC ‖ M.ICC` shape throws
  /// [InvalidDataPassed] (upstream slice-crashes; part of the same fix).
  /// The derivation slices below are verbatim.
  ({Uint8List ksenc, Uint8List ksmac, Uint8List ssc}) sessionKeys(
    List<int> data,
  ) {
    bacLog.fine(
      'Decrypt and verify received data and compare received RND.IFD with '
      'generated RND.IFD ${binToHexRep(ksmac)}',
    );

    if (data.length < 40) {
      throw InvalidDataPassed(
        'mutual-auth response is ${data.length} bytes, need 40 '
        '(E.ICC ‖ M.ICC)',
      );
    }

    // Verify M.ICC (the retail MAC over E.ICC with Kmac).
    final micc = data.sublist(32, 40);
    final ccb = desMAC(key: ksmac, msg: pad(data.sublist(0, 32), blockSize: 8));
    if (!_bytesEqual(micc, ccb)) {
      throw const InvalidResponseChecksum();
    }

    final response = tripleDESDecrypt(
      ksenc,
      data.sublist(0, 32),
      List.filled(8, 0),
    );

    // The decrypted response is RND.ICC ‖ RND.IFD ‖ K.ICC; the echoed
    // RND.IFD must be the one we sent (P11 §4.3.1 step 4).
    if (!_bytesEqual(response.sublist(8, 16), _rndIfd)) {
      throw const InvalidDataPassed('mutual-auth RND.IFD mismatch');
    }

    final responseKicc = response.sublist(16, 32);
    final kseed = xor(kifd, responseKicc);
    bacLog.fine('Calculate XOR of Kifd and Kicc');
    bacLog.fine('\tKseed: ${binToHexRep(kseed)}');

    const smskg = SecureMessagingSessionKeyGenerator();
    final ksEnc = smskg.deriveKey(keySeed: kseed, mode: SMSMode.encMode);
    final ksMac = smskg.deriveKey(keySeed: kseed, mode: SMSMode.macMode);

    bacLog.fine('Calculate Session Keys (KSenc and KSmac) using Appendix 5.1');
    bacLog.fine('\tKSenc: ${binToHexRep(ksEnc)}');
    bacLog.fine('\tKSmac: ${binToHexRep(ksMac)}');

    // SSC = rnd_icc[4:8] ‖ rnd_ifd[4:8] (9303-11 §9.8.6.3; App D.3 pins
    // it).
    final ssc = Uint8List.fromList([
      ..._suffix4(_rndIcc),
      ..._suffix4(_rndIfd),
    ]);
    bacLog.fine('Calculate Send Sequence Counter');
    bacLog.fine('\tSSC: ${binToHexRep(ssc)}');
    return (ksenc: ksEnc, ksmac: ksMac, ssc: ssc);
  }

  /// Swift `suffix(4)` semantics: the last four bytes, or everything when
  /// shorter (a sub-4-byte RND would crash a plain `sublist`; upstream's
  /// `suffix` doesn't, and the 8-byte `SecureMessaging` SSC guard catches
  /// the resulting short SSC typed).
  static List<int> _suffix4(List<int> bytes) =>
      bytes.length <= 4 ? bytes : bytes.sublist(bytes.length - 4);

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

/// MRZ-key composition helper (a Dart-only addition; no upstream
/// equivalent). Pads [documentNumber] to 9 with `<`, computes the three
/// ICAO 9303 Part 3 §4.9 check digits, returns the 24-char key string
/// `BACHandler`/`createPaceKey` consume.
///
/// All three inputs are opaque MRZ strings, not parsed values: the date
/// fields get no digit validation and no date parsing; Part 3 §4.8
/// completes an unknown date wholly or partly with `<` fillers, which are
/// legal input and count as 0 in the check digit (no `Date` objects at the
/// API boundary). Document numbers longer than 9 pass through
/// unpadded (P11 §9.7.3 requires the complete number: the TD1
/// concatenated-docnum case).
///
/// Composition-only: check digits are recomputed, which is correct when
/// composing from components (manual entry). A scanned MRZ's *printed*
/// check digits can legitimately differ (`id-Deviation-MRZ-WrongCheckDigit`,
/// Part 3 §7.3.4.3): the app's adapter must prefer digits as-read for
/// optically scanned MRZs.
String composeMrzKey({
  required String documentNumber,
  required String dateOfBirth,
  required String dateOfExpiry,
}) {
  final paddedDocNum = documentNumber.length < 9
      ? documentNumber.padRight(9, '<')
      : documentNumber;
  return '$paddedDocNum${mrzCheckDigit(paddedDocNum)}'
      '$dateOfBirth${mrzCheckDigit(dateOfBirth)}'
      '$dateOfExpiry${mrzCheckDigit(dateOfExpiry)}';
}

/// ICAO 9303 Part 3 §4.9 check digit over an MRZ field: `0-9` -> face
/// value, `A-Z` -> 10..35, `<` -> 0; weights 7/3/1 cycling; sum mod 10. Any
/// other character throws [InvalidDataPassed] (dart-only strictness: the
/// digit is undefined outside the MRZ character set).
int mrzCheckDigit(String field) {
  const weights = [7, 3, 1];
  var sum = 0;
  for (var i = 0; i < field.length; i++) {
    final c = field.codeUnitAt(i);
    final int value;
    if (c >= 0x30 && c <= 0x39) {
      value = c - 0x30; // '0'..'9'
    } else if (c >= 0x41 && c <= 0x5A) {
      value = c - 0x41 + 10; // 'A'..'Z'
    } else if (c == 0x3C) {
      value = 0; // '<'
    } else {
      throw InvalidDataPassed(
        'MRZ check digit undefined for character "${field[i]}"',
      );
    }
    sum += value * weights[i % 3];
  }
  return sum % 10;
}
