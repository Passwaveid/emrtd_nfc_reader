// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/SecureMessagingSessionKeyGenerator.swift @ 3bf5456 (2.3.2)

/// TR-SAC 1.01 §4.2 key derivation, ported with signature parity and quirks
/// intact: digest(keySeed ‖ nonce? ‖ 00 00 00 ‖ mode), then the cipher-specific
/// key cut.
///
/// Quirks preserved:
/// - [SecureMessagingSessionKeyGenerator.deriveKey]'s `paceKeyReference`
///   parameter is accepted and **completely unused**.
/// - `keyLength` 112 and 128 are two labels for the same two-key 3DES
///   derivation (ICAO 9303 P11 §9.7.1.1: "128-bit (112-bit excluding parity
///   bits)"); upstream's `PACEInfo.toKeyLength` only ever reports 128, so the
///   112 branch is reachable only synthetically.
/// - Digest inference runs *first* and is exact-match case-sensitive over
///   {`DESede`, `AES`, `AES-128`, `AES-192`, `AES-256`}, so the key-cut
///   branch's `"3DES"` alias and lowercased `"aes"` prefix tolerance are dead
///   code upstream, mirrored anyway for diffability.
/// - Error messages mirrored verbatim, typos included ("128-but"); codes are
///   what conformance asserts, messages are for log-diffing.
///
/// The `nonce` parameter is TR-03110-3 A.2.3's optional `r` (CA-v2-only,
/// out of scope); every in-scope call site passes null, so nonce-present
/// vectors are synthetic.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../errors.dart';

/// Upstream `SecureMessagingSessionKeyGenerator.SMSMode`.
enum SMSMode {
  encMode(0x1),
  macMode(0x2),
  paceMode(0x3);

  const SMSMode(this.value);

  /// Upstream raw value: the final byte of the KDF counter `c`.
  final int value;
}

/// Upstream `SecureMessagingSessionKeyGenerator` (internal class; drivable on
/// the Swift side via the fork's `@testable` conformance target).
class SecureMessagingSessionKeyGenerator {
  const SecureMessagingSessionKeyGenerator();

  /// Upstream `NO_PACE_KEY_REFERENCE`.
  static const int noPaceKeyReference = 0x00;

  /// Swift `deriveKey(keySeed:cipherAlgName:keyLength:nonce:mode:paceKeyReference:)`:
  /// the four upstream overloads collapse into one method with defaults
  /// matching the overload chain (`DESede`, 128, no nonce).
  ///
  /// [paceKeyReference] is dead: accepted, never used in the derivation;
  /// kept for parity (a PACE call site passes it).
  ///
  /// Throws [InvalidDataPassed] on unsupported algorithm/length combinations.
  Uint8List deriveKey({
    required List<int> keySeed,
    String cipherAlgName = 'DESede',
    int keyLength = 128,
    List<int>? nonce,
    required SMSMode mode,
    int paceKeyReference = noPaceKeyReference,
  }) {
    final digestAlgo = inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(
      cipherAlg: cipherAlgName,
      keyLength: keyLength,
    );

    final modeArr = [0x00, 0x00, 0x00, mode.value];
    final dataEls = [keySeed, if (nonce != null) nonce, modeArr];
    final hashResult = getHash(algo: digestAlgo, dataElements: dataEls);

    List<int> keyBytes;
    if (cipherAlgName == 'DESede' || cipherAlgName == '3DES') {
      // TR-SAC 1.01, 4.2.1.
      switch (keyLength) {
        case 112 || 128:
          // E (octets 1..8), D (octets 9..16), E again: 112-bit 3DES key.
          keyBytes = [
            ...hashResult.sublist(0, 16),
            ...hashResult.sublist(0, 8),
          ];
        default:
          throw const InvalidDataPassed(
            'Can only use DESede with 128-but key length',
          );
      }
    } else if (cipherAlgName.toLowerCase() == 'aes' ||
        cipherAlgName.toLowerCase().startsWith('aes')) {
      // TR-SAC 1.01, 4.2.2.
      switch (keyLength) {
        case 128:
          keyBytes = hashResult.sublist(0, 16);
        case 192:
          keyBytes = hashResult.sublist(0, 24);
        case 256:
          keyBytes = hashResult.sublist(0, 32);
        default:
          throw const InvalidDataPassed(
            'Can only use AES with 128-bit, 192-bit key or 256-bit length',
          );
      }
    } else {
      throw const InvalidDataPassed('Unsupported cipher algorithm used');
    }

    return Uint8List.fromList(keyBytes);
  }

  /// Swift `inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation`:
  /// exact-match, case-sensitive (see library doc).
  String inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation({
    required String cipherAlg,
    required int keyLength,
  }) {
    if (cipherAlg == 'DESede' || cipherAlg == 'AES-128') {
      return 'SHA1';
    }
    if (cipherAlg == 'AES' && keyLength == 128) {
      return 'SHA1';
    }
    if (cipherAlg == 'AES-256' || cipherAlg == 'AES-192') {
      return 'SHA256';
    }
    if (cipherAlg == 'AES' && (keyLength == 192 || keyLength == 256)) {
      return 'SHA256';
    }

    throw const InvalidDataPassed('Unsupported cipher algorithm or key length');
  }

  /// Swift `getHash(algo:dataElements:)`: digest over the concatenation of
  /// [dataElements]. Lowercases [algo]; upstream's KDF-side hash switch
  /// supports sha1/sha256/sha384/sha512 (no sha224, unlike `calcHash`).
  Uint8List getHash({
    required String algo,
    required List<List<int>> dataElements,
  }) {
    final data = [for (final d in dataElements) ...d];
    switch (algo.toLowerCase()) {
      case 'sha1':
        return Uint8List.fromList(sha1.convert(data).bytes);
      case 'sha256':
        return Uint8List.fromList(sha256.convert(data).bytes);
      case 'sha384':
        return Uint8List.fromList(sha384.convert(data).bytes);
      case 'sha512':
        return Uint8List.fromList(sha512.convert(data).bytes);
      default:
        throw const InvalidHashAlgorithmSpecified();
    }
  }
}
