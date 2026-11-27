// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Utils.swift @ 3bf5456 (2.3.2)
//   (mac/desMAC/aesMAC; aesMAC's body = OpenSSLUtils.generateAESCMAC,
//    OpenSSLUtils.swift lines 553-574)

/// MACs from upstream `Utils.swift`: the ISO/IEC 9797-1 Algorithm 3 "retail
/// MAC" ([desMAC]), AES-CMAC ([aesMAC]), and the [mac] dispatcher with its
/// [SecureMessagingSupportedAlgorithms] enum (defined upstream in
/// `SecureMessaging.swift`; moved here, beside the MACs it selects).
///
/// **Vendored CMAC:** pointycastle's `CMac` builds its zero IV at *key* length
/// instead of block length, maintainer-confirmed at
/// [bcgit/pc-dart#200](https://github.com/bcgit/pc-dart/issues/200), still
/// unfixed in the pinned 4.0.0 (re-verified 2026-07-17), which breaks
/// AES-192/256 CMAC outright. [aesMAC] therefore runs a minimal local
/// SP 800-38B implementation over pointycastle's `AESEngine`; the
/// `cipher.json` RFC 4493 / SP 800-38B vectors (128/192/256) gate it.
///
/// Deviations: [desMAC] throws on non-8-aligned input where upstream silently
/// drops the trailing partial block (unreachable upstream, every call site
/// pads first); [aesMAC] throws on key sizes other than 16/24/32 where
/// upstream MACs with an *uninitialized* CMAC context.
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';

import '../errors.dart';
import '../logging.dart';
import '../utils.dart';
import 'ciphers.dart';

/// Upstream `SecureMessagingSupportedAlgorithms` (SecureMessaging.swift):
/// cases `DES`/`AES`.
enum SecureMessagingSupportedAlgorithms { des, aes }

/// Swift `mac(algoName:key:msg:)`: dispatches to [desMAC] or [aesMAC].
Uint8List mac({
  required SecureMessagingSupportedAlgorithms algoName,
  required List<int> key,
  required List<int> msg,
}) {
  if (algoName == SecureMessagingSupportedAlgorithms.des) {
    return desMAC(key: key, msg: msg);
  } else {
    return aesMAC(key: key, msg: msg);
  }
}

/// Swift `desMAC(key:msg:)`, ISO/IEC 9797-1 MAC Algorithm 3 ("retail MAC"):
/// single-DES CBC over 8-byte blocks with key bytes 0..8, then
/// D(key[8..16]) + E(key[0..8]) in ECB on the final block.
///
/// [msg] must be pre-padded by the caller to a multiple of 8 (the port throws
/// where upstream floors `msg.count / 8` and silently drops a trailing partial
/// block). Only the first 16 bytes of [key] are used: a 24-byte 3DES KSmac MACs
/// identically to its first 16 bytes.
Uint8List desMAC({required List<int> key, required List<int> msg}) {
  if (key.length < 16) {
    throw InvalidDataPassed(
      'desMAC: key must be at least 16 bytes, got ${key.length}',
    );
  }
  if (msg.length % 8 != 0) {
    throw InvalidDataPassed(
      'desMAC: msg length ${msg.length} is not a multiple of 8; caller '
      'must pad first',
    );
  }

  final size = msg.length ~/ 8;
  var y = Uint8List(8);

  passportReaderLog.fine('Calc mac');
  for (var i = 0; i < size; i++) {
    final tmp = msg.sublist(i * 8, i * 8 + 8);
    passportReaderLog.fine('x$i: ${binToHexRep(tmp)}');
    y = desEncrypt(key.sublist(0, 8), tmp, y);
    passportReaderLog.fine('y$i: ${binToHexRep(y)}');
  }

  passportReaderLog.fine('y: ${binToHexRep(y)}');
  passportReaderLog.fine('bkey: ${binToHexRep(key.sublist(8, 16))}');
  passportReaderLog.fine('akey: ${binToHexRep(key.sublist(0, 8))}');
  final b = desDecrypt(key.sublist(8, 16), y, ecb: true);
  passportReaderLog.fine('b: ${binToHexRep(b)}');
  final a = desEncrypt(key.sublist(0, 8), b, const [], ecb: true);
  passportReaderLog.fine('a: ${binToHexRep(a)}');

  return a;
}

/// Swift `aesMAC(key:msg:)` -> `OpenSSLUtils.generateAESCMAC`: AES-CMAC
/// (SP 800-38B); key length 16/24/32 selects AES-128/192/256. Returns the
/// **full 16-byte** MAC: truncation to 8 bytes is the call sites' job.
/// Upstream's `aesMac - mac - ...` debug line logged under the dropped
/// `openSSL` category is not ported.
Uint8List aesMAC({required List<int> key, required List<int> msg}) {
  if (key.length != 16 && key.length != 24 && key.length != 32) {
    throw InvalidDataPassed(
      'aesMAC: AES-CMAC key must be 16, 24 or 32 bytes, '
      'got ${key.length}',
    );
  }
  return _aesCmac(Uint8List.fromList(key), msg);
}

// --- vendored SP 800-38B CMAC over AESEngine (see library doc) --------------

/// GF(2^128) doubling: left-shift by one bit, XOR 0x87 into the last byte if
/// the shifted-out MSB was set (SP 800-38B §6.1, Rb for b = 128).
Uint8List _dbl(Uint8List block) {
  final out = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    out[i] = (block[i] << 1) & 0xFF;
    if (i < 15 && (block[i + 1] & 0x80) != 0) {
      out[i] |= 0x01;
    }
  }
  if ((block[0] & 0x80) != 0) {
    out[15] ^= 0x87;
  }
  return out;
}

Uint8List _aesCmac(Uint8List key, List<int> message) {
  final cipher = AESEngine()..init(true, KeyParameter(key));

  // Subkeys: L = CIPH_K(0^128); K1 = dbl(L); K2 = dbl(K1).
  final l = Uint8List(16);
  cipher.processBlock(Uint8List(16), 0, l, 0);
  final k1 = _dbl(l);
  final k2 = _dbl(k1);

  // Block count; an empty message is treated as one (padded) block.
  final n = message.isEmpty ? 1 : (message.length + 15) ~/ 16;
  final lastComplete = message.isNotEmpty && message.length % 16 == 0;

  // Last block: XOR K1 if complete, else pad 10* and XOR K2.
  final last = Uint8List(16);
  final lastStart = (n - 1) * 16;
  final lastLen = message.length - lastStart;
  last.setRange(0, lastLen, message, lastStart);
  if (!lastComplete) {
    last[lastLen] = 0x80;
  }
  final subkey = lastComplete ? k1 : k2;
  for (var i = 0; i < 16; i++) {
    last[i] ^= subkey[i];
  }

  // CBC-MAC chain.
  final x = Uint8List(16);
  final buf = Uint8List(16);
  for (var b = 0; b < n - 1; b++) {
    for (var i = 0; i < 16; i++) {
      buf[i] = x[i] ^ message[b * 16 + i];
    }
    cipher.processBlock(buf, 0, x, 0);
  }
  for (var i = 0; i < 16; i++) {
    buf[i] = x[i] ^ last[i];
  }
  final out = Uint8List(16);
  cipher.processBlock(buf, 0, out, 0);
  return out;
}
