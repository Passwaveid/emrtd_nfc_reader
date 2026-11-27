// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/AES_3DES_DESEncryption.swift @ 3bf5456 (2.3.2)

/// Block ciphers from upstream `AES_3DES_DESEncryption.swift`, over
/// pointycastle engines. No padding anywhere: callers pad (ISO 9797-1
/// method 2 via `pad`).
///
/// Deviation: upstream returns `[]` on every CommonCrypto error and no caller
/// checks; the port throws [InvalidDataPassed] on bad key/IV sizes and
/// non-block-aligned input. Success paths are byte-identical (pinned by
/// `cipher.json`).
///
/// Quirks: `AESDecrypt`'s 16-to-24-byte key extension is dead code upstream
/// (`keyLength` stays 16, so CommonCrypto never reads the extension), ported
/// as plain AES-CBC. `DESDecrypt` ignores its `iv` parameter; the port drops
/// the parameter entirely.
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/desede_engine.dart';
import 'package:pointycastle/block/modes/cbc.dart';
import 'package:pointycastle/block/modes/ecb.dart';

import '../errors.dart';

/// Runs [cipher] over the whole (block-aligned) [message].
Uint8List _processBlocks(
  BlockCipher cipher,
  List<int> message,
  int blockSize,
  String stage,
) {
  if (message.length % blockSize != 0) {
    throw InvalidDataPassed(
      '$stage: message length ${message.length} is not a multiple of the '
      '$blockSize-byte block size',
    );
  }
  final data = Uint8List.fromList(message);
  final out = Uint8List(data.length);
  for (var off = 0; off < data.length; off += blockSize) {
    cipher.processBlock(data, off, out, off);
  }
  return out;
}

Uint8List _aesKey(List<int> key, String stage) {
  if (key.length != 16 && key.length != 24 && key.length != 32) {
    throw InvalidDataPassed(
      '$stage: AES key must be 16, 24 or 32 bytes, '
      'got ${key.length}',
    );
  }
  return Uint8List.fromList(key);
}

/// Upstream `tripleDESEncrypt`/`tripleDESDecrypt` key fix-up: a 16-byte 2-key
/// EDE key K1‖K2 extends to K1‖K2‖K1; 24-byte keys pass through.
Uint8List _tdesKey(List<int> key, String stage) {
  if (key.length == 16) {
    return Uint8List.fromList([...key, ...key.sublist(0, 8)]);
  }
  if (key.length == 24) {
    return Uint8List.fromList(key);
  }
  throw InvalidDataPassed(
    '$stage: 3DES key must be 16 or 24 bytes, got ${key.length}',
  );
}

/// Single DES via `DESedeEngine` with K‖K‖K (pointycastle registers no
/// standalone DES engine; EDE with K1=K2=K3 collapses to single DES).
Uint8List _desKey(List<int> key, String stage) {
  if (key.length != 8) {
    throw InvalidDataPassed(
      '$stage: DES key must be 8 bytes, got ${key.length}',
    );
  }
  return Uint8List.fromList([...key, ...key, ...key]);
}

Uint8List _iv(List<int> iv, int blockSize, String stage) {
  if (iv.length != blockSize) {
    throw InvalidDataPassed(
      '$stage: IV must be $blockSize bytes, got ${iv.length}',
    );
  }
  return Uint8List.fromList(iv);
}

/// Swift `AESEncrypt(key:message:iv:)`: AES-CBC, no padding. Key length
/// (16/24/32) selects AES-128/192/256.
Uint8List aesEncrypt(List<int> key, List<int> message, List<int> iv) {
  final cipher = CBCBlockCipher(AESEngine())
    ..init(
      true,
      ParametersWithIV(
        KeyParameter(_aesKey(key, 'AESEncrypt')),
        _iv(iv, 16, 'AESEncrypt'),
      ),
    );
  return _processBlocks(cipher, message, 16, 'AESEncrypt');
}

/// Swift `AESDecrypt(key:message:iv:)`: AES-CBC, no padding. The upstream
/// 16-to-24-byte `fixedKey` extension is dead code (see library doc); plain
/// AES-CBC.
Uint8List aesDecrypt(List<int> key, List<int> message, List<int> iv) {
  final cipher = CBCBlockCipher(AESEngine())
    ..init(
      false,
      ParametersWithIV(
        KeyParameter(_aesKey(key, 'AESDecrypt')),
        _iv(iv, 16, 'AESDecrypt'),
      ),
    );
  return _processBlocks(cipher, message, 16, 'AESDecrypt');
}

/// Swift `AESECBEncrypt(key:message:)`: AES-ECB, no padding (used for the
/// AES-SM IV = E(KSenc, SSC)).
Uint8List aesECBEncrypt(List<int> key, List<int> message) {
  final cipher = ECBBlockCipher(AESEngine())
    ..init(true, KeyParameter(_aesKey(key, 'AESECBEncrypt')));
  return _processBlocks(cipher, message, 16, 'AESECBEncrypt');
}

/// Swift `tripleDESEncrypt(key:message:iv:)`: 3DES-CBC, no padding, 16-byte
/// keys extended K1‖K2‖K1.
Uint8List tripleDESEncrypt(List<int> key, List<int> message, List<int> iv) {
  final cipher = CBCBlockCipher(DESedeEngine())
    ..init(
      true,
      ParametersWithIV(
        KeyParameter(_tdesKey(key, 'tripleDESEncrypt')),
        _iv(iv, 8, 'tripleDESEncrypt'),
      ),
    );
  return _processBlocks(cipher, message, 8, 'tripleDESEncrypt');
}

/// Swift `tripleDESDecrypt(key:message:iv:)`.
Uint8List tripleDESDecrypt(List<int> key, List<int> message, List<int> iv) {
  final cipher = CBCBlockCipher(DESedeEngine())
    ..init(
      false,
      ParametersWithIV(
        KeyParameter(_tdesKey(key, 'tripleDESDecrypt')),
        _iv(iv, 8, 'tripleDESDecrypt'),
      ),
    );
  return _processBlocks(cipher, message, 8, 'tripleDESDecrypt');
}

/// Swift `DESEncrypt(key:message:iv:options:)`: single DES, CBC by default,
/// ECB when [ecb] (upstream's `kCCOptionECBMode` options flag). The IV is
/// ignored in ECB mode, as CommonCrypto ignores it.
Uint8List desEncrypt(
  List<int> key,
  List<int> message,
  List<int> iv, {
  bool ecb = false,
}) {
  final keyParam = KeyParameter(_desKey(key, 'DESEncrypt'));
  final BlockCipher cipher;
  if (ecb) {
    cipher = ECBBlockCipher(DESedeEngine())..init(true, keyParam);
  } else {
    cipher = CBCBlockCipher(DESedeEngine())
      ..init(true, ParametersWithIV(keyParam, _iv(iv, 8, 'DESEncrypt')));
  }
  return _processBlocks(cipher, message, 8, 'DESEncrypt');
}

/// Swift `DESDecrypt(key:message:iv:options:)`. No IV parameter: upstream
/// passes `nil` to CCCrypt whatever the caller supplies (preserved: no
/// caller may "fix" a DES-CBC-with-IV decrypt into existence). CBC mode
/// therefore runs with the zero IV, which is CCCrypt's nil-IV semantic; ECB
/// ([ecb]) matches upstream's only live call site (`desMAC`).
Uint8List desDecrypt(List<int> key, List<int> message, {bool ecb = false}) {
  final keyParam = KeyParameter(_desKey(key, 'DESDecrypt'));
  final BlockCipher cipher;
  if (ecb) {
    cipher = ECBBlockCipher(DESedeEngine())..init(false, keyParam);
  } else {
    cipher = CBCBlockCipher(DESedeEngine())
      ..init(false, ParametersWithIV(keyParam, Uint8List(8)));
  }
  return _processBlocks(cipher, message, 8, 'DESDecrypt');
}
