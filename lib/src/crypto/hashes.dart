// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Utils.swift @ 3bf5456 (2.3.2)

/// SHA family from upstream `Utils.swift` (`calcHash` +
/// `calcSHA1/224/256/384/512Hash`), over `package:crypto`.
///
/// `calcHash` lowercases the algorithm name and dispatches on the exact
/// strings `sha1`/`sha224`/`sha256`/`sha384`/`sha512`: dashed forms like
/// `"SHA-256"` are rejected, as upstream rejects them
/// ([InvalidHashAlgorithmSpecified]).
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../errors.dart';

/// Swift `calcHash(data:hashAlgorithm:)`.
Uint8List calcHash(List<int> data, String hashAlgorithm) {
  switch (hashAlgorithm.toLowerCase()) {
    case 'sha1':
      return calcSHA1Hash(data);
    case 'sha224':
      return calcSHA224Hash(data);
    case 'sha256':
      return calcSHA256Hash(data);
    case 'sha384':
      return calcSHA384Hash(data);
    case 'sha512':
      return calcSHA512Hash(data);
    default:
      throw const InvalidHashAlgorithmSpecified();
  }
}

/// Swift `calcSHA1Hash`.
Uint8List calcSHA1Hash(List<int> data) =>
    Uint8List.fromList(sha1.convert(data).bytes);

/// Swift `calcSHA224Hash`.
Uint8List calcSHA224Hash(List<int> data) =>
    Uint8List.fromList(sha224.convert(data).bytes);

/// Swift `calcSHA256Hash`.
Uint8List calcSHA256Hash(List<int> data) =>
    Uint8List.fromList(sha256.convert(data).bytes);

/// Swift `calcSHA384Hash`.
Uint8List calcSHA384Hash(List<int> data) =>
    Uint8List.fromList(sha384.convert(data).bytes);

/// Swift `calcSHA512Hash`.
Uint8List calcSHA512Hash(List<int> data) =>
    Uint8List.fromList(sha512.convert(data).bytes);
