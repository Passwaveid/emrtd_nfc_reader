// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Utils.swift @ 3bf5456 (2.3.2)
//   (generateRandomUInt8Array: reworked into the injectable RNG seam)

/// Injectable RNG seam. Upstream's `generateRandomUInt8Array` (`arc4random`)
/// is deliberately *not* ported as a bare function: every randomness
/// consumer takes an [EmrtdRandom] so deterministic transcript replay can
/// inject [FixedRandom].
///
/// BAC consumes 8 (RND.IFD) + 16 (K.IFD) bytes per session. PACE ephemeral
/// EC/DH private keys additionally flow through
/// `ecGenerateKeyPair`/`dhGenerateKeyPair` on the live path, but deterministic
/// tests inject the private scalars directly via the PACE handler's seam.
library;

import 'dart:math';
import 'dart:typed_data';

/// Randomness seam. Implementations return exactly [nextBytes]`(length)`
/// bytes.
abstract class EmrtdRandom {
  Uint8List nextBytes(int length);
}

/// Live-path RNG backed by [Random.secure], the only permitted `dart:math`
/// [Random] use in `lib/`.
class SystemRandom implements EmrtdRandom {
  SystemRandom();

  final Random _random = Random.secure();

  @override
  Uint8List nextBytes(int length) {
    final out = Uint8List(length);
    for (var i = 0; i < length; i++) {
      out[i] = _random.nextInt(256);
    }
    return out;
  }
}

/// Canned RNG for deterministic replay. Bytes are consumed front-to-back;
/// exhaustion **throws** rather than wrapping around: a transcript that
/// consumes more randomness than recorded is a parity failure, not a
/// wrap-around.
class FixedRandom implements EmrtdRandom {
  FixedRandom(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int _offset = 0;

  /// Bytes not yet consumed.
  int get remaining => _bytes.length - _offset;

  @override
  Uint8List nextBytes(int length) {
    if (length > remaining) {
      throw StateError(
        'FixedRandom exhausted: $length bytes requested, $remaining '
        'remaining (replay consumed more randomness than '
        'recorded)',
      );
    }
    final out = Uint8List.sublistView(_bytes, _offset, _offset + length);
    _offset += length;
    return Uint8List.fromList(out);
  }
}
