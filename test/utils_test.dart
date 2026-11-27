/// Unit tests for the utils helpers not covered by conformance vectors
/// (`binToHex`/`binToHexRepByte` are below vector granularity).
library;

import 'package:emrtd_core/src/utils.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('binToHex is identity on 0..255 (call-site parity shim)', () {
    for (final v in [0, 1, 0x7F, 0x80, 0xFF]) {
      expect(binToHex(v), v);
    }
  });

  test('binToHexRepByte formats one byte uppercase', () {
    expect(binToHexRepByte(0x00), '00');
    expect(binToHexRepByte(0x0A), '0A');
    expect(binToHexRepByte(0xFF), 'FF');
  });

  test('binToHexBytes and binToInt agree (same upstream parse)', () {
    expect(binToHexBytes([0xDE, 0xAD]), binToInt([0xDE, 0xAD]));
  });
}
