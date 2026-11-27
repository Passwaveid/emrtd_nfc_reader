/// Unit tests for the EmrtdException hierarchy: stable codes
/// (upstream case names, verbatim) and `.value`-parity messages.
library;

import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('payload-less cases: code and message are the upstream case name', () {
    const cases = <EmrtdException>[
      UnexpectedError(),
      NFCNotSupported(),
      NoConnectedTag(),
      D087Malformed(),
      InvalidResponseChecksum(),
      MissingMandatoryFields(),
      CannotDecodeASN1Length(),
      InvalidASN1Value(),
      UnableToProtectAPDU(),
      UnableToUnprotectAPDU(),
      UnsupportedDataGroup(),
      UnknownTag(),
      UnknownImageFormat(),
      TagNotValid(),
      ConnectionError(),
      TimeOutError(),
      UserCanceled(),
      InvalidMRZKey(),
      MoreThanOneTagFound(),
      ChipAuthenticationFailed(),
      InvalidHashAlgorithmSpecified(),
      UnsupportedCipherAlgorithm(),
      UnsupportedMappingType(),
    ];
    for (final e in cases) {
      // The class name IS the upstream case name for these.
      expect(e.code, e.runtimeType.toString());
      expect(e.message, e.code);
    }
  });

  test('ResponseError carries reason and status words', () {
    const e = ResponseError('sw1 - 0x6A, sw2 - 0x82', 0x6A, 0x82);
    expect(e.code, 'ResponseError');
    expect(e.message, 'sw1 - 0x6A, sw2 - 0x82');
    expect(e.sw1, 0x6A);
    expect(e.sw2, 0x82);
  });

  test('InvalidResponse formats like upstream .value', () {
    const e = InvalidResponse(DataGroupId.DG1, 0x61, 0x7F);
    expect(e.code, 'InvalidResponse');
    expect(e.message, 'InvalidResponse in DG1. Expected: 61 Actual: 7F');
  });

  test('InvalidResponse pads single-digit tags like %02X', () {
    const e = InvalidResponse(DataGroupId.COM, 0x0E, 0x01);
    expect(e.message, 'InvalidResponse in COM. Expected: 0E Actual: 01');
  });

  test('PACEError formats like upstream .value', () {
    const e = PACEError('Step2 KA', 'Failed to map nonce');
    expect(e.code, 'PACEError');
    expect(e.message, 'PACEError (Step2 KA) - Failed to map nonce');
  });

  test('InvalidDataPassed formats like upstream .value', () {
    const e = InvalidDataPassed('Wrong length');
    expect(e.code, 'InvalidDataPassed');
    expect(e.message, 'Invalid data passed - Wrong length');
  });

  test('NotYetSupported formats like upstream .value', () {
    const e = NotYetSupported('DH keys');
    expect(e.code, 'NotYetSupported');
    expect(e.message, 'Not yet supported - DH keys');
  });

  test('UnknownError class deviates but code stays "Unknown"', () {
    final e = UnknownError(const FormatException('bad'));
    expect(e.code, 'Unknown');
    expect(e.message, 'Unknown error: FormatException: bad');
  });

  test('toString carries code and message', () {
    expect(
      const NoConnectedTag().toString(),
      'EmrtdException(NoConnectedTag): NoConnectedTag',
    );
  });

  test('hierarchy is catchable as EmrtdException', () {
    expect(
      () => throw const InvalidASN1Value(),
      throwsA(isA<EmrtdException>()),
    );
  });
}
