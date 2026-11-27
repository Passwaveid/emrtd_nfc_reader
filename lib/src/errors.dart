// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Errors.swift @ 3bf5456 (2.3.2)

/// Sealed exception hierarchy mirroring upstream's `NFCPassportReaderError`:
/// one final subclass per ported case.
///
/// [EmrtdException.code] is the upstream case name **verbatim**: the stable
/// string used by telemetry and by conformance vectors' `expect.error` field.
/// [EmrtdException.message] mirrors upstream's `.value`.
///
/// Dropped cases: `DataGroupNotRead`, `NotImplemented` (defined upstream,
/// never thrown). The `OpenSSLError` and `PassiveAuthenticationError` enums
/// are dropped wholesale; the surviving call sites map into this hierarchy.
library;

import 'lds/data_group_id.dart';

/// Base of the ported error hierarchy. Match exhaustively via Dart 3
/// `switch`, or on [code] for upstream-parity telemetry.
sealed class EmrtdException implements Exception {
  const EmrtdException();

  /// Upstream `NFCPassportReaderError` case name, verbatim. Stable.
  String get code;

  /// Mirrors upstream's `.value` string for the case.
  String get message;

  @override
  String toString() => 'EmrtdException($code): $message';
}

/// Cases whose upstream `.value` is just the case name.
abstract final class _SimpleCase extends EmrtdException {
  const _SimpleCase();

  @override
  String get message => code;
}

/// Upstream `%02X`-style hex used by [InvalidResponse]'s message
/// (`Int.hexString` in `Utils.swift`).
String _hexString(int val) =>
    val.toRadixString(16).toUpperCase().padLeft(2, '0');

final class ResponseError extends EmrtdException {
  const ResponseError(this.reason, this.sw1, this.sw2);

  final String reason;
  final int sw1;
  final int sw2;

  @override
  String get code => 'ResponseError';

  @override
  String get message => reason;
}

final class InvalidResponse extends EmrtdException {
  const InvalidResponse(this.dataGroupId, this.expectedTag, this.actualTag);

  final DataGroupId dataGroupId;
  final int expectedTag;
  final int actualTag;

  @override
  String get code => 'InvalidResponse';

  @override
  String get message =>
      'InvalidResponse in ${dataGroupId.getName()}. '
      'Expected: ${_hexString(expectedTag)} Actual: ${_hexString(actualTag)}';
}

final class UnexpectedError extends _SimpleCase {
  const UnexpectedError();

  @override
  String get code => 'UnexpectedError';
}

final class NFCNotSupported extends _SimpleCase {
  const NFCNotSupported();

  @override
  String get code => 'NFCNotSupported';
}

final class NoConnectedTag extends _SimpleCase {
  const NoConnectedTag();

  @override
  String get code => 'NoConnectedTag';
}

final class D087Malformed extends _SimpleCase {
  const D087Malformed();

  @override
  String get code => 'D087Malformed';
}

final class InvalidResponseChecksum extends _SimpleCase {
  const InvalidResponseChecksum();

  @override
  String get code => 'InvalidResponseChecksum';
}

final class MissingMandatoryFields extends _SimpleCase {
  const MissingMandatoryFields();

  @override
  String get code => 'MissingMandatoryFields';
}

final class CannotDecodeASN1Length extends _SimpleCase {
  const CannotDecodeASN1Length();

  @override
  String get code => 'CannotDecodeASN1Length';
}

final class InvalidASN1Value extends _SimpleCase {
  const InvalidASN1Value();

  @override
  String get code => 'InvalidASN1Value';
}

final class UnableToProtectAPDU extends _SimpleCase {
  const UnableToProtectAPDU();

  @override
  String get code => 'UnableToProtectAPDU';
}

final class UnableToUnprotectAPDU extends _SimpleCase {
  const UnableToUnprotectAPDU();

  @override
  String get code => 'UnableToUnprotectAPDU';
}

final class UnsupportedDataGroup extends _SimpleCase {
  const UnsupportedDataGroup();

  @override
  String get code => 'UnsupportedDataGroup';
}

final class UnknownTag extends _SimpleCase {
  const UnknownTag();

  @override
  String get code => 'UnknownTag';
}

final class UnknownImageFormat extends _SimpleCase {
  const UnknownImageFormat();

  @override
  String get code => 'UnknownImageFormat';
}

final class TagNotValid extends _SimpleCase {
  const TagNotValid();

  @override
  String get code => 'TagNotValid';
}

final class ConnectionError extends _SimpleCase {
  const ConnectionError();

  @override
  String get code => 'ConnectionError';
}

final class TimeOutError extends _SimpleCase {
  const TimeOutError();

  @override
  String get code => 'TimeOutError';
}

final class UserCanceled extends _SimpleCase {
  const UserCanceled();

  @override
  String get code => 'UserCanceled';
}

final class InvalidMRZKey extends _SimpleCase {
  const InvalidMRZKey();

  @override
  String get code => 'InvalidMRZKey';
}

final class MoreThanOneTagFound extends _SimpleCase {
  const MoreThanOneTagFound();

  @override
  String get code => 'MoreThanOneTagFound';
}

/// Upstream `ChipAuthenticationFailed`: thrown when every
/// `ChipAuthenticationPublicKeyInfo` in DG14 failed its handshake.
final class ChipAuthenticationFailed extends _SimpleCase {
  const ChipAuthenticationFailed();

  @override
  String get code => 'ChipAuthenticationFailed';
}

final class InvalidHashAlgorithmSpecified extends _SimpleCase {
  const InvalidHashAlgorithmSpecified();

  @override
  String get code => 'InvalidHashAlgorithmSpecified';
}

final class UnsupportedCipherAlgorithm extends _SimpleCase {
  const UnsupportedCipherAlgorithm();

  @override
  String get code => 'UnsupportedCipherAlgorithm';
}

final class UnsupportedMappingType extends _SimpleCase {
  const UnsupportedMappingType();

  @override
  String get code => 'UnsupportedMappingType';
}

final class PACEError extends EmrtdException {
  const PACEError(this.step, this.reason);

  final String step;
  final String reason;

  @override
  String get code => 'PACEError';

  @override
  String get message => 'PACEError ($step) - $reason';
}

final class InvalidDataPassed extends EmrtdException {
  const InvalidDataPassed(this.reason);

  final String reason;

  @override
  String get code => 'InvalidDataPassed';

  @override
  String get message => 'Invalid data passed - $reason';
}

final class NotYetSupported extends EmrtdException {
  const NotYetSupported(this.reason);

  final String reason;

  @override
  String get code => 'NotYetSupported';

  @override
  String get message => 'Not yet supported - $reason';
}

/// Upstream case `Unknown(Error)`. The Dart class name deviates (a bare
/// `Unknown` is unusably generic); [code] stays `"Unknown"`.
final class UnknownError extends EmrtdException {
  const UnknownError(this.cause);

  final Object cause;

  @override
  String get code => 'Unknown';

  @override
  String get message => 'Unknown error: $cause';
}
