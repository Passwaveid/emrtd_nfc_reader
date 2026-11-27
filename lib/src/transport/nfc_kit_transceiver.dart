// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: replaces the CoreNFC `NFCISO7816Tag.sendCommand` transport in
//   Sources/NFCPassportReader/TagReader.swift @ 3bf5456 (2.3.2)

/// `flutter_nfc_kit` transceiver: THE ONLY FILE IN `lib/` ALLOWED TO IMPORT
/// FLUTTER OR PLUGIN APIS.
///
/// The exception mapping and the capability constants below are pinned to
/// `flutter_nfc_kit` 3.6.2: re-verify both against the plugin's platform
/// sources on every dependency upgrade, and against real devices. The poll
/// result's `maxTransceiveLength` / `isExtendedLengthApduSupported` fields
/// come from the vendored fork (`vendor/flutter_nfc_kit`) until upstream
/// ships them.
library;

import 'dart:typed_data';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import '../errors.dart';
import '../utils.dart';
import 'nfc_session.dart';
import 'transceiver.dart';

/// [NfcTransceiver] over `FlutterNfcKit.transceive`. The session (poll /
/// finish) is owned by [NfcSession], package `PassportReader` in the
/// default wiring; construct this once a tag is polled.
class NfcKitTransceiver implements NfcTransceiver {
  /// [timeout] is the per-command transceive timeout, an Android-only knob
  /// in `flutter_nfc_kit` (ignored on iOS, where the OS decides). Default
  /// **30 s**, not the plugin's 5 s: dmrtd's maintainer advises 30 s after
  /// mid-read session invalidations, and single Android transceives have
  /// been logged at 3.5 s.
  ///
  /// [maxTransceiveLength] / [isExtendedLengthApduSupported] default to the
  /// pessimistic constants: 261, the value AOSP reports when a vendor config
  /// sets no ISO-DEP cap, and no extended length, the 9303-10 §3.6.4 stance.
  /// [FlutterNfcKitNfcSession.poll] passes the plugin's real values instead.
  NfcKitTransceiver({
    this.timeout = const Duration(seconds: 30),
    this.maxTransceiveLength = 261,
    this.isExtendedLengthApduSupported = false,
    this.historicalBytes,
    this.tagCapabilities,
  });

  /// Per-command transceive timeout (Android-only, see constructor).
  final Duration timeout;

  @override
  final int maxTransceiveLength;

  @override
  final bool isExtendedLengthApduSupported;

  @override
  final Uint8List? historicalBytes;

  @override
  final TagCapabilities? tagCapabilities;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    try {
      return await FlutterNfcKit.transceive<Uint8List>(capdu, timeout: timeout);
    } on PlatformException catch (e) {
      throw mapNfcKitPlatformException(e);
    }
  }
}

/// Maps a `flutter_nfc_kit` [PlatformException] from `transceive` to the
/// [EmrtdException] hierarchy. Code-level contract with a unit test per row,
/// pinned to the 3.6.2 platform sources:
///
/// | code | plugin meaning (3.6.2) | mapped |
/// |---|---|---|
/// | `406` | "No tag polled" (both platforms) | [NoConnectedTag] |
/// | `503` | "Tag already removed" (Android `SecurityException`) | [ConnectionError] |
/// | `500` | "Communication error" (Android `IOException`, incl. `TagLostException`, which is also how an in-transceive **timeout** surfaces on Android; iOS CoreNFC send/session errors) | [ConnectionError] |
/// | `408` | session timeout (iOS `SessionTimeOut` resolving a pending transceive; Android poll timeout) | [TimeOutError] |
/// | `409` | iOS "SessionCanceled" resolving a pending transceive | [UserCanceled] |
/// | other (`400`, `405`, ...) | caller/plugin bugs, unsupported card | [UnknownError] wrapping the original |
///
/// Android cannot distinguish its transceive timeout from tag loss (both are
/// `TagLostException` -> code `500`), so the "timeout -> [TimeOutError]" row is
/// only reachable from iOS session expiry.
EmrtdException mapNfcKitPlatformException(PlatformException e) =>
    switch (e.code) {
      '406' => const NoConnectedTag(),
      '503' => const ConnectionError(),
      '500' => const ConnectionError(),
      '408' => const TimeOutError(),
      '409' => const UserCanceled(),
      _ => UnknownError(e),
    };

/// The production [NfcSession] over `flutter_nfc_kit`, in this file because
/// it is the only one in `lib/` allowed to import Flutter.
///
/// Construction is platform-call-free: plugin calls happen only at use time,
/// so `PassportReader` subclasses and fakes instantiate in VM tests without
/// a platform channel.
class FlutterNfcKitNfcSession implements NfcSession {
  @override
  Future<NfcAvailability> availability() async =>
      _mapAvailability(await FlutterNfcKit.nfcAvailability);

  @override
  Future<bool> isAvailable() async =>
      await availability() == NfcAvailability.available;

  /// Maps `flutter_nfc_kit`'s already-tri-state `NFCAvailability` to the
  /// package [NfcAvailability]. Pinned to 3.6.2.
  NfcAvailability _mapAvailability(NFCAvailability a) => switch (a) {
    NFCAvailability.available => NfcAvailability.available,
    NFCAvailability.disabled => NfcAvailability.disabled,
    NFCAvailability.not_supported => NfcAvailability.notSupported,
  };

  @override
  Future<NfcTransceiver> poll({
    required String iosAlertMessage,
    required Duration transceiveTimeout,
  }) async {
    final NFCTag tag;
    try {
      tag = await FlutterNfcKit.poll(iosAlertMessage: iosAlertMessage);
    } on PlatformException catch (e) {
      // Same code table as the transceive mapping above minus the rows a
      // poll cannot produce.
      throw switch (e.code) {
        '406' => const NoConnectedTag(),
        '408' => const TimeOutError(),
        '409' => const UserCanceled(),
        _ => const ConnectionError(),
      };
    }
    // The fork reports both caps for every ISO-DEP tag (Android from
    // `IsoDep`, iOS as CoreNFC's constants); a tag without them is not an
    // ISO-DEP tag at all, and keeps the pessimistic defaults.
    return NfcKitTransceiver(
      timeout: transceiveTimeout,
      maxTransceiveLength: tag.maxTransceiveLength ?? 261,
      isExtendedLengthApduSupported: tag.isExtendedLengthApduSupported ?? false,
      historicalBytes: _optionalHexField(tag.historicalBytes),
      tagCapabilities: TagCapabilities(
        type: tag.type.name,
        standard: tag.standard,
        atqa: _optionalHexField(tag.atqa),
        sak: _optionalHexField(tag.sak),
        protocolInfo: _optionalHexField(tag.protocolInfo),
        applicationData: _optionalHexField(tag.applicationData),
      ),
    );
  }

  /// The plugin's per-technology hex fields (historical bytes, ATQA, SAK,
  /// protocol info, application data) arrive as `""` on Android when the
  /// tag does not have them and are omitted on iOS; both mean "none".
  static Uint8List? _optionalHexField(String? hex) =>
      hex == null || hex.isEmpty ? null : hexRepToBin(hex);

  @override
  Future<void> setAlertMessage(String message) =>
      FlutterNfcKit.setIosAlertMessage(message);

  @override
  Future<void> finish({String? iosAlertMessage, String? iosErrorMessage}) =>
      FlutterNfcKit.finish(
        iosAlertMessage: iosAlertMessage,
        iosErrorMessage: iosErrorMessage,
      );
}
