/// NFC session seam: the package's orchestration entry point,
/// `PassportReader`, owns the session lifecycle (poll, iOS alert messages,
/// exactly-one-finish) through this seam.
///
/// Production is `FlutterNfcKitNfcSession`, which lives in
/// `nfc_kit_transceiver.dart`, the only file in `lib/` that imports Flutter,
/// so this file stays plugin-free. Apps may inject their own implementation;
/// tests inject a fake whose [poll] returns a scripted transceiver.
library;

import 'transceiver.dart';

/// Tri-state NFC availability: the `bool` from [NfcSession.isAvailable] cannot
/// separate "no NFC hardware" (a dead-end) from "NFC disabled" (openable in
/// Android settings). `flutter_nfc_kit`'s own `NFCAvailability` already carries
/// all three states; this surfaces them instead of collapsing to a bool at the
/// transport boundary.
enum NfcAvailability {
  /// NFC hardware present and enabled: a read may be attempted.
  available,

  /// NFC hardware present but turned off (Android; the consumer routes to
  /// the system NFC settings). Never occurs on iOS (no user toggle).
  disabled,

  /// No NFC hardware: a dead-end for chip reading.
  notSupported,
}

abstract class NfcSession {
  Future<bool> isAvailable();

  /// Tri-state availability. Implementations derive [isAvailable] as
  /// `availability() == NfcAvailability.available`.
  Future<NfcAvailability> availability();

  /// Polls for a tag and returns the transceiver over it. Throws a typed
  /// `EmrtdException` (ConnectionError / TimeOutError / UserCanceled /
  /// NoConnectedTag) on failure.
  Future<NfcTransceiver> poll({
    required String iosAlertMessage,
    required Duration transceiveTimeout,
  });

  Future<void> setAlertMessage(String message);

  Future<void> finish({String? iosAlertMessage, String? iosErrorMessage});
}
