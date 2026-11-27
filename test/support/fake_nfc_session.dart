import 'package:emrtd_core/emrtd_core.dart';

/// Test session driver: hands `PassportReader` a simulated chip instead of
/// polling `flutter_nfc_kit`, and counts lifecycle calls for the
/// exactly-one-completion assertions.
class FakeNfcSession implements NfcSession {
  FakeNfcSession(this.transceiver, {this.available = true, this.pollError});

  final NfcTransceiver transceiver;
  final bool available;

  /// When set, [poll] throws it (a typed EmrtdException) instead of
  /// connecting.
  final Object? pollError;

  int pollCalls = 0;
  int finishCalls = 0;
  final List<String> alerts = [];

  @override
  Future<bool> isAvailable() async => available;

  @override
  Future<NfcAvailability> availability() async =>
      available ? NfcAvailability.available : NfcAvailability.notSupported;

  @override
  Future<NfcTransceiver> poll({
    required String iosAlertMessage,
    required Duration transceiveTimeout,
  }) async {
    pollCalls++;
    alerts.add(iosAlertMessage);
    final error = pollError;
    if (error != null) throw error;
    return transceiver;
  }

  @override
  Future<void> setAlertMessage(String message) async {
    alerts.add(message);
  }

  @override
  Future<void> finish({
    String? iosAlertMessage,
    String? iosErrorMessage,
  }) async {
    finishCalls++;
  }
}
