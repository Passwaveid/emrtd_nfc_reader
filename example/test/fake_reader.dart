import 'package:emrtd_core/emrtd_core.dart';

/// An [NfcSession] that never touches a radio.
///
/// `PassportReader`'s constructor builds a `FlutterNfcKitNfcSession` when it
/// is given no session, and that one reaches for a platform channel. Handing
/// it this instead is what keeps these tests free of a device.
class FakeNfcSession implements NfcSession {
  @override
  Future<bool> isAvailable() async => true;

  @override
  Future<NfcAvailability> availability() async => NfcAvailability.available;

  @override
  Future<NfcTransceiver> poll({
    required String iosAlertMessage,
    required Duration transceiveTimeout,
  }) async => throw UnimplementedError('the fake reader never polls');

  @override
  Future<void> setAlertMessage(String message) async {}

  @override
  Future<void> finish({
    String? iosAlertMessage,
    String? iosErrorMessage,
  }) async {}
}

/// A `PassportReader` that replays a scripted read.
///
/// `PassportReader` is deliberately non-final with an overridable
/// [readPassport] so consumers can fake it without a chip simulator; this is
/// that seam being used as intended.
class FakePassportReader extends PassportReader {
  FakePassportReader({
    this.availability = NfcAvailability.available,
    this.script = const [],
    this.result,
    this.error,
    this.stepDelay = const Duration(milliseconds: 10),
  }) : super(session: FakeNfcSession());

  final NfcAvailability availability;

  /// The read's callbacks, in order. A null percent fires `onStage`; a
  /// non-null one fires `onProgress`, so a script can interleave them the way
  /// a real read does.
  final List<(PassportReadStage, int?)> script;

  final PassportReadResult? result;
  final Object? error;

  /// How long the read pauses between callbacks. Long enough that one
  /// `pump(stepDelay)` advances exactly one step, so a test can watch the
  /// screen change rather than only see the final state.
  final Duration stepDelay;

  /// What the screen actually passed down.
  String? receivedMrzKey;
  int readCalls = 0;

  @override
  Future<NfcAvailability> nfcAvailability() async => availability;

  @override
  Future<bool> isNfcAvailable() async =>
      availability == NfcAvailability.available;

  @override
  Future<PassportReadResult> readPassport({
    required String mrzKey,
    List<int>? aaChallenge,
    void Function(PassportReadStage stage)? onStage,
    void Function(PassportReadStage stage, int percent)? onProgress,
  }) async {
    readCalls++;
    receivedMrzKey = mrzKey;
    for (final (stage, percent) in script) {
      if (percent == null) {
        onStage?.call(stage);
      } else {
        onProgress?.call(stage, percent);
      }
      await Future<void>.delayed(stepDelay);
    }
    final failure = error;
    if (failure != null) throw failure;
    return result!;
  }
}
