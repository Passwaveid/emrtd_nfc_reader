/// Scripted fake transceiver: drives golden-transcript replay and any test
/// that needs command-by-command assertions.
///
/// Each expected step carries the structured command (compared on both
/// runners' replays) and optionally the exact wire bytes (asserted on the
/// Dart side only: CoreNFC wire bytes are unobservable, ours are
/// canonical). Responses are canned data‖SW1‖SW2 frames.
library;

import 'dart:typed_data';

import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:flutter_test/flutter_test.dart';

class ScriptedStep {
  ScriptedStep({required this.cmd, this.wire, required this.response});

  /// Expected structured command (CLA/INS/P1/P2/data/Le).
  final CommandAPDU cmd;

  /// Optional exact expected wire bytes (Dart-runner-only assertion).
  final Uint8List? wire;

  /// Canned response: data‖SW1‖SW2.
  final Uint8List response;
}

class ScriptedTransceiver implements NfcTransceiver {
  ScriptedTransceiver(
    this._steps, {
    this.maxTransceiveLength = 261,
    this.isExtendedLengthApduSupported = false,
    this.historicalBytes,
    this.tagCapabilities,
  });

  final List<ScriptedStep> _steps;
  int _next = 0;

  @override
  final int maxTransceiveLength;

  @override
  final bool isExtendedLengthApduSupported;

  @override
  final Uint8List? historicalBytes;

  @override
  final TagCapabilities? tagCapabilities;

  /// True once every scripted step has been consumed; transcripts assert
  /// this at the end so unexercised steps fail loudly.
  bool get exhausted => _next == _steps.length;

  int get consumedSteps => _next;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    final hex = _hex(capdu);
    if (_next >= _steps.length) {
      fail(
        'scripted transceiver exhausted after $_next step(s); '
        'implementation sent unexpected command $hex',
      );
    }
    final step = _steps[_next];
    final stepLabel = 'step ${_next + 1}';
    _next++;

    final actual = CommandAPDU.parse(capdu);
    final expected = step.cmd;
    expect(
      {
        'cla': actual.instructionClass,
        'ins': actual.instructionCode,
        'p1': actual.p1Parameter,
        'p2': actual.p2Parameter,
        'data': _hex(actual.data),
        'le': actual.expectedResponseLength,
      },
      equals({
        'cla': expected.instructionClass,
        'ins': expected.instructionCode,
        'p1': expected.p1Parameter,
        'p2': expected.p2Parameter,
        'data': _hex(expected.data),
        'le': expected.expectedResponseLength,
      }),
      reason: '$stepLabel: structured command mismatch (sent wire: $hex)',
    );
    if (step.wire != null) {
      expect(hex, _hex(step.wire!), reason: '$stepLabel: wire bytes mismatch');
    }
    return step.response;
  }

  static String _hex(List<int> bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}
