import 'dart:async';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter/material.dart';

import 'face_pixels.dart';
import 'mrz_input.dart';
import 'read_failure.dart';

enum _Phase {
  checkingNfc,
  nfcUnsupported,
  nfcDisabled,
  form,
  reading,
  result,
  failed,
}

class ReadScreen extends StatefulWidget {
  const ReadScreen({super.key, required this.reader});

  final PassportReader reader;

  @override
  State<ReadScreen> createState() => _ReadScreenState();
}

class _ReadScreenState extends State<ReadScreen> {
  final _documentNumber = TextEditingController();
  final _dateOfBirth = TextEditingController();
  final _dateOfExpiry = TextEditingController();

  _Phase _phase = _Phase.checkingNfc;
  final List<PassportReadStage> _stages = [];
  int? _percent;
  PassportReadResult? _result;
  ReadFailure? _failure;
  MrzInputError? _formError;

  @override
  void initState() {
    super.initState();
    _checkAvailability();
  }

  @override
  void dispose() {
    _documentNumber.dispose();
    _dateOfBirth.dispose();
    _dateOfExpiry.dispose();
    super.dispose();
  }

  Future<void> _checkAvailability() async {
    final availability = await widget.reader.nfcAvailability();
    if (!mounted) return;
    setState(() {
      _phase = switch (availability) {
        NfcAvailability.available => _Phase.form,
        // Android only: the hardware is there and the user can turn it on.
        NfcAvailability.disabled => _Phase.nfcDisabled,
        NfcAvailability.notSupported => _Phase.nfcUnsupported,
      };
    });
  }

  MrzInput? get _parsedInput {
    try {
      return MrzInput.parse(
        documentNumber: _documentNumber.text,
        dateOfBirth: _dateOfBirth.text,
        dateOfExpiry: _dateOfExpiry.text,
      );
    } on MrzInputError {
      return null;
    }
  }

  Future<void> _read() async {
    final MrzInput input;
    try {
      input = MrzInput.parse(
        documentNumber: _documentNumber.text,
        dateOfBirth: _dateOfBirth.text,
        dateOfExpiry: _dateOfExpiry.text,
      );
    } on MrzInputError catch (e) {
      setState(() => _formError = e);
      return;
    }

    setState(() {
      _phase = _Phase.reading;
      _stages.clear();
      _percent = null;
      _result = null;
      _failure = null;
      _formError = null;
    });

    try {
      final result = await widget.reader.readPassport(
        mrzKey: input.mrzKey,
        onStage: (stage) {
          if (!mounted) return;
          setState(() {
            _recordStage(stage);
            _percent = null;
          });
        },
        onProgress: (stage, percent) {
          if (!mounted) return;
          setState(() {
            _recordStage(stage);
            _percent = percent;
          });
        },
      );
      if (!mounted) return;
      setState(() {
        _result = result;
        _phase = _Phase.result;
      });
    } on PassportReadException catch (e) {
      if (!mounted) return;
      setState(() {
        _failure = classify(e);
        _phase = _Phase.failed;
      });
    }
  }

  void _recordStage(PassportReadStage stage) {
    if (_stages.isEmpty || _stages.last != stage) _stages.add(stage);
  }

  void _backToForm() {
    setState(() {
      _phase = _Phase.form;
      _failure = null;
      _result = null;
      _stages.clear();
      _percent = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('emrtd_core example')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: switch (_phase) {
            _Phase.checkingNfc => const Center(
              child: CircularProgressIndicator(),
            ),
            _Phase.nfcUnsupported => _message(
              copyFor(ReadFailureKind.nfcUnsupported),
            ),
            _Phase.nfcDisabled => _message(
              'NFC is switched off. Turn NFC on in system settings, then '
              'reopen this screen.',
            ),
            _Phase.form => _buildForm(),
            _Phase.reading => _buildReading(),
            _Phase.result => _buildResult(_result!),
            _Phase.failed => _buildFailure(_failure!),
          },
        ),
      ),
    );
  }

  Widget _message(String text) =>
      Center(child: Text(text, textAlign: TextAlign.center));

  Widget _buildForm() {
    final ready = _parsedInput != null;
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text(
            'Enter the three values from the document\'s machine-readable zone. '
            'They are the access key: the chip refuses to open without them.',
          ),
          const SizedBox(height: 16),
          _field(
            _documentNumber,
            'Document number',
            MrzField.documentNumber,
            hint: 'L898902C3',
          ),
          _field(
            _dateOfBirth,
            'Date of birth (YYMMDD)',
            MrzField.dateOfBirth,
            hint: '740812',
          ),
          _field(
            _dateOfExpiry,
            'Date of expiry (YYMMDD)',
            MrzField.dateOfExpiry,
            hint: '340415',
          ),
          const SizedBox(height: 16),
          FilledButton(
            onPressed: ready ? _read : null,
            child: const Text('Read chip'),
          ),
        ],
      ),
    );
  }

  Widget _field(
    TextEditingController controller,
    String label,
    MrzField field, {
    required String hint,
  }) {
    final error = _formError?.field == field ? _formError : null;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: controller,
        textCapitalization: TextCapitalization.characters,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: const OutlineInputBorder(),
          errorText: error == null ? null : _reasonText(error.reason),
        ),
        onChanged: (_) => setState(() => _formError = null),
      ),
    );
  }

  String _reasonText(MrzErrorReason reason) => switch (reason) {
    MrzErrorReason.empty => 'Required',
    MrzErrorReason.illegalCharacter => 'Only A-Z, 0-9 and < are allowed',
    MrzErrorReason.wrongLength => 'Six characters, YYMMDD',
  };

  Widget _buildReading() {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const Text('Hold the device against the document and keep it still.'),
          const SizedBox(height: 16),
          for (final stage in _stages)
            Row(
              children: [
                const Icon(Icons.check, size: 16),
                const SizedBox(width: 8),
                Text(stageLabel(stage)),
                if (stage == _stages.last && _percent != null) ...[
                  const SizedBox(width: 8),
                  Text('$_percent %'),
                ],
              ],
            ),
          const SizedBox(height: 16),
          const LinearProgressIndicator(),
        ],
      ),
    );
  }

  Widget _buildResult(PassportReadResult result) {
    final fields = Dg1Fields.from(result.dg1);
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FaceView(image: result.faceImage, format: result.faceImageFormat),
          const SizedBox(height: 16),
          _row(
            'Name',
            '${fields.primaryIdentifier} ${fields.secondaryIdentifier}',
          ),
          _row('Document number', fields.documentNumber),
          _row('Issuing state', fields.issuingState),
          _row('Nationality', fields.nationality),
          _row('Date of birth', fields.dateOfBirth),
          _row('Date of expiry', fields.dateOfExpiry),
          _row('Sex', fields.sex),
          const Divider(),
          _row('Access protocol', result.accessProtocol.name.toUpperCase()),
          _row(
            'Chip authentication',
            _statusLabel(result.chipAuthenticationStatus.name),
          ),
          _row(
            'Active authentication',
            _statusLabel(result.activeAuthenticationStatus.name),
          ),
          _row('Duration', '${result.durationMs} ms'),
          const SizedBox(height: 16),
          FilledButton(
            onPressed: _backToForm,
            child: const Text('Read another'),
          ),
        ],
      ),
    );
  }

  Widget _row(String label, String? value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 2),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(width: 150, child: Text(label)),
        Expanded(child: Text(value ?? '-')),
      ],
    ),
  );

  Widget _buildFailure(ReadFailure failure) {
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(copyFor(failure.kind)),
          const SizedBox(height: 16),
          // Not user copy: this is what a bug report needs, and leaving it out
          // is why chip-read issues are so hard to diagnose in the field.
          Text(
            'step: ${failure.step?.name ?? '-'}   '
            'code: ${failure.code ?? '-'}   '
            'sw: ${failure.sw == null ? '-' : failure.sw!.toRadixString(16)}'
            '${failure.paceOnly ? '   pace-only' : ''}',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 16),
          FilledButton(onPressed: _backToForm, child: const Text('Try again')),
        ],
      ),
    );
  }
}

String _statusLabel(String enumName) => enumName.replaceAllMapped(
  RegExp(r'[A-Z]'),
  (m) => ' ${m[0]!.toLowerCase()}',
);

String stageLabel(PassportReadStage stage) => switch (stage) {
  PassportReadStage.waitingForTag => 'Waiting for the chip',
  PassportReadStage.authenticating => 'Authenticating',
  PassportReadStage.readingDg14 => 'Reading DG14',
  PassportReadStage.readingDg1 => 'Reading DG1',
  PassportReadStage.readingDg2 => 'Reading DG2',
  PassportReadStage.readingDg7 => 'Reading DG7',
  PassportReadStage.readingDg11 => 'Reading DG11',
  PassportReadStage.readingDg12 => 'Reading DG12',
  PassportReadStage.readingDg15 => 'Reading DG15',
  PassportReadStage.readingSod => 'Reading the security object',
  PassportReadStage.activeAuthentication => 'Verifying chip authenticity',
  PassportReadStage.done => 'Done',
};

/// Renders the DG2 face image, decoding JPEG 2000 when that is what the chip
/// carried.
///
/// Every branch ends in a picture or a labelled placeholder, never a blank
/// and never an exception; a portrait that will not decode is a display
/// problem, not a read failure, and the rest of the result is still good.
class FaceView extends StatefulWidget {
  const FaceView({super.key, required this.image, required this.format});

  final Uint8List image;
  final FaceImageFormat? format;

  @override
  State<FaceView> createState() => _FaceViewState();
}

class _FaceViewState extends State<FaceView> {
  ui.Image? _decoded;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    final decode = decideFace(widget.image, widget.format);
    if (decode.kind == FaceDecodeKind.jpeg2000) {
      _decodeJpeg2000(decode.bytes!);
    }
  }

  Future<void> _decodeJpeg2000(Uint8List bytes) async {
    // Off the UI isolate: a full-size portrait is hundreds of milliseconds of
    // pure computation, which would drop frames on the main one.
    final pixels = await decodeJpeg2000FaceInIsolate(bytes);
    if (!mounted) return;
    if (pixels == null) {
      setState(() => _failed = true);
      return;
    }
    final completer = Completer<ui.Image>();
    ui.decodeImageFromPixels(
      pixels.rgba,
      pixels.width,
      pixels.height,
      ui.PixelFormat.rgba8888,
      completer.complete,
    );
    final image = await completer.future;
    if (!mounted) return;
    setState(() => _decoded = image);
  }

  @override
  void dispose() {
    _decoded?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final decode = decideFace(widget.image, widget.format);
    return SizedBox(
      height: 240,
      child: switch (decode.kind) {
        FaceDecodeKind.jpeg => Image.memory(
          decode.bytes!,
          fit: BoxFit.contain,
          errorBuilder: (_, _, _) => const FacePlaceholder(),
        ),
        FaceDecodeKind.jpeg2000 when _decoded != null => RawImage(
          image: _decoded,
          fit: BoxFit.contain,
        ),
        FaceDecodeKind.jpeg2000 when _failed => const FacePlaceholder(),
        FaceDecodeKind.jpeg2000 => const Center(
          child: CircularProgressIndicator(),
        ),
        FaceDecodeKind.unknown => const FacePlaceholder(),
      },
    );
  }
}

class FacePlaceholder extends StatelessWidget {
  const FacePlaceholder({super.key});

  @override
  Widget build(BuildContext context) => DecoratedBox(
    decoration: BoxDecoration(border: Border.all()),
    child: const Center(child: Text('Photo could not be decoded')),
  );
}
