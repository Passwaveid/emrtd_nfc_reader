import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:emrtd_core_example/main.dart';
import 'package:emrtd_core_example/read_failure.dart';
import 'package:emrtd_core_example/read_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'fake_reader.dart';
import 'specimen.dart';

/// A DG2 that reports a different image and format than the parsed one, so a
/// test can drive the JPEG 2000 branch without a JPEG 2000 chip fixture.
///
/// `DataGroup2` is non-final, `imageData` is an ordinary field and
/// `faceImageFormat` an overridable getter, which is what makes this possible
/// without touching the package.
class SwappedFaceDataGroup2 extends DataGroup2 {
  SwappedFaceDataGroup2(super.data, this._image, this._format);

  final Uint8List _image;
  final FaceImageFormat _format;

  @override
  Uint8List get imageData => _image;

  @override
  FaceImageFormat get faceImageFormat => _format;
}

PassportReadResult buildResult({DataGroup2? dg2}) => PassportReadResult(
  dg1: DataGroup1(hex(dg1Hex)),
  dg2: dg2 ?? DataGroup2(hex(dg2Hex)),
  sod: SOD(hex(sodHex)),
  dg14: null,
  dg15: null,
  dg7: null,
  dg11: null,
  dg12: null,
  accessProtocol: AccessProtocol.bac,
  paceCamStatus: PaceCamStatus.notApplicable,
  chipAuthenticationStatus: ChipAuthenticationStatus.notDone,
  activeAuthenticationStatus: ActiveAuthenticationStatus.notDone,
  activeAuthenticationChallenge: null,
  activeAuthenticationSignature: null,
  passiveAuth: null,
  trace: PassportReadTrace(),
);

const happyScript = <(PassportReadStage, int?)>[
  (PassportReadStage.waitingForTag, null),
  (PassportReadStage.authenticating, null),
  (PassportReadStage.readingDg1, null),
  (PassportReadStage.readingDg2, 40),
  (PassportReadStage.readingSod, null),
  (PassportReadStage.done, null),
];

Future<void> pumpApp(WidgetTester tester, FakePassportReader reader) async {
  await tester.pumpWidget(EmrtdExampleApp(reader: reader));
  await tester.pumpAndSettle();
}

Future<void> enterSpecimen(WidgetTester tester) async {
  await tester.enterText(find.byType(TextField).at(0), 'L898902C');
  await tester.enterText(find.byType(TextField).at(1), '690806');
  await tester.enterText(find.byType(TextField).at(2), '940623');
  await tester.pump();
}

/// Taps submit and pumps the scripted read to completion.
///
/// Not `pumpAndSettle`: the fake yields between callbacks with a
/// zero-duration timer, which a bare `pump()` never fires, and the JPEG 2000
/// branch shows a spinner whose animation would keep `pumpAndSettle` from
/// ever settling.
const step = Duration(milliseconds: 10);

Future<void> runRead(WidgetTester tester, {int extraFrames = 2}) async {
  await tester.tap(find.text('Read chip'));
  for (var i = 0; i < happyScript.length + extraFrames; i++) {
    await tester.pump(step);
  }
}

void main() {
  group('NFC availability gate', () {
    testWidgets('no hardware is a dead end, and never starts a read', (
      tester,
    ) async {
      final reader = FakePassportReader(
        availability: NfcAvailability.notSupported,
      );
      await pumpApp(tester, reader);

      expect(find.text(copyFor(ReadFailureKind.nfcUnsupported)), findsOne);
      expect(find.byType(TextField), findsNothing);
      expect(reader.readCalls, 0);
    });

    testWidgets('disabled NFC offers the settings route', (tester) async {
      await pumpApp(
        tester,
        FakePassportReader(availability: NfcAvailability.disabled),
      );

      expect(find.textContaining('Turn NFC on'), findsOne);
      expect(find.byType(TextField), findsNothing);
    });

    testWidgets('available NFC shows the form with submit disabled', (
      tester,
    ) async {
      await pumpApp(tester, FakePassportReader());

      expect(find.byType(TextField), findsExactly(3));
      final button = tester.widget<FilledButton>(find.byType(FilledButton));
      expect(button.onPressed, isNull);
    });
  });

  group('the form', () {
    testWidgets('a complete specimen enables submit', (tester) async {
      await pumpApp(tester, FakePassportReader());
      await enterSpecimen(tester);

      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNotNull,
      );
    });

    testWidgets('an invalid expiry disables submit', (tester) async {
      await pumpApp(tester, FakePassportReader());
      await enterSpecimen(tester);
      await tester.enterText(find.byType(TextField).at(2), '9406');
      await tester.pump();

      expect(
        tester.widget<FilledButton>(find.byType(FilledButton)).onPressed,
        isNull,
      );
    });
  });

  group('a successful read', () {
    testWidgets('renders every stage in order, with the DG2 percentage', (
      tester,
    ) async {
      final reader = FakePassportReader(
        script: happyScript,
        result: buildResult(),
      );
      await pumpApp(tester, reader);
      await enterSpecimen(tester);
      await tester.tap(find.text('Read chip'));

      final seen = <String>[];
      for (var i = 0; i < happyScript.length; i++) {
        await tester.pump(step);
        for (final label in [
          'Waiting for the chip',
          'Authenticating',
          'Reading DG1',
          'Reading DG2',
          'Reading the security object',
          'Done',
        ]) {
          if (find.text(label).evaluate().isNotEmpty && !seen.contains(label)) {
            seen.add(label);
          }
        }
        if (find.text('40 %').evaluate().isNotEmpty && !seen.contains('40 %')) {
          seen.add('40 %');
        }
      }

      expect(seen, [
        'Waiting for the chip',
        'Authenticating',
        'Reading DG1',
        'Reading DG2',
        '40 %',
        'Reading the security object',
        'Done',
      ]);
    });

    testWidgets('shows the parsed document and the protocol outcomes', (
      tester,
    ) async {
      await pumpApp(
        tester,
        FakePassportReader(script: happyScript, result: buildResult()),
      );
      await enterSpecimen(tester);
      await runRead(tester);

      expect(find.text('ERIKSSON ANNA MARIA'), findsOne);
      expect(find.text('L898902C3'), findsOne);
      expect(find.text('UTO'), findsExactly(2)); // issuing state, nationality
      expect(find.text('740812'), findsOne);
      expect(find.text('340415'), findsOne);
      expect(find.text('BAC'), findsOne);
      expect(find.text('not done'), findsExactly(2)); // CA and AA
    });

    testWidgets('passes the composed MRZ key down to readPassport', (
      tester,
    ) async {
      final reader = FakePassportReader(
        script: happyScript,
        result: buildResult(),
      );
      await pumpApp(tester, reader);
      await enterSpecimen(tester);
      await runRead(tester);

      expect(reader.receivedMrzKey, specimenMrzKey);
    });

    testWidgets('a second read replaces the first, with no stale stages', (
      tester,
    ) async {
      final reader = FakePassportReader(
        script: happyScript,
        result: buildResult(),
      );
      await pumpApp(tester, reader);
      await enterSpecimen(tester);
      await runRead(tester);

      // The button sits below the fold on a short viewport; tapping without
      // scrolling to it would land the pointer on whatever is there instead.
      await tester.ensureVisible(find.text('Read another'));
      await tester.tap(find.text('Read another'));
      await tester.pump(step);
      expect(find.byType(TextField), findsExactly(3));
      expect(find.text('ERIKSSON ANNA MARIA'), findsNothing);
      expect(find.text('Done'), findsNothing);

      await runRead(tester);
      expect(reader.readCalls, 2);
      expect(find.text('ERIKSSON ANNA MARIA'), findsOne);
    });
  });

  group('the face image', () {
    testWidgets('an undecodable JPEG falls back to the placeholder', (
      tester,
    ) async {
      // The specimen DG2 carries a JFIF header and 4 bytes of nothing, which
      // is exactly why Image.memory needs an errorBuilder here.
      await pumpApp(
        tester,
        FakePassportReader(script: happyScript, result: buildResult()),
      );
      await enterSpecimen(tester);
      await runRead(tester);

      expect(find.byType(Image), findsOne);
      expect(find.byType(FacePlaceholder), findsOne);
    });

    testWidgets('a JPEG 2000 face decodes and renders', (tester) async {
      final jp2 = File('test/fixtures/synthetic_face.jp2').readAsBytesSync();
      final reader = FakePassportReader(
        script: happyScript,
        result: buildResult(
          dg2: SwappedFaceDataGroup2(hex(dg2Hex), jp2, FaceImageFormat.jp2),
        ),
      );
      await pumpApp(tester, reader);
      await enterSpecimen(tester);
      await runRead(tester);

      // The decode runs on another isolate, so the test has to let real time
      // pass (runAsync) and then pump to see the result of the setState it
      // triggers. Neither alone is enough.
      for (
        var i = 0;
        i < 100 && find.byType(RawImage).evaluate().isEmpty;
        i++
      ) {
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)),
        );
        await tester.pump();
      }

      final image = tester.widget<RawImage>(find.byType(RawImage)).image!;
      expect(image.width, 96);
      expect(image.height, 128);
      expect(find.byType(FacePlaceholder), findsNothing);
    });

    testWidgets('an undetected format shows the placeholder', (tester) async {
      // Reached through FaceView directly: PassportReadResult's format comes
      // off DataGroup2 and is never null, but a caller passing a sniffed
      // format from DG7/DG12 can hand it one.
      await tester.pumpWidget(
        MaterialApp(home: FaceView(image: hex(dg2Hex), format: null)),
      );
      await tester.pumpAndSettle();

      expect(find.byType(FacePlaceholder), findsOne);
      expect(find.byType(Image), findsNothing);
    });
  });

  group('a failed read', () {
    Future<void> failWith(WidgetTester tester, Object error) async {
      await pumpApp(
        tester,
        FakePassportReader(script: happyScript, error: error),
      );
      await enterSpecimen(tester);
      await runRead(tester);
    }

    PassportReadException failure(
      EmrtdException? cause,
      PassportReadStep step,
    ) => PassportReadException(
      cause: cause,
      step: step,
      trace: PassportReadTrace()..step = step,
      message: 'test',
    );

    testWidgets('a wrong key returns to the form with the values kept', (
      tester,
    ) async {
      await failWith(tester, failure(InvalidMRZKey(), PassportReadStep.bac));
      expect(find.text(copyFor(ReadFailureKind.wrongDetails)), findsOne);

      await tester.tap(find.text('Try again'));
      await tester.pump(step);

      expect(find.byType(TextField), findsExactly(3));
      expect(
        tester.widget<TextField>(find.byType(TextField).at(0)).controller!.text,
        'L898902C',
      );
      expect(
        tester.widget<TextField>(find.byType(TextField).at(1)).controller!.text,
        '690806',
      );
      expect(
        tester.widget<TextField>(find.byType(TextField).at(2)).controller!.text,
        '940623',
      );
    });

    testWidgets('a cancelled session reads as interrupted', (tester) async {
      await failWith(tester, failure(UserCanceled(), PassportReadStep.poll));
      expect(find.text(copyFor(ReadFailureKind.interrupted)), findsOne);

      await tester.tap(find.text('Try again'));
      await tester.pump(step);
      expect(find.byType(TextField), findsExactly(3));
    });

    testWidgets('a poll timeout reads as never-found, with diagnostics', (
      tester,
    ) async {
      await failWith(tester, failure(TimeOutError(), PassportReadStep.poll));

      expect(find.text(copyFor(ReadFailureKind.neverFound)), findsOne);
      expect(find.textContaining('poll'), findsOne);
      expect(find.textContaining('TimeOutError'), findsOne);
    });
  });
}
