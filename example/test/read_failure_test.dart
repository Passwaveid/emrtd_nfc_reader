import 'package:emrtd_core/emrtd_core.dart';
import 'package:emrtd_core_example/read_failure.dart';
import 'package:flutter_test/flutter_test.dart';

PassportReadException exception({
  EmrtdException? cause,
  required PassportReadStep step,
  bool cardAccessPresent = false,
  bool paceAttempted = false,
  String? paceSw,
}) {
  final trace = PassportReadTrace()
    ..step = step
    ..cardAccessPresent = cardAccessPresent
    ..paceAttempted = paceAttempted
    ..paceSw = paceSw;
  return PassportReadException(
    cause: cause,
    step: step,
    trace: trace,
    message: 'test',
  );
}

void main() {
  group('arm 1: the chip refused the PACE password', () {
    test('63 00 is wrong details, and outranks the PACE-only arm', () {
      final f = classify(
        exception(
          cause: ResponseError('', 0x69, 0x82),
          step: PassportReadStep.bac,
          cardAccessPresent: true,
          paceAttempted: true,
          paceSw: '6300',
        ),
      );
      expect(f.kind, ReadFailureKind.wrongDetails);
      expect(f.sw, 0x6982);
      expect(f.paceOnly, isFalse);
    });

    for (final sw in ['63c0', '63cf']) {
      test('the retry-counter status $sw is wrong details', () {
        final f = classify(
          exception(
            cause: ResponseError('', 0x69, 0x82),
            step: PassportReadStep.bac,
            paceAttempted: true,
            paceSw: sw,
          ),
        );
        expect(f.kind, ReadFailureKind.wrongDetails);
      });
    }

    for (final sw in ['63d0', '6982', null, 'zz']) {
      test('the ambiguous status ${sw ?? 'null'} does not take arm 1', () {
        final f = classify(
          exception(
            cause: TimeOutError(),
            step: PassportReadStep.readDg1,
            paceAttempted: true,
            paceSw: sw,
          ),
        );
        expect(f.kind, ReadFailureKind.lostConnection);
      });
    }

    test(
      'a matching status word without paceAttempted does not take arm 1',
      () {
        final f = classify(
          exception(
            cause: TimeOutError(),
            step: PassportReadStep.readDg1,
            paceSw: '6300',
          ),
        );
        expect(f.kind, ReadFailureKind.lostConnection);
      },
    );
  });

  group('arm 2: the PACE-only chip', () {
    ReadFailure paceOnlyCase({
      required int sw1,
      required int sw2,
      bool cardAccessPresent = true,
      bool paceAttempted = true,
      PassportReadStep step = PassportReadStep.bac,
    }) => classify(
      exception(
        cause: ResponseError('', sw1, sw2),
        step: step,
        cardAccessPresent: cardAccessPresent,
        paceAttempted: paceAttempted,
      ),
    );

    test('6982 at bac is flagged, and is never wrong details', () {
      final f = paceOnlyCase(sw1: 0x69, sw2: 0x82);
      expect(f.kind, ReadFailureKind.couldNotRead);
      expect(f.paceOnly, isTrue);
      expect(f.sw, 0x6982);
    });

    test('6A88 at bac is flagged too', () {
      expect(paceOnlyCase(sw1: 0x6A, sw2: 0x88).paceOnly, isTrue);
    });

    test('6A80 is a different refusal and is not flagged', () {
      final f = paceOnlyCase(sw1: 0x6A, sw2: 0x80);
      expect(f.kind, ReadFailureKind.couldNotRead);
      expect(f.paceOnly, isFalse);
    });

    test('without EF.CardAccess it is not the PACE-only shape', () {
      expect(
        paceOnlyCase(sw1: 0x69, sw2: 0x82, cardAccessPresent: false).paceOnly,
        isFalse,
      );
    });

    test('without a PACE attempt it is not the PACE-only shape', () {
      expect(
        paceOnlyCase(sw1: 0x69, sw2: 0x82, paceAttempted: false).paceOnly,
        isFalse,
      );
    });

    test('at another step it is not the PACE-only shape', () {
      expect(
        paceOnlyCase(
          sw1: 0x69,
          sw2: 0x82,
          step: PassportReadStep.selectApp,
        ).paceOnly,
        isFalse,
      );
    });

    test('the same shape with InvalidMRZKey falls through to arm 5', () {
      final f = classify(
        exception(
          cause: InvalidMRZKey(),
          step: PassportReadStep.bac,
          cardAccessPresent: true,
          paceAttempted: true,
        ),
      );
      expect(f.kind, ReadFailureKind.wrongDetails);
      expect(f.paceOnly, isFalse);
    });
  });

  group('arm 3: the SOD hash oracle', () {
    test('a null cause at the oracle step could not be read', () {
      final f = classify(exception(step: PassportReadStep.oracle));
      expect(f.kind, ReadFailureKind.couldNotRead);
      expect(f.code, isNull);
      expect(f.step, PassportReadStep.oracle);
    });

    test('a null cause at any other step is the defensive wrap', () {
      final f = classify(exception(step: PassportReadStep.readDg2));
      expect(f.kind, ReadFailureKind.couldNotRead);
    });
  });

  group('arm 4: never found versus lost', () {
    test('a timeout at poll never found the chip', () {
      final f = classify(
        exception(cause: TimeOutError(), step: PassportReadStep.poll),
      );
      expect(f.kind, ReadFailureKind.neverFound);
      expect(f.code, 'TimeOutError');
    });

    test('no connected tag at poll never found the chip', () {
      expect(
        classify(
          exception(cause: NoConnectedTag(), step: PassportReadStep.poll),
        ).kind,
        ReadFailureKind.neverFound,
      );
    });

    test('the same timeout past poll is a dropped link', () {
      expect(
        classify(
          exception(cause: TimeOutError(), step: PassportReadStep.readDg2),
        ).kind,
        ReadFailureKind.lostConnection,
      );
    });

    test('a connection error at poll is a dropped link, not never-found', () {
      expect(
        classify(
          exception(cause: ConnectionError(), step: PassportReadStep.poll),
        ).kind,
        ReadFailureKind.lostConnection,
      );
    });
  });

  group('arm 5: by cause', () {
    final cases = <EmrtdException, ReadFailureKind>{
      InvalidMRZKey(): ReadFailureKind.wrongDetails,
      UserCanceled(): ReadFailureKind.interrupted,
      NFCNotSupported(): ReadFailureKind.nfcUnsupported,
      ConnectionError(): ReadFailureKind.lostConnection,
      PACEError('step', 'why'): ReadFailureKind.couldNotRead,
      InvalidResponse(DataGroupId.DG1, 0x61, 0x62):
          ReadFailureKind.couldNotRead,
      UnknownError('boom'): ReadFailureKind.couldNotRead,
    };
    cases.forEach((cause, expected) {
      test('${cause.code} is $expected', () {
        final f = classify(exception(cause: cause, step: PassportReadStep.bac));
        expect(f.kind, expected);
        expect(f.code, cause.code, reason: 'the code mirrors cause.code');
      });
    });
  });

  group('copy', () {
    for (final kind in ReadFailureKind.values) {
      test('$kind has copy', () {
        final copy = copyFor(kind);
        expect(copy, isNotEmpty);
        // The library ships no copy on purpose, and an example must not
        // smuggle one product's voice into everyone else's app.
        expect(copy.toLowerCase(), isNot(contains('passwave')));
      });
    }
  });
}
