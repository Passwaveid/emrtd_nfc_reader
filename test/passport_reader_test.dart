/// PassportReader session tests: the orchestration reproduced from upstream
/// (ladder order, PACE fallback, per-DG retries, fatal errors), the per-DG
/// retry table, the session lifecycle, and the hash oracle, each driven
/// end-to-end through the injected session/transceiver seam against the
/// simulated chip (real BAC/PACE crypto, no canned wire bytes), asserted
/// against the result/trace/exception surface. The error classification and
/// the sdkId pin stay app-side (policy).
library;

import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/emrtd_chip_sim.dart';
import 'support/emrtd_fixtures.dart';
import 'support/fake_nfc_session.dart';
import 'support/pki_fixtures.dart';

void main() {
  late List<PassportReadStage> stages;

  setUp(() {
    stages = [];
  });

  PassportReader reader(FakeNfcSession session) =>
      PassportReader(session: session);

  Future<PassportReadResult> readOk(FakeNfcSession session) => reader(
    session,
  ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

  Future<PassportReadException> readFail(FakeNfcSession session) async {
    try {
      await readOk(session);
      fail('expected PassportReadException');
    } on PassportReadException catch (e) {
      return e;
    }
  }

  /// The BAC-only shape: MF select refused, no EF.CardAccess.
  EmrtdChipSim bacOnlyChip({
    int mutualAuthSw = 0x9000,
    int aidSelectSw = 0x9000,
    int? Function(SimCommand cmd)? injectSw,
    Object? Function(SimCommand cmd)? injectThrow,
    bool Function(SimCommand cmd)? corruptMac,
    bool tamperedDg1 = false,
  }) => EmrtdChipSim(
    mrzKey: specimenMrzInfo,
    files: specimenFiles(tamperedDg1: tamperedDg1),
    mfSelectSw: 0x6A86,
    aidSelectSw: aidSelectSw,
    mutualAuthSw: mutualAuthSw,
    injectSw: injectSw,
    injectThrow: injectThrow,
    corruptMac: corruptMac,
  );

  /// A PACE-capable chip (EF.CardAccess served, ECDH-GM over Brainpool
  /// P-256) whose password answer can be scripted.
  EmrtdChipSim paceChip({
    String mrzKey = specimenMrzInfo,
    int paceTokenSw = 0x9000,
    int mutualAuthSw = 0x9000,
    int? Function(SimCommand cmd)? injectSw,
    Object? Function(SimCommand cmd)? injectThrow,
    bool Function(SimCommand cmd)? corruptMac,
    bool Function(SimCommand cmd)? malformDo87,
  }) => EmrtdChipSim(
    mrzKey: mrzKey,
    files: specimenFiles(),
    cardAccess: hx(cardAccessG1Hex),
    pace: paceG1Config(),
    paceTokenSw: paceTokenSw,
    mutualAuthSw: mutualAuthSw,
    injectSw: injectSw,
    injectThrow: injectThrow,
    corruptMac: corruptMac,
    malformDo87: malformDo87,
  );

  /// A re-authentication record minus its timing, for `expect`.
  Map<String, Object?> reauthView(SessionReauthentication r) => {
    'step': r.step,
    'paceAttempted': r.paceAttempted,
    'paceFailedCode': r.paceFailedCode,
    'paceFailedStep': r.paceFailedStep,
    'paceSw': r.paceSw,
    'protocol': r.protocol,
  };

  /// True for the first command [match] accepts, false ever after.
  bool Function(SimCommand cmd) firstOf(bool Function(SimCommand cmd) match) {
    var fired = false;
    return (cmd) {
      if (fired || !match(cmd)) return false;
      return fired = true;
    };
  }

  /// [sw] for the first command [match] accepts, then never again.
  int? Function(SimCommand cmd) swOnce(
    int sw,
    bool Function(SimCommand cmd) match,
  ) {
    final hit = firstOf(match);
    return (cmd) => hit(cmd) ? sw : null;
  }

  bool dg1Read(SimCommand cmd) => cmd.ins == 0xB0 && cmd.fid == 0x0101;

  /// The re-PACE's MSE:Set AT: the second unprotected one of the read (the
  /// Chip Authentication MSE is protected).
  bool Function(SimCommand cmd) secondPlainMse() {
    var seen = 0;
    return (cmd) => !cmd.isProtected && cmd.ins == 0x22 && ++seen == 2;
  }

  group('BAC-only session (no EF.CardAccess)', () {
    test(
      'full read: ladder, parsed files, raws, trace, stages, one finish',
      () async {
        final chip = bacOnlyChip();
        final session = FakeNfcSession(chip);
        final result = await readOk(session);

        // Parsed files travel alongside the raw bytes.
        expect(result.dg1.elements['5F1F']?.length, 88);
        expect(
          result.dg1.elements['5F1F'],
          startsWith('PPUTOERIKSSON<<ANNA<MARIA'),
        );
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.dg2Raw, hx(dg2Hex));
        expect(result.sodRaw, hx(sodHex));
        expect(result.faceImage, hx(dg2FaceJpegHex));
        expect(result.faceImageFormat, FaceImageFormat.jpeg);
        expect(result.accessProtocol, AccessProtocol.bac);

        // The oracle always ran and passed on a result.
        expect(result.trace.sodHashCheck, isNotNull);
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(result.durationMs, result.trace.totalMs);

        // Stage sequence at operation boundaries: the DG14 and DG15 probes
        // run even on a chip carrying neither, so both stages are emitted;
        // `activeAuthentication` is not, because there is no DG15 to
        // authenticate against.
        expect(stages, [
          PassportReadStage.waitingForTag,
          PassportReadStage.authenticating,
          PassportReadStage.readingDg14,
          PassportReadStage.readingDg1,
          PassportReadStage.readingDg2,
          PassportReadStage.readingDg15,
          PassportReadStage.readingSod,
          PassportReadStage.done,
        ]);

        // DG14: probed, absent, CA never attempted.
        expect(result.dg14, isNull);
        expect(result.dg14Raw, isNull);
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.notDone,
        );
        expect(result.trace.dg14Present, isFalse);
        expect(result.trace.caSupported, isFalse);
        expect(result.trace.caOid, isNull);
        expect(result.trace.caKeyId, isNull);
        expect(result.trace.dg14Retries, 0);

        // DG15: probed, absent, AA never attempted.
        expect(result.dg15, isNull);
        expect(result.dg15Raw, isNull);
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.notDone,
        );
        expect(result.activeAuthenticationChallenge, isNull);
        expect(result.activeAuthenticationSignature, isNull);
        expect(result.trace.dg15Present, isFalse);
        expect(result.trace.aaSupported, isFalse);
        expect(result.trace.aaDigest, isNull);
        expect(result.trace.dg15Retries, 0);
        expect(chip.internalAuthCount, 0);

        // Exactly one finish; single BAC; PACE never attempted (the ladder
        // falls through on missing EF.CardAccess).
        expect(session.finishCalls, 1);
        expect(chip.getChallengeCount, 1);
        expect(chip.mseSetAtCount, 0);

        // Trace facts.
        final trace = result.trace;
        expect(trace.step, PassportReadStep.oracle);
        expect(trace.paceAttempted, isFalse);
        expect(trace.paceFailedCode, isNull);
        expect(trace.paceSw, isNull);
        expect(trace.cardAccessPresent, isFalse);
        expect(trace.paceInfos, isEmpty);
        expect(trace.sw, isNull);
        expect(trace.transceiverMaxLen, 261);
        expect(trace.transceiverExtended, isFalse);
        expect(trace.dg1Retries + trace.dg2Retries + trace.sodRetries, 0);
        expect(trace.reauthentications, isEmpty);
      },
    );

    test('COM is never read (fixed DG1->DG2->SOD list)', () async {
      // The sim serves no COM file (0x011E); a COM select would fail the
      // read. Success is the assertion.
      final chip = bacOnlyChip();
      await readOk(FakeNfcSession(chip));
    });
  });

  group('PACE session (App G.1 suite)', () {
    test('PACE succeeds: no BAC, AES SM reads, accessProtocol pace', () async {
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(),
        cardAccess: hx(cardAccessG1Hex),
        pace: paceG1Config(),
      );
      final session = FakeNfcSession(chip);
      final result = await readOk(session);

      expect(result.accessProtocol, AccessProtocol.pace);
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(chip.getChallengeCount, 0, reason: 'BAC iff PACE failed');
      expect(chip.mseSetAtCount, 1);

      final trace = result.trace;
      expect(trace.paceAttempted, isTrue);
      expect(trace.paceOid, '0.4.0.127.0.7.2.2.4.2.2');
      expect(trace.paceParameterId, 13);
      expect(trace.cardAccessPresent, isTrue);
      expect(trace.paceInfos, [
        (oid: '0.4.0.127.0.7.2.2.4.2.2', parameterId: 13),
      ]);
      expect(trace.paceFailedCode, isNull);
      expect(trace.paceSw, isNull);
      expect(trace.reauthentications, isEmpty);
    });

    test(
      'a mid-read re-authentication of a PACE session re-runs PACE',
      () async {
        final chip = paceChip(injectSw: swOnce(0x6982, dg1Read));
        final result = await readOk(FakeNfcSession(chip));

        // The session protocol stays 'pace' (the ladder's outcome).
        expect(result.accessProtocol, AccessProtocol.pace);
        expect(chip.getChallengeCount, 0, reason: 'BAC never ran');
        expect(chip.mseSetAtCount, 2, reason: 'the ladder\'s PACE + the redo');
        expect(result.trace.dg1Retries, 1);
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
        // The two selects with no READ BINARY between, then PACE.
        final plain = chip.plainInsLog;
        expect(plain.sublist(plain.length - 7), [
          0xA4,
          0xA4,
          0x22,
          0x86,
          0x86,
          0x86,
          0x86,
        ]);
        expect(chip.selectedFids.where((fid) => fid == 0x011C), hasLength(2));
        expect(result.trace.reauthentications.map(reauthView), [
          {
            'step': PassportReadStep.readDg1,
            'paceAttempted': true,
            'paceFailedCode': null,
            'paceFailedStep': null,
            'paceSw': null,
            'protocol': AccessProtocol.pace,
          },
        ]);
        expect(
          result.trace.reauthentications.single.ms,
          greaterThanOrEqualTo(0),
        );
        expect(result.trace.paceFailedCode, isNull);
      },
    );
  });

  group('ladder edges', () {
    test('PACE failure at MSE falls through to BAC (never fatal)', () async {
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(),
        cardAccess: hx(cardAccessG1Hex),
        // pace: null -> MSE:Set AT answered with 6A80.
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.accessProtocol, AccessProtocol.bac);
      expect(chip.mseSetAtCount, 1);
      expect(chip.getChallengeCount, 1);
      expect(result.trace.paceAttempted, isTrue);
      expect(result.trace.cardAccessPresent, isTrue);
      expect(result.trace.paceFailedCode, 'ResponseError');
      expect(result.trace.paceSw, '6a80');
    });

    test(
      'PACE refused 63 00, chip survives, BAC-capable -> recorded',
      () async {
        final chip = paceChip(paceTokenSw: 0x6300, mutualAuthSw: 0x6300);
        final e = await readFail(FakeNfcSession(chip));

        expect(e.step, PassportReadStep.bac);
        expect(e.cause, isA<InvalidMRZKey>());
        expect(
          e.trace.sw,
          isNull,
          reason: 'InvalidMRZKey is not a ResponseError',
        );
        expect(e.trace.paceFailedCode, 'ResponseError');
        expect(e.trace.paceSw, '6300');
        expect(e.trace.paceFailedStep, isNull);
        expect(chip.mseSetAtCount, 1);
        expect(chip.getChallengeCount, 1, reason: 'the read still reached BAC');
      },
    );

    test('PACE refused 63 00, then the tag mutes at the SELECT', () async {
      final chip = paceChip(
        paceTokenSw: 0x6300,
        injectThrow: (cmd) =>
            cmd.ins == 0xA4 && cmd.p1 == 0x04 ? const ConnectionError() : null,
      );
      final e = await readFail(FakeNfcSession(chip));

      expect(e.step, PassportReadStep.selectApp);
      expect(e.cause, isA<ConnectionError>());
      expect(e.trace.sw, isNull);
      expect(e.trace.paceSw, '6300');
      expect(e.trace.paceFailedCode, 'ResponseError');
      expect(chip.getChallengeCount, 0, reason: 'BAC never reached');
    });

    test('a PACEError records step and code, no status word', () async {
      // The chip holds a different key from the one readOk sends, so PACE
      // dies at the terminal-side token check; 63 00 on EXTERNAL AUTHENTICATE
      // then fails BAC deterministically before the differing seed matters.
      final chip = paceChip(
        mrzKey: 'L898902D<369080619406236',
        mutualAuthSw: 0x6300,
      );
      final e = await readFail(FakeNfcSession(chip));

      expect(e.trace.paceFailedStep, 'Step3 KeyAgreement');
      expect(e.trace.paceFailedCode, 'PACEError');
      expect(e.trace.paceSw, isNull);
      expect(e.step, PassportReadStep.bac);
      expect(e.cause, isA<InvalidMRZKey>());
    });

    test('selectPassportApplication failure fails the attempt', () async {
      final chip = bacOnlyChip(aidSelectSw: 0x6A82);
      final session = FakeNfcSession(chip);
      final e = await readFail(session);
      expect(e.step, PassportReadStep.selectApp);
      expect(e.cause, isA<ResponseError>());
      expect(e.trace.sw, '6a82');
      expect(chip.getChallengeCount, 0, reason: 'BAC never reached');
      expect(session.finishCalls, 1);
    });
  });

  group('per-DG retry table', () {
    test('69 82 on a DG read: redo-BAC once, retry succeeds', () async {
      var injected = false;
      final chip = bacOnlyChip(
        injectSw: (cmd) {
          if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x0101) {
            injected = true;
            return 0x6982;
          }
          return null;
        },
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.accessProtocol, AccessProtocol.bac);
      expect(chip.getChallengeCount, 2, reason: 'initial BAC + one redo');
      expect(result.trace.dg1Retries, 1);
      // A BAC session's redo is BAC alone, byte-identical at INS
      // level: the ladder's refused MF and EF.CardAccess selects, the AID,
      // BAC, then the redo's BAC.
      expect(chip.plainInsLog, [0xA4, 0xA4, 0xA4, 0x84, 0x82, 0x84, 0x82]);
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': false,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': AccessProtocol.bac,
        },
      ]);
    });

    test('69 82 twice: second failure propagates', () async {
      final chip = bacOnlyChip(
        injectSw: (cmd) =>
            (cmd.ins == 0xB0 && cmd.fid == 0x0101) ? 0x6982 : null,
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.readDg1);
      expect(e.cause, isA<ResponseError>());
      expect(e.trace.sw, '6982');
      expect(chip.getChallengeCount, 2, reason: 'no redo after final failure');
      expect(e.trace.dg1Retries, 1);
    });

    test('6E 00 is fatal to the attempt, no in-session retry', () async {
      var injected = false;
      final chip = bacOnlyChip(
        injectSw: (cmd) {
          if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x0101) {
            injected = true;
            return 0x6E00;
          }
          return null;
        },
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.readDg1);
      expect(e.trace.sw, '6e00');
      expect(chip.getChallengeCount, 1, reason: 'no redo-BAC on the fatal set');
      expect(e.trace.dg1Retries, 0);
    });

    test('67 00: reduce read amount + redo-BAC + retry', () async {
      var injected = false;
      final chip = bacOnlyChip(
        injectSw: (cmd) {
          if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x0102) {
            injected = true;
            return 0x6700;
          }
          return null;
        },
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.dg2Raw, hx(dg2Hex));
      expect(chip.getChallengeCount, 2);
      expect(result.trace.dg2Retries, 1);
    });

    test(
      'SM checksum failure: redo-BAC + retry (SM-objects-incorrect row)',
      () async {
        var corrupted = false;
        final chip = bacOnlyChip(
          corruptMac: (cmd) {
            if (!corrupted && cmd.ins == 0xB0 && cmd.fid == 0x0101) {
              corrupted = true;
              return true;
            }
            return false;
          },
        );
        final result = await readOk(FakeNfcSession(chip));
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(chip.getChallengeCount, 2);
        expect(result.trace.dg1Retries, 1);
      },
    );
  });

  group('re-authenticating a PACE session', () {
    bool dg1Select(SimCommand cmd) =>
        cmd.ins == 0xA4 && cmd.p1 == 0x02 && cmd.fid == 0x0101;

    final rows = <String, EmrtdChipSim Function()>{
      '69 82': () =>
          paceChip(mutualAuthSw: 0x6982, injectSw: swOnce(0x6982, dg1Read)),
      '6A 82': () =>
          paceChip(mutualAuthSw: 0x6982, injectSw: swOnce(0x6A82, dg1Read)),
      '67 00': () =>
          paceChip(mutualAuthSw: 0x6982, injectSw: swOnce(0x6700, dg1Read)),
      // On a READ BINARY, 62 82 is a valid partial read; only a SELECT
      // answered with it reaches the retry table.
      '62 82 (on the SELECT)': () =>
          paceChip(mutualAuthSw: 0x6982, injectSw: swOnce(0x6282, dg1Select)),
      '6B 00': () =>
          paceChip(mutualAuthSw: 0x6982, injectSw: swOnce(0x6B00, dg1Read)),
      'response MAC': () =>
          paceChip(mutualAuthSw: 0x6982, corruptMac: firstOf(dg1Read)),
      'malformed DO87': () =>
          paceChip(mutualAuthSw: 0x6982, malformDo87: firstOf(dg1Read)),
    };

    for (final MapEntry(key: row, value: build) in rows.entries) {
      test('a PACE-only chip recovers in-session from the $row row', () async {
        final chip = build();
        final result = await readOk(FakeNfcSession(chip));
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(result.trace.dg1Retries, 1);
        expect(chip.getChallengeCount, 0, reason: 'BAC never ran');
        expect(chip.mseSetAtCount, 2);
        expect(result.trace.reauthentications.map(reauthView), [
          {
            'step': PassportReadStep.readDg1,
            'paceAttempted': true,
            'paceFailedCode': null,
            'paceFailedStep': null,
            'paceSw': null,
            'protocol': AccessProtocol.pace,
          },
        ]);
      });
    }

    test('a refused re-PACE falls back to BAC after the application '
        'select', () async {
      final refuseMse = secondPlainMse();
      final refuseDg1 = swOnce(0x6982, dg1Read);
      final chip = paceChip(
        injectSw: (cmd) => refuseMse(cmd) ? 0x6A80 : refuseDg1(cmd),
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(result.accessProtocol, AccessProtocol.pace);
      expect(chip.plainInsLog.where((ins) => ins == 0x22), hasLength(2));
      expect(chip.getChallengeCount, 1);
      // MF, EF.CardAccess, the refused MSE, the AID, then BAC.
      final plain = chip.plainInsLog;
      expect(plain.sublist(plain.length - 6), [
        0xA4,
        0xA4,
        0x22,
        0xA4,
        0x84,
        0x82,
      ]);
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': true,
          'paceFailedCode': 'ResponseError',
          'paceFailedStep': null,
          'paceSw': '6a80',
          'protocol': AccessProtocol.bac,
        },
      ]);
    });

    test('once BAC has replaced the PACE session, a later '
        're-authentication is BAC alone', () async {
      final refuseMse = secondPlainMse();
      final refuseDg1 = swOnce(0x6982, dg1Read);
      final refuseDg2 = swOnce(
        0x6982,
        (cmd) => cmd.ins == 0xB0 && cmd.fid == 0x0102,
      );
      final chip = paceChip(
        injectSw: (cmd) =>
            refuseMse(cmd) ? 0x6A80 : refuseDg1(cmd) ?? refuseDg2(cmd),
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.dg2Raw, hx(dg2Hex));
      expect(
        chip.plainInsLog.where((ins) => ins == 0x22),
        hasLength(2),
        reason: 'no third PACE',
      );
      expect(chip.getChallengeCount, 2);
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': true,
          'paceFailedCode': 'ResponseError',
          'paceFailedStep': null,
          'paceSw': '6a80',
          'protocol': AccessProtocol.bac,
        },
        {
          'step': PassportReadStep.readDg2,
          'paceAttempted': false,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': AccessProtocol.bac,
        },
      ]);
    });

    test('a failed re-authentication in a data-group retry keeps that '
        'step', () async {
      final refuseMse = secondPlainMse();
      final refuseDg1 = swOnce(0x6982, dg1Read);
      final chip = paceChip(
        mutualAuthSw: 0x6982,
        injectSw: (cmd) => refuseMse(cmd) ? 0x6A80 : refuseDg1(cmd),
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.readDg1);
      expect(e.cause, isA<ResponseError>());
      expect(e.trace.sw, '6982');
      expect(e.trace.dg1Retries, 1);
      expect(e.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': true,
          'paceFailedCode': 'ResponseError',
          'paceFailedStep': null,
          'paceSw': '6a80',
          'protocol': null,
        },
      ]);
      expect(e.trace.paceFailedCode, isNull);
    });

    test('a session BAC established is redone with BAC, though the chip '
        'offered PACE', () async {
      final chip = paceChip(
        paceTokenSw: 0x6300,
        injectSw: swOnce(0x6982, dg1Read),
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.accessProtocol, AccessProtocol.bac);
      expect(chip.mseSetAtCount, 1);
      expect(chip.getChallengeCount, 2);
      expect(result.trace.paceSw, '6300', reason: 'the ladder\'s');
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': false,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': AccessProtocol.bac,
        },
      ]);
    });

    test('a re-PACE that throws outside the package vocabulary records '
        'no code and falls back to BAC', () async {
      final refuseMse = secondPlainMse();
      final chip = paceChip(
        injectSw: swOnce(0x6982, dg1Read),
        injectThrow: (cmd) => refuseMse(cmd) ? StateError('transport') : null,
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(result.accessProtocol, AccessProtocol.pace);
      expect(chip.getChallengeCount, 1);
      expect(chip.plainInsLog.where((ins) => ins == 0x22), hasLength(2));
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.readDg1,
          'paceAttempted': true,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': AccessProtocol.bac,
        },
      ]);
    });
  });

  group('oracle', () {
    test(
      'tampered DG1 vs SOD: throws with per-DG booleans on the trace',
      () async {
        final chip = bacOnlyChip(tamperedDg1: true);
        final session = FakeNfcSession(chip);
        final e = await readFail(session);
        expect(e.step, PassportReadStep.oracle);
        expect(e.cause, isNull, reason: 'the oracle-mismatch case');
        expect(session.finishCalls, 1);

        final check = e.trace.sodHashCheck;
        expect(check, isNotNull);
        expect(check!.passed, isFalse);
        expect(
          {
            for (final entry in check.dataGroupHashes.entries)
              entry.key.getName(): entry.value.match,
          },
          {'DG1': false, 'DG2': true},
        );
      },
    );
  });

  group('session lifecycle', () {
    test(
      'poll/mid-read failures cannot poison the next read (fresh session)',
      () async {
        // Poll failure: typed cause, step poll, exactly one finish.
        final polling = FakeNfcSession(
          bacOnlyChip(),
          pollError: const UserCanceled(),
        );
        final e1 = await readFail(polling);
        expect(e1.step, PassportReadStep.poll);
        expect(e1.cause, isA<UserCanceled>());
        expect(polling.finishCalls, 1);

        // Mid-read cancellation: the abort row; no in-session retry.
        stages = [];
        final chip2 = bacOnlyChip(
          injectThrow: (cmd) => (cmd.ins == 0xB0 && cmd.fid == 0x0101)
              ? const UserCanceled()
              : null,
        );
        final session2 = FakeNfcSession(chip2);
        final e2 = await readFail(session2);
        expect(e2.step, PassportReadStep.readDg1);
        expect(e2.cause, isA<UserCanceled>());
        expect(e2.trace.dg1Retries, 0, reason: 'abort class never retries');
        expect(session2.finishCalls, 1);

        // Third attempt = fresh RF session: full ladder re-runs.
        stages = [];
        final chip3 = bacOnlyChip();
        final session3 = FakeNfcSession(chip3);
        final result = await readOk(session3);
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(session3.finishCalls, 1);
      },
    );
  });

  group('DG14 probe + Chip Authentication', () {
    const caAes = '0.4.0.127.0.7.2.2.3.2.2'; // id-CA-ECDH-AES-CBC-CMAC-128
    const ca3des = '0.4.0.127.0.7.2.2.3.2.1'; // id-CA-ECDH-3DES-CBC-CBC

    EmrtdChipSim caChip({
      required String caOid,
      bool withPublicKey = true,
      int? keyId,
      int mseSw = 0x9000,
      bool viaPace = false,
      int mutualAuthSw = 0x9000,
      Uint8List? sodCoversDg14,
      int maxTransceiveLength = 261,
      Object? Function(SimCommand cmd)? injectThrow,
      bool Function(SimCommand cmd)? corruptMac,
      int? Function(SimCommand cmd)? injectSw,
      Duration? Function(SimCommand cmd)? injectDelay,
    }) {
      final dg14 = buildDg14(
        caOid: caOid,
        withPublicKey: withPublicKey,
        keyId: keyId,
      );
      return EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFilesWithDg14(dg14, sodCoversDg14: sodCoversDg14),
        cardAccess: viaPace ? hx(cardAccessG1Hex) : null,
        pace: viaPace ? paceG1Config() : null,
        ca: caConfig(caOid, mseSw: mseSw),
        mfSelectSw: viaPace ? 0x9000 : 0x6A86,
        mutualAuthSw: mutualAuthSw,
        maxTransceiveLength: maxTransceiveLength,
        injectThrow: injectThrow,
        corruptMac: corruptMac,
        injectSw: injectSw,
        injectDelay: injectDelay,
      );
    }

    test(
      'post-BAC AES suite: MSE:Set AT + GA, DGs read under the CA keys',
      () async {
        final chip = caChip(caOid: caAes);
        final result = await readOk(FakeNfcSession(chip));

        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.success,
        );
        expect(result.accessProtocol, AccessProtocol.bac);
        // The AES flow is one MSE:Set AT plus a single (unchained) GA; a
        // P-256 point wraps well under the 224-byte chunk.
        expect(chip.caMseCount, 1);
        expect(chip.caGaCount, 1);
        // The remaining files came back intact, i.e. under the new keys.
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.dg2Raw, hx(dg2Hex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(chip.getChallengeCount, 1, reason: 'no redo-BAC on success');

        final trace = result.trace;
        expect(trace.dg14Present, isTrue);
        expect(trace.caSupported, isTrue);
        expect(trace.caOid, caAes);
        expect(trace.caKeyId, isNull, reason: 'DG14 carried no keyId');
        expect(trace.caFailure, isNull);
        expect(trace.caSw, isNull);
        expect(trace.dg14Retries, 0);
        expect(result.dg14, isNotNull);
        expect(result.dg14Raw, buildDg14(caOid: caAes));
        expect(result.dg14!.securityInfos, hasLength(2));

        // Stage order: the DG14 slot sits between authenticating and DG1, the
        // DG15 probe between DG2 and SOD.
        expect(stages, [
          PassportReadStage.waitingForTag,
          PassportReadStage.authenticating,
          PassportReadStage.readingDg14,
          PassportReadStage.readingDg1,
          PassportReadStage.readingDg2,
          PassportReadStage.readingDg15,
          PassportReadStage.readingSod,
          PassportReadStage.done,
        ]);
      },
    );

    test(
      'post-PACE DESede suite: MSE:Set KAT upgrades an AES session',
      () async {
        final chip = caChip(caOid: ca3des, viaPace: true, keyId: 2);
        final result = await readOk(FakeNfcSession(chip));

        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.success,
        );
        expect(result.accessProtocol, AccessProtocol.pace);
        expect(chip.caMseCount, 1);
        expect(chip.caGaCount, 0, reason: 'the DESede flow is KAT-only');
        expect(chip.getChallengeCount, 0, reason: 'PACE session, no BAC');
        expect(result.trace.caOid, ca3des);
        expect(result.trace.caKeyId, 2);
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test(
      'a chip without DG14 answers the probe 6A82; absent, not a retry',
      () async {
        // The three-file chip has no 0x010E; a first-attempt 6A82 must NOT take
        // the retry table's redoBac row.
        final chip = bacOnlyChip();
        final result = await readOk(FakeNfcSession(chip));
        expect(result.trace.dg14Present, isFalse);
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.notDone,
        );
        expect(chip.getChallengeCount, 1, reason: 'the probe never redid BAC');
        expect(result.trace.dg14Retries, 0);
      },
    );

    test(
      'DG14 with no public key: CA is not attempted, status stays notDone',
      () async {
        final chip = caChip(caOid: caAes, withPublicKey: false);
        final result = await readOk(FakeNfcSession(chip));
        expect(result.trace.dg14Present, isTrue);
        expect(result.trace.caSupported, isFalse);
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.notDone,
        );
        expect(chip.caMseCount, 0);
        expect(result.dg14, isNotNull, reason: 'read and kept regardless');
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(result.trace.caFailure, isNull);
      },
    );

    test(
      'a failed handshake re-establishes BAC and the read completes',
      () async {
        final chip = caChip(caOid: caAes, mseSw: 0x6A80);
        final result = await readOk(FakeNfcSession(chip));

        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.failed,
        );
        expect(result.trace.caOid, isNull);
        expect(result.trace.caFailure, ChipAuthenticationFailure.chipRefused);
        expect(result.trace.caSw, '6a80');
        expect(chip.getChallengeCount, 2, reason: 'initial BAC + the CA redo');
        // Full result all the same; a CA failure never fails the read.
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.dg2Raw, hx(dg2Hex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(result.trace.reauthentications.map(reauthView), [
          {
            'step': PassportReadStep.chipAuth,
            'paceAttempted': false,
            'paceFailedCode': null,
            'paceFailedStep': null,
            'paceSw': null,
            'protocol': AccessProtocol.bac,
          },
        ]);
      },
    );

    test('on a PACE-only chip a failed handshake re-runs PACE and the '
        'read completes', () async {
      final chip = caChip(
        caOid: caAes,
        mseSw: 0x6A80,
        viaPace: true,
        mutualAuthSw: 0x6982,
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.chipAuthenticationStatus, ChipAuthenticationStatus.failed);
      expect(result.accessProtocol, AccessProtocol.pace);
      expect(chip.getChallengeCount, 0, reason: 'BAC never ran');
      expect(chip.mseSetAtCount, 2);
      expect(chip.caMseCount, 1, reason: 'CA is not re-run');
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.dg2Raw, hx(dg2Hex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(result.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.chipAuth,
          'paceAttempted': true,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': AccessProtocol.pace,
        },
      ]);
      expect(result.trace.paceFailedCode, isNull);
      // The CA cause is recorded whatever the re-authentication did.
      expect(result.trace.caFailure, ChipAuthenticationFailure.chipRefused);
      expect(result.trace.caSw, '6a80');
    });

    test('a read DG14 joins the oracle map and can fail it', () async {
      final chip = caChip(
        caOid: caAes,
        // The SOD attests a *different* DG14; the CA handshake still works.
        sodCoversDg14: buildDg14(caOid: ca3des),
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.oracle);
      expect(e.cause, isNull);
      final check = e.trace.sodHashCheck!;
      expect(check.passed, isFalse);
      expect(
        {
          for (final entry in check.dataGroupHashes.entries)
            entry.key.getName(): entry.value.match,
        },
        {'DG1': true, 'DG2': true, 'DG14': false},
      );
    });

    test(
      'skipChipAuthentication: no probe, no CA, dg14Present stays null',
      () async {
        final chip = caChip(caOid: caAes);
        final result = await PassportReader(
          session: FakeNfcSession(chip),
          skipChipAuthentication: true,
        ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

        expect(result.trace.dg14Present, isNull);
        expect(result.dg14, isNull);
        expect(result.dg14Raw, isNull);
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.notDone,
        );
        expect(chip.caMseCount, 0);
        expect(stages, isNot(contains(PassportReadStage.readingDg14)));
        // The SOD covers DG14, but an unread DG is not the oracle's business.
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test('surface: enums, default message, retry/ms trace arms', () async {
      expect(
        const PassportReaderMessages().readingDg14,
        'Reading chip security data...',
      );
      expect(
        PassportReadStep.values,
        containsAll([PassportReadStep.readDg14, PassportReadStep.chipAuth]),
      );
      expect(ChipAuthenticationStatus.values, [
        ChipAuthenticationStatus.notDone,
        ChipAuthenticationStatus.success,
        ChipAuthenticationStatus.failed,
      ]);

      // One transient 69 82 on the DG14 read takes the ordinary retry-table
      // row.
      var injected = false;
      final chip = caChip(caOid: caAes);
      final retrying = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFilesWithDg14(buildDg14(caOid: caAes)),
        ca: caConfig(caAes),
        mfSelectSw: 0x6A86,
        injectSw: (cmd) {
          if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x010E) {
            injected = true;
            return 0x6982;
          }
          return null;
        },
      );
      final result = await readOk(FakeNfcSession(retrying));
      expect(result.trace.dg14Retries, 1);
      expect(retrying.getChallengeCount, 2, reason: 'the retry redo-BAC ran');
      expect(result.chipAuthenticationStatus, ChipAuthenticationStatus.success);
      expect(chip.caMseCount, 0, reason: 'the unused sim stayed untouched');
    });

    // A cap of 88: under BAC's 3DES secure messaging the fixture key's
    // MSE:Set KAT is 91 bytes and the AES flow's GA 94, while every other
    // command of the read fits (EXTERNAL AUTHENTICATE 46, a protected SELECT
    // 27, a protected READ BINARY 19, MSE:Set AT 35).
    test('a CA command over the transport cap is refused unsent; BAC is '
        'redone and the read completes', () async {
      final chip = caChip(caOid: ca3des, maxTransceiveLength: 88);
      final result = await readOk(FakeNfcSession(chip));

      expect(result.chipAuthenticationStatus, ChipAuthenticationStatus.failed);
      expect(
        result.trace.caFailure,
        ChipAuthenticationFailure.exceedsTransceiveLength,
      );
      expect(result.trace.caSw, isNull);
      expect(chip.caMseCount, 0, reason: 'the KAT never reached the chip');
      expect(chip.getChallengeCount, 2, reason: 'initial BAC + the CA redo');
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.dg2Raw, hx(dg2Hex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(result.trace.transceiverMaxLen, 88);
    });

    test('the AES flow is refused at GENERAL AUTHENTICATE, after '
        'MSE:Set AT went out', () async {
      final chip = caChip(caOid: caAes, maxTransceiveLength: 88);
      final result = await readOk(FakeNfcSession(chip));

      expect(
        result.trace.caFailure,
        ChipAuthenticationFailure.exceedsTransceiveLength,
      );
      expect(chip.caMseCount, 1);
      expect(chip.caGaCount, 0);
      expect(result.dg1Raw, hx(dg1GoodHex));
    });

    test('a transport failure mid-handshake is transceiveFailed, and the read '
        'completes', () async {
      // BAC-only chip, so the only INS 0x22 of the read is the CA MSE.
      final chip = caChip(
        caOid: ca3des,
        injectThrow: (cmd) => cmd.ins == 0x22 ? const ConnectionError() : null,
      );
      final result = await readOk(FakeNfcSession(chip));

      expect(
        result.trace.caFailure,
        ChipAuthenticationFailure.transceiveFailed,
      );
      expect(result.trace.caSw, isNull);
      expect(chip.getChallengeCount, 2);
      expect(result.dg1Raw, hx(dg1GoodHex));
    });

    test('a CA answer that fails its MAC is responseInvalid, and the read '
        'completes', () async {
      final chip = caChip(caOid: ca3des, corruptMac: (cmd) => cmd.ins == 0x22);
      final result = await readOk(FakeNfcSession(chip));

      expect(result.trace.caFailure, ChipAuthenticationFailure.responseInvalid);
      expect(chip.getChallengeCount, 2);
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test('a PACE-only chip that refuses the re-PACE fails the attempt '
        'at bac', () async {
      final refuseMse = secondPlainMse();
      final chip = caChip(
        caOid: caAes,
        mseSw: 0x6A80,
        viaPace: true,
        mutualAuthSw: 0x6982,
        injectSw: (cmd) => refuseMse(cmd) ? 0x6A80 : null,
      );
      final e = await readFail(FakeNfcSession(chip));
      // The PACE-only-chip shape the consumer classifies.
      expect(e.step, PassportReadStep.bac);
      expect(e.cause, isA<ResponseError>());
      expect(e.trace.sw, '6982');
      expect(chip.plainInsLog.where((ins) => ins == 0x22), hasLength(2));
      expect(chip.getChallengeCount, 1);
      expect(e.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.chipAuth,
          'paceAttempted': true,
          'paceFailedCode': 'ResponseError',
          'paceFailedStep': null,
          'paceSw': '6a80',
          'protocol': null,
        },
      ]);
      // The ladder's fields record the ladder's attempt only.
      expect(e.trace.paceFailedCode, isNull);
      expect(e.trace.paceSw, isNull);
      expect(e.trace.caFailure, ChipAuthenticationFailure.chipRefused);
      expect(e.trace.caSw, '6a80');
    });

    test('a re-PACE whose application select fails ends the attempt at '
        'selectApp', () async {
      var aidSelects = 0;
      final chip = caChip(
        caOid: caAes,
        mseSw: 0x6A80,
        viaPace: true,
        // The ladder's AID select is the first; the re-PACE's is the second.
        injectSw: (cmd) =>
            cmd.ins == 0xA4 && cmd.p1 == 0x04 && ++aidSelects == 2
            ? 0x6A82
            : null,
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.selectApp);
      expect(e.trace.sw, '6a82');
      expect(chip.mseSetAtCount, 2);
      expect(chip.getChallengeCount, 0);
      expect(e.trace.reauthentications.map(reauthView), [
        {
          'step': PassportReadStep.chipAuth,
          'paceAttempted': true,
          'paceFailedCode': null,
          'paceFailedStep': null,
          'paceSw': null,
          'protocol': null,
        },
      ]);
    });

    test('caMs stops at the handshake; the re-authentication is timed '
        'on its own record', () async {
      var caMseSeen = false;
      var held = false;
      final chip = caChip(
        caOid: caAes,
        mseSw: 0x6A80,
        viaPace: true,
        injectDelay: (cmd) {
          if (cmd.isProtected && cmd.ins == 0x22) caMseSeen = true;
          if (caMseSeen && !cmd.isProtected && !held) {
            held = true;
            return const Duration(milliseconds: 500);
          }
          return null;
        },
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(held, isTrue);
      expect(result.trace.caMs, lessThan(500));
      expect(
        result.trace.reauthentications.single.ms,
        greaterThanOrEqualTo(500),
      );
    });
  });

  group('DG15 probe + Active Authentication', () {
    const caAes = '0.4.0.127.0.7.2.2.3.2.2';
    const plainSha512 = '0.4.0.127.0.7.1.1.4.1.5';

    EmrtdChipSim aaChip({
      required Uint8List dg15,
      AaSimConfig? aa,
      Uint8List? dg14,
      bool viaPace = false,
      Uint8List? sodCoversDg15,
      int? Function(SimCommand cmd)? injectSw,
    }) => EmrtdChipSim(
      mrzKey: specimenMrzInfo,
      files: specimenFilesWithDg15(
        dg15,
        dg14: dg14,
        sodCoversDg15: sodCoversDg15,
      ),
      cardAccess: viaPace ? hx(cardAccessG1Hex) : null,
      pace: viaPace ? paceG1Config() : null,
      ca: dg14 == null ? null : caConfig(caAes),
      aa: aa,
      mfSelectSw: viaPace ? 0x9000 : 0x6A86,
      injectSw: injectSw,
    );

    test(
      'RSA AA success post-BAC: status, challenge/signature, trace, stages',
      () async {
        final dg15 = buildDg15();
        final chip = aaChip(dg15: dg15, aa: aaRsaConfig());
        final result = await readOk(FakeNfcSession(chip));

        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.success,
        );
        expect(result.dg15Raw, dg15);
        expect(result.dg15!.isActiveAuthenticationSupported, isTrue);
        expect(result.activeAuthenticationChallenge, hasLength(8));
        // The signature is the full RSA_size block the chip signed.
        expect(result.activeAuthenticationSignature, hasLength(128));
        expect(chip.internalAuthCount, 1);
        expect(chip.lastAaChallenge, result.activeAuthenticationChallenge);

        final trace = result.trace;
        expect(trace.dg15Present, isTrue);
        expect(trace.aaSupported, isTrue);
        expect(trace.aaDigest, 'SHA1');
        expect(trace.dg15Retries, 0);
        expect(trace.sw, isNull);
        expect(trace.step, PassportReadStep.oracle);
        expect(trace.sodHashCheck!.passed, isTrue);

        expect(stages, [
          PassportReadStage.waitingForTag,
          PassportReadStage.authenticating,
          PassportReadStage.readingDg14,
          PassportReadStage.readingDg1,
          PassportReadStage.readingDg2,
          PassportReadStage.readingDg15,
          PassportReadStage.readingSod,
          PassportReadStage.activeAuthentication,
          PassportReadStage.done,
        ]);
      },
    );

    test('RSA AA with a two-byte trailer (34 CC -> SHA-256)', () async {
      final chip = aaChip(
        dg15: buildDg15(),
        aa: aaRsaConfig(trailer: const [0x34, 0xCC], hashAlgorithm: 'SHA256'),
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(
        result.activeAuthenticationStatus,
        ActiveAuthenticationStatus.success,
      );
      expect(result.trace.aaDigest, 'SHA256');
    });

    test('ECDSA AA success post-PACE, digest named by DG14', () async {
      final dg15 = buildDg15(rsa: false);
      final dg14 = buildDg14WithAa(signatureAlgorithmOid: plainSha512);
      final chip = aaChip(
        dg15: dg15,
        dg14: dg14,
        aa: aaEcConfig(hashAlgorithm: 'SHA512'),
        viaPace: true,
      );
      final result = await readOk(FakeNfcSession(chip));

      expect(result.accessProtocol, AccessProtocol.pace);
      expect(
        result.activeAuthenticationStatus,
        ActiveAuthenticationStatus.success,
      );
      expect(result.trace.aaDigest, 'SHA512');
      // Plain r‖s over P-256.
      expect(result.activeAuthenticationSignature, hasLength(64));
      // DG14 was read for AA's sake but carries no CA key.
      expect(result.trace.caSupported, isFalse);
      expect(result.chipAuthenticationStatus, ChipAuthenticationStatus.notDone);
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test(
      'ECDSA AA with no DG14 at all: the SHA-256 default verifies',
      () async {
        final chip = aaChip(dg15: buildDg15(rsa: false), aa: aaEcConfig());
        final result = await readOk(FakeNfcSession(chip));
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.success,
        );
        expect(result.trace.aaDigest, 'SHA256');
        expect(result.dg14, isNull);
      },
    );

    test(
      'no DG15 on the chip -> first-attempt 6A82 is absence, not retry',
      () async {
        final chip = bacOnlyChip();
        final result = await readOk(FakeNfcSession(chip));
        expect(result.trace.dg15Present, isFalse);
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.notDone,
        );
        expect(chip.getChallengeCount, 1, reason: 'the probe never redid BAC');
        expect(result.trace.dg15Retries, 0);
      },
    );

    test(
      'unparseable DG15: AA unsupported, oracle still passes on the bytes',
      () async {
        final dg15 = buildUnparseableDg15();
        final chip = aaChip(dg15: dg15, aa: aaRsaConfig());
        final result = await readOk(FakeNfcSession(chip));

        expect(result.trace.dg15Present, isTrue);
        expect(result.trace.aaSupported, isFalse);
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.notDone,
        );
        expect(chip.internalAuthCount, 0, reason: 'the guard skipped AA');
        expect(result.dg15Raw, dg15, reason: 'raw bytes kept regardless');
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(stages, isNot(contains(PassportReadStage.activeAuthentication)));
      },
    );

    test('signature that does not verify -> failed, read completes', () async {
      final chip = aaChip(
        dg15: buildDg15(),
        aa: aaRsaConfig(corruptSignature: true),
      );
      final result = await readOk(FakeNfcSession(chip));

      expect(
        result.activeAuthenticationStatus,
        ActiveAuthenticationStatus.failed,
      );
      // Full result all the same; verification failure is non-fatal on both
      // sides (upstream parity).
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.activeAuthenticationSignature, isNotNull);
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test(
      'INTERNAL AUTHENTICATE 6982 -> failed + trace.sw, read completes',
      () async {
        final chip = aaChip(
          dg15: buildDg15(),
          aa: aaRsaConfig(),
          injectSw: (cmd) => cmd.ins == 0x88 ? 0x6982 : null,
        );
        final result = await readOk(FakeNfcSession(chip));

        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.failed,
        );
        expect(result.trace.sw, '6982');
        expect(
          result.activeAuthenticationChallenge,
          isNotNull,
          reason: 'the challenge is kept even though the APDU failed',
        );
        expect(result.activeAuthenticationSignature, isNull);
        // The whole read still completes: a divergence from upstream, which
        // propagates and discards everything already read.
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.dg2Raw, hx(dg2Hex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
        expect(chip.getChallengeCount, 1, reason: 'no redo-BAC after AA');
      },
    );

    test(
      'a chip that answers INS 88 with 6D00 fails AA and finishes the read',
      () async {
        // aa: null -> the sim answers `6D 00` (instruction not supported).
        final chip = aaChip(dg15: buildDg15());
        final result = await readOk(FakeNfcSession(chip));
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.failed,
        );
        expect(result.trace.sw, '6d00');
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test('skipActiveAuthentication -> no DG15 select, no INS 88', () async {
      final chip = aaChip(dg15: buildDg15(), aa: aaRsaConfig());
      final result = await PassportReader(
        session: FakeNfcSession(chip),
        skipActiveAuthentication: true,
      ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

      expect(result.trace.dg15Present, isNull);
      expect(result.dg15, isNull);
      expect(result.dg15Raw, isNull);
      expect(
        result.activeAuthenticationStatus,
        ActiveAuthenticationStatus.notDone,
      );
      expect(chip.internalAuthCount, 0);
      expect(stages, isNot(contains(PassportReadStage.readingDg15)));
      expect(stages, isNot(contains(PassportReadStage.activeAuthentication)));
      // The SOD covers DG15, but an unread DG is not the oracle's business.
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test(
      'retry loop: a transient 6982 mid-DG15-read retries after a redo-BAC',
      () async {
        var injected = false;
        final chip = aaChip(
          dg15: buildDg15(),
          aa: aaRsaConfig(),
          injectSw: (cmd) {
            if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x010F) {
              injected = true;
              return 0x6982;
            }
            return null;
          },
        );
        final result = await readOk(FakeNfcSession(chip));
        expect(result.trace.dg15Retries, 1);
        expect(chip.getChallengeCount, 2, reason: 'initial BAC + the redo');
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.success,
        );
      },
    );

    test(
      'ordering: AA runs before the oracle, which then fails the read',
      () async {
        final chip = aaChip(
          dg15: buildDg15(),
          aa: aaRsaConfig(),
          // The SOD attests a *different* DG15; AA itself still succeeds.
          sodCoversDg15: buildDg15(rsa: false),
        );
        final e = await readFail(FakeNfcSession(chip));

        expect(e.step, PassportReadStep.oracle);
        expect(e.cause, isNull);
        expect(
          e.trace.aaDigest,
          'SHA1',
          reason: 'AA had already run when the oracle rejected the read',
        );
        final check = e.trace.sodHashCheck!;
        expect(check.passed, isFalse);
        expect(
          {
            for (final entry in check.dataGroupHashes.entries)
              entry.key.getName(): entry.value.match,
          },
          {'DG1': true, 'DG2': true, 'DG15': false},
        );
      },
    );

    test(
      'aaChallenge parameter travels to the wire and back on the result',
      () async {
        final chip = aaChip(dg15: buildDg15(), aa: aaRsaConfig());
        final fixed = hx('0011223344556677');
        final result = await PassportReader(
          session: FakeNfcSession(chip),
        ).readPassport(mrzKey: specimenMrzInfo, aaChallenge: fixed);

        expect(chip.lastAaChallenge, fixed);
        expect(result.activeAuthenticationChallenge, fixed);
        expect(
          result.activeAuthenticationStatus,
          ActiveAuthenticationStatus.success,
        );
      },
    );

    test('surface: enums, default messages, step vocabulary', () async {
      expect(
        const PassportReaderMessages().readingDg15,
        'Reading chip authenticity key...',
      );
      expect(
        const PassportReaderMessages().activeAuthentication,
        'Verifying chip authenticity...',
      );
      expect(
        PassportReadStep.values,
        containsAll([PassportReadStep.readDg15, PassportReadStep.activeAuth]),
      );
      expect(
        PassportReadStage.values,
        containsAll([
          PassportReadStage.readingDg15,
          PassportReadStage.activeAuthentication,
        ]),
      );
      expect(ActiveAuthenticationStatus.values, [
        ActiveAuthenticationStatus.notDone,
        ActiveAuthenticationStatus.success,
        ActiveAuthenticationStatus.failed,
      ]);
    });
  });

  group('opt-in extra data groups (DG7/DG11/DG12)', () {
    const dg7Fid = 0x0107;
    const dg11Fid = 0x010B;
    const dg12Fid = 0x010C;

    /// The read list without extras, written down: DG14 probe, DG1, DG2,
    /// DG15 probe, SOD (the EF.CardAccess probe precedes them on a BAC-only
    /// chip).
    const baselineFids = [0x011C, 0x010E, 0x0101, 0x0102, 0x010F, 0x011D];

    EmrtdChipSim extrasChip({
      bool withDg7 = true,
      bool withDg11 = true,
      bool withDg12 = true,
      bool sodOmitsDg7 = false,
      int? Function(SimCommand cmd)? injectSw,
    }) => EmrtdChipSim(
      mrzKey: specimenMrzInfo,
      files: specimenFilesWithExtras(
        dg7: withDg7 ? buildDg7() : null,
        dg11: withDg11 ? buildDg11() : null,
        dg12: withDg12 ? buildDg12() : null,
        sodOmitsDg7: sodOmitsDg7,
      ),
      mfSelectSw: 0x6A86,
      injectSw: injectSw,
    );

    Future<PassportReadResult> readExtras(
      EmrtdChipSim chip,
      Set<DataGroupId> extras,
    ) => PassportReader(
      session: FakeNfcSession(chip),
      extraDataGroups: extras,
    ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

    test('default (knob empty): the APDU stream is the baseline one, extras '
        'absent from result and trace', () async {
      // The chip *has* all three extras; the default read must not touch them.
      final chip = extrasChip();
      final result = await readOk(FakeNfcSession(chip));

      expect(
        chip.selectedFids,
        baselineFids,
        reason: 'no extra file may be selected with the knob at its default',
      );
      expect(result.dg7, isNull);
      expect(result.dg11, isNull);
      expect(result.dg12, isNull);
      expect(result.dg7Raw, isNull);
      expect(result.dg11Raw, isNull);
      expect(result.dg12Raw, isNull);
      expect(result.trace.extrasRequested, isEmpty);
      expect(result.trace.extrasAbsent, isEmpty);
      expect(result.trace.dg7Ms + result.trace.dg11Ms + result.trace.dg12Ms, 0);
      expect(stages, isNot(contains(PassportReadStage.readingDg7)));
      expect(stages, isNot(contains(PassportReadStage.readingDg11)));
      expect(stages, isNot(contains(PassportReadStage.readingDg12)));
      // The SOD covers all three, but an unread DG is not the oracle's
      // business (as with DG14 and DG15 under the skip flags).
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test(
      'all three requested and present: parsed, ordered, oracle-covered',
      () async {
        final chip = extrasChip();
        final result = await readExtras(chip, {
          DataGroupId.DG12,
          DataGroupId.DG7,
          DataGroupId.DG11,
        });

        // Fixed LDS order regardless of the set's iteration order.
        expect(chip.selectedFids, [
          0x011C, 0x010E, 0x0101, 0x0102, //
          dg7Fid, dg11Fid, dg12Fid, 0x010F, 0x011D,
        ]);
        expect(stages, [
          PassportReadStage.waitingForTag,
          PassportReadStage.authenticating,
          PassportReadStage.readingDg14,
          PassportReadStage.readingDg1,
          PassportReadStage.readingDg2,
          PassportReadStage.readingDg7,
          PassportReadStage.readingDg11,
          PassportReadStage.readingDg12,
          PassportReadStage.readingDg15,
          PassportReadStage.readingSod,
          PassportReadStage.done,
        ]);

        expect(result.dg7, isA<DataGroup7>());
        expect(result.dg11, isA<DataGroup11>());
        expect(result.dg12, isA<DataGroup12>());
        expect(result.dg7Raw, buildDg7());
        expect(result.dg11Raw, buildDg11());
        expect(result.dg12Raw, buildDg12());

        // The parsers ran, not just the reads.
        expect(result.dg7!.imageData, hx(dg2FaceJpegHex));
        expect(result.dg7!.imageFormat, FaceImageFormat.jpeg);
        expect(result.dg11!.fullName, 'ERIKSSON<<ANNA<MARIA');
        expect(result.dg11!.otherNames, ['SMITH<<JANE<ELIZABETH']);
        expect(result.dg12!.dateOfIssue, '20150315');
        expect(result.dg12!.otherPersons, ['ERIKSSON<<KARL']);

        final trace = result.trace;
        expect(trace.extrasRequested, [
          DataGroupId.DG7,
          DataGroupId.DG11,
          DataGroupId.DG12,
        ]);
        expect(trace.extrasAbsent, isEmpty);
        expect(trace.dg7Retries + trace.dg11Retries + trace.dg12Retries, 0);
        expect(trace.step, PassportReadStep.oracle);

        // The oracle covered all three (its strictness on extras, the other
        // way round).
        final check = trace.sodHashCheck!;
        expect(check.passed, isTrue);
        expect(
          {
            for (final entry in check.dataGroupHashes.entries)
              entry.key.getName(): entry.value.match,
          },
          {'DG1': true, 'DG2': true, 'DG7': true, 'DG11': true, 'DG12': true},
        );
      },
    );

    test('requested but absent (6A82 on select): skipped, read succeeds, no '
        'redo-BAC', () async {
      // The chip carries DG11 only; DG7/DG12 answer 6A82.
      final chip = extrasChip(withDg7: false, withDg12: false);
      final result = await readExtras(chip, {
        DataGroupId.DG7,
        DataGroupId.DG11,
        DataGroupId.DG12,
      });

      expect(result.dg7, isNull);
      expect(result.dg12, isNull);
      expect(result.dg11, isNotNull);
      expect(result.trace.extrasRequested, [
        DataGroupId.DG7,
        DataGroupId.DG11,
        DataGroupId.DG12,
      ]);
      expect(result.trace.extrasAbsent, [DataGroupId.DG7, DataGroupId.DG12]);
      expect(result.trace.dg7Retries, 0);
      expect(result.trace.dg12Retries, 0);
      expect(
        chip.getChallengeCount,
        1,
        reason: 'absence never takes the retry table\'s redo-BAC row',
      );
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test('6A82 after a redo-BAC still reads as absence (at any attempt, '
        'not only the first)', () async {
      // First DG7 read attempt: 69 82 -> redo-BAC (a real retry). Second
      // attempt: 6A 82 -> absent, skipped instead of fatal.
      var injectedSecurity = false;
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFilesWithExtras(dg7: buildDg7()),
        mfSelectSw: 0x6A86,
        injectSw: (cmd) {
          if (cmd.ins == 0xB0 && cmd.fid == dg7Fid) {
            if (!injectedSecurity) {
              injectedSecurity = true;
              return 0x6982;
            }
            return 0x6A82;
          }
          return null;
        },
      );
      final result = await readExtras(chip, {DataGroupId.DG7});

      expect(result.dg7, isNull);
      expect(result.trace.extrasAbsent, [DataGroupId.DG7]);
      expect(result.trace.dg7Retries, 1, reason: 'the 6982 took the retry row');
      expect(chip.getChallengeCount, 2, reason: 'initial BAC + the redo');
      expect(result.trace.sodHashCheck!.passed, isTrue);
    });

    test('a persistent non-absence failure on an extra is still fatal '
        '(retry-table semantics intact)', () async {
      final chip = extrasChip(
        injectSw: (cmd) =>
            (cmd.ins == 0xB0 && cmd.fid == dg11Fid) ? 0x6300 : null,
      );
      final session = FakeNfcSession(chip);
      try {
        await PassportReader(
          session: session,
          extraDataGroups: {DataGroupId.DG11},
        ).readPassport(mrzKey: specimenMrzInfo);
        fail('expected PassportReadException');
      } on PassportReadException catch (e) {
        expect(e.step, PassportReadStep.readDg11);
        expect(e.cause, isA<ResponseError>());
        expect(e.trace.sw, '6300');
        expect(e.trace.dg11Retries, 1, reason: 'plain retry, then fatal');
        expect(session.finishCalls, 1);
      }
    });

    test('an extra the SOD does not hash fails the oracle', () async {
      final chip = extrasChip(
        withDg11: false,
        withDg12: false,
        sodOmitsDg7: true,
      );
      final session = FakeNfcSession(chip);
      try {
        await PassportReader(
          session: session,
          extraDataGroups: {DataGroupId.DG7},
        ).readPassport(mrzKey: specimenMrzInfo);
        fail('expected PassportReadException');
      } on PassportReadException catch (e) {
        expect(e.step, PassportReadStep.oracle);
        expect(e.cause, isNull);
        final check = e.trace.sodHashCheck!;
        expect(check.passed, isFalse);
        // The DG7 the chip served is absent from the SOD's hash list.
        expect(check.errors, contains('DataGroup DG7 is missing!'));
      }
    });

    test(
      'subset request: only the named extra is read, order preserved',
      () async {
        final chip = extrasChip();
        final result = await readExtras(chip, {DataGroupId.DG11});

        expect(chip.selectedFids, [
          0x011C,
          0x010E,
          0x0101,
          0x0102,
          dg11Fid,
          0x010F,
          0x011D,
        ]);
        expect(result.dg7, isNull);
        expect(result.dg12, isNull);
        expect(result.dg11, isNotNull);
        expect(result.trace.extrasRequested, [DataGroupId.DG11]);
        expect(result.trace.extrasAbsent, isEmpty);
        expect(result.trace.dg11Ms, greaterThanOrEqualTo(0));
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test('an id outside {DG7, DG11, DG12} is ArgumentError at '
        'construction', () {
      for (final bad in [
        DataGroupId.DG14,
        DataGroupId.DG1,
        DataGroupId.SOD,
        DataGroupId.DG3,
        DataGroupId.Unknown,
      ]) {
        expect(
          () => PassportReader(extraDataGroups: {bad}),
          throwsA(isA<ArgumentError>()),
          reason: '${bad.getName()} must be rejected',
        );
      }
      // The supported set constructs fine (no session touched).
      expect(
        () => PassportReader(
          extraDataGroups: const {
            DataGroupId.DG7,
            DataGroupId.DG11,
            DataGroupId.DG12,
          },
        ),
        returnsNormally,
      );
    });

    test('surface: stages, steps, default messages', () {
      const messages = PassportReaderMessages();
      expect(messages.readingDg7, 'Reading passport data...');
      expect(messages.readingDg11, 'Reading passport data...');
      expect(messages.readingDg12, 'Reading passport data...');
      expect(
        PassportReadStage.values,
        containsAll([
          PassportReadStage.readingDg7,
          PassportReadStage.readingDg11,
          PassportReadStage.readingDg12,
        ]),
      );
      expect(
        PassportReadStep.values,
        containsAll([
          PassportReadStep.readDg7,
          PassportReadStep.readDg11,
          PassportReadStep.readDg12,
        ]),
      );
    });
  });

  // -------------------------------------------------------------------------
  // The opt-in on-device passive-authentication step.
  // -------------------------------------------------------------------------
  group('passive authentication on the read', () {
    EmrtdChipSim paChip({Uint8List? sod, bool tamperedDg1 = false}) =>
        EmrtdChipSim(
          mrzKey: specimenMrzInfo,
          files: pkiSpecimenFiles(sod: sod, tamperedDg1: tamperedDg1),
          mfSelectSw: 0x6A86,
        );

    Future<PassportReadResult> readWithStore(
      EmrtdChipSim chip,
      CscaTrustStore store, {
      EmrtdRandom? random,
    }) => PassportReader(
      session: FakeNfcSession(chip),
      trustStore: store,
      random: random,
    ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

    /// RND.IFD(8) + K.IFD(16), fixed so two reads of the same chip produce a
    /// byte-identical BAC handshake and therefore a byte-identical stream.
    EmrtdRandom fixedBacRandom() =>
        FixedRandom(List<int>.generate(24, (i) => (i * 7 + 3) & 0xFF));

    test('default (trustStore null): APDU stream byte-identical, '
        'result.passiveAuth null', () async {
      final without = paChip();
      final resultWithout = await PassportReader(
        session: FakeNfcSession(without),
        random: fixedBacRandom(),
      ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);
      expect(resultWithout.passiveAuth, isNull);
      expect(resultWithout.trace.passiveAuthMs, 0);
      expect(
        resultWithout.trace.step,
        PassportReadStep.oracle,
        reason: 'the last step reached is still the oracle',
      );

      // The same chip read *with* a store must issue exactly the same
      // commands: passive authentication is local compute after the read.
      final with_ = paChip();
      final resultWith = await readWithStore(
        with_,
        CscaTrustStore.fromPem(trustPemDefault),
        random: fixedBacRandom(),
      );
      expect(with_.commandLog.length, without.commandLog.length);
      for (var i = 0; i < without.commandLog.length; i++) {
        expect(
          with_.commandLog[i],
          without.commandLog[i],
          reason: 'command $i must be byte-identical',
        );
      }
      expect(with_.selectedFids, without.selectedFids);
      expect(resultWith.sodRaw, resultWithout.sodRaw);
      expect(resultWith.dg1Raw, resultWithout.dg1Raw);
    });

    test(
      'authentic chip + trusting store: verdict verified, trace stamped',
      () async {
        final chip = paChip();
        final result = await readWithStore(
          chip,
          CscaTrustStore.fromPem(trustPemDefault),
        );

        final pa = result.passiveAuth!;
        expect(
          pa.outcome,
          PassiveAuthOutcome.verified,
          reason: pa.signature.detail ?? pa.trust?.detail,
        );
        expect(pa.cause, isNull);
        expect(pa.signature.valid, isTrue);
        expect(pa.trust!.trusted, isTrue);
        expect(pa.documentSigningCertificate!.subject, contains('DS RSA 001'));
        expect(pa.countrySigningCertificate!.subject, contains('CSCA RSA'));
        // The hash half is the oracle's result, reused rather than recomputed.
        expect(identical(pa.hashCheck, result.trace.sodHashCheck), isTrue);
        expect(pa.passportDataNotTampered, isTrue);
        expect(pa.documentSigningCertificateVerified, isTrue);
        expect(pa.passportCorrectlySigned, isTrue);
        // Step order: ... -> oracle -> passiveAuth. No new stage or alert.
        expect(result.trace.step, PassportReadStep.passiveAuth);
        expect(result.trace.passiveAuthMs, greaterThanOrEqualTo(0));
        expect(stages.last, PassportReadStage.done);
        expect(stages.where((s) => s == PassportReadStage.done), hasLength(1));
      },
    );

    test(
      'unknown CSCA: the read SUCCEEDS with an unverifiable verdict',
      () async {
        final chip = paChip();
        final result = await readWithStore(chip, CscaTrustStore.fromPem(''));

        final pa = result.passiveAuth!;
        expect(pa.outcome, PassiveAuthOutcome.unverifiable);
        expect(pa.cause, PassiveAuthCause.unknownCsca);
        // Never throws; the consumer decides what an unverifiable document
        // means.
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(pa.signature.valid, isTrue);
        expect(pa.passportCorrectlySigned, isFalse);
      },
    );

    test('corrupted SOD signature: the read succeeds, verdict '
        'invalid/bad_ds_signature', () async {
      final chip = paChip(sod: sodCorruptSignature);
      final result = await readWithStore(
        chip,
        CscaTrustStore.fromPem(trustPemDefault),
      );

      final pa = result.passiveAuth!;
      expect(pa.outcome, PassiveAuthOutcome.invalid);
      expect(pa.cause, PassiveAuthCause.badDsSignature);
      expect(pa.documentSigningCertificateVerified, isFalse);
      // The chain still built: upstream's boolean triple, computable.
      expect(pa.passportCorrectlySigned, isTrue);
      expect(pa.passportDataNotTampered, isTrue);
    });

    test(
      'a SOD the port cannot model at all is malformed_sod, not a throw',
      () async {
        // The vectors' SOD fixture: a two-element stand-in SignerInfo.
        final chip = EmrtdChipSim(
          mrzKey: specimenMrzInfo,
          files: specimenFiles(),
          mfSelectSw: 0x6A86,
        );
        final result = await readWithStore(
          chip,
          CscaTrustStore.fromPem(trustPemDefault),
        );
        expect(result.passiveAuth!.outcome, PassiveAuthOutcome.invalid);
        expect(result.passiveAuth!.cause, PassiveAuthCause.malformedSod);
      },
    );

    test('a tampered DG still throws at the oracle, before PA', () async {
      final chip = paChip(tamperedDg1: true);
      try {
        await readWithStore(chip, CscaTrustStore.fromPem(trustPemDefault));
        fail('expected the oracle to fail the read');
      } on PassportReadException catch (e) {
        expect(e.step, PassportReadStep.oracle);
        expect(e.trace.sodHashCheck!.passed, isFalse);
        expect(
          e.trace.passiveAuthMs,
          0,
          reason: 'the PA step never ran: the oracle throw fires first',
        );
      }
    });

    test('surface: passive auth adds exactly one step-enum member', () {
      expect(PassportReadStep.values.last, PassportReadStep.passiveAuth);
      expect(
        PassportReadStep.values.indexOf(PassportReadStep.passiveAuth),
        PassportReadStep.values.indexOf(PassportReadStep.oracle) + 1,
      );
      // No new stage and no new alert message (local compute, the oracle
      // precedent).
      expect(PassportReadStage.values.last, PassportReadStage.done);
    });
  });

  group('PACE-CAM verification', () {
    const caAes = '0.4.0.127.0.7.2.2.3.2.2'; // id-CA-ECDH-AES-CBC-CMAC-128

    /// A CAM-negotiating chip. Its static CA key defaults to the one
    /// `buildDg14` publishes, so the 9303-11 §4.4.3.5.2 equation holds (the
    /// CAM key *is* the CA key).
    EmrtdChipSim camChip({
      BigInt? staticPrivateKey,
      Uint8List? camDataObject,
      bool omitCamDataObject = false,
      bool withPublicKey = true,
      int? keyId,
      String? caOid = caAes,
    }) {
      final dg14 = buildDg14(
        caOid: caOid,
        withPublicKey: withPublicKey,
        keyId: keyId,
      );
      return EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFilesWithDg14(dg14),
        cardAccess: hx(cardAccessCamHex),
        pace: paceCamConfig(
          staticPrivateKey: staticPrivateKey,
          camDataObject: camDataObject,
          omitCamDataObject: omitCamDataObject,
        ),
        ca: caOid == null ? null : caConfig(caOid),
        mfSelectSw: 0x9000,
      );
    }

    test(
      'verified: DG14 key matches, status + camKeyId land on the surface',
      () async {
        final chip = camChip(keyId: 7);
        final result = await readOk(FakeNfcSession(chip));

        expect(result.paceCamStatus, PaceCamStatus.verified);
        expect(result.trace.camKeyId, 7);
        expect(result.accessProtocol, AccessProtocol.pace);
        expect(result.trace.paceOid, '0.4.0.127.0.7.2.2.4.6.2');
        // CA still runs afterwards; no skip-CA optimization.
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.success,
        );
        // The read itself is untouched.
        expect(result.dg1Raw, hx(dg1GoodHex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test('a DG14 entry with no keyId verifies with camKeyId null', () async {
      final result = await readOk(FakeNfcSession(camChip()));
      expect(result.paceCamStatus, PaceCamStatus.verified);
      expect(result.trace.camKeyId, isNull);
    });

    test('failed: the chip proves a DIFFERENT key than DG14 publishes '
        '(the clone shape), and the read still succeeds', () async {
      final chip = camChip(
        staticPrivateKey: BigInt.parse(
          '5f2b1c8e3a7d4906b1e2c3d4a5f60718293a4b5c6d7e8f9012a3b4c5d6e7f801',
          radix: 16,
        ),
      );
      final result = await readOk(FakeNfcSession(chip));

      expect(result.paceCamStatus, PaceCamStatus.failed);
      expect(result.trace.camKeyId, isNull);
      // Surface, never gate. Everything else about the read is normal.
      expect(result.dg1Raw, hx(dg1GoodHex));
      expect(result.trace.sodHashCheck!.passed, isTrue);
      expect(result.chipAuthenticationStatus, ChipAuthenticationStatus.success);
    });

    test(
      'failed: an absent DO8A on a CAM session (extraction mapping)',
      () async {
        final result = await readOk(
          FakeNfcSession(camChip(omitCamDataObject: true)),
        );
        expect(
          result.paceCamStatus,
          PaceCamStatus.failed,
          reason:
              '9303-11 §4.4.5 makes the DO8A mandatory under CAM, so its '
              'absence is never benign',
        );
        expect(result.dg1Raw, hx(dg1GoodHex));
      },
    );

    test('failed: an undecryptable DO8A (extraction mapping)', () async {
      final result = await readOk(
        FakeNfcSession(
          camChip(camDataObject: Uint8List.fromList(List.filled(48, 0xAB))),
        ),
      );
      expect(result.paceCamStatus, PaceCamStatus.failed);
      expect(result.dg1Raw, hx(dg1GoodHex));
    });

    test(
      'noMatchingKey: DG14 carries no ChipAuthenticationPublicKeyInfo',
      () async {
        final result = await readOk(
          FakeNfcSession(camChip(withPublicKey: false)),
        );
        expect(result.paceCamStatus, PaceCamStatus.noMatchingKey);
        expect(result.trace.dg14Present, isTrue);
        expect(result.trace.caSupported, isFalse);
      },
    );

    test('noMatchingKey: no DG14 on the chip at all', () async {
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(), // no 0x010E
        cardAccess: hx(cardAccessCamHex),
        pace: paceCamConfig(),
        mfSelectSw: 0x9000,
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.paceCamStatus, PaceCamStatus.noMatchingKey);
      expect(result.trace.dg14Present, isFalse);
    });

    test(
      'skipped: skipChipAuthentication means there is no key to check',
      () async {
        final session = FakeNfcSession(camChip());
        final result = await PassportReader(
          session: session,
          skipChipAuthentication: true,
        ).readPassport(mrzKey: specimenMrzInfo);

        expect(result.paceCamStatus, PaceCamStatus.skipped);
        expect(result.trace.dg14Present, isNull);
        expect(
          result.chipAuthenticationStatus,
          ChipAuthenticationStatus.notDone,
        );
      },
    );

    test(
      'an extraction failure still reads `failed` under '
      'skipChipAuthentication: the DO8A anomaly is independent of DG14',
      () async {
        final session = FakeNfcSession(camChip(omitCamDataObject: true));
        final result = await PassportReader(
          session: session,
          skipChipAuthentication: true,
        ).readPassport(mrzKey: specimenMrzInfo);
        expect(result.paceCamStatus, PaceCamStatus.failed);
      },
    );

    test('notApplicable: a non-CAM PACE session', () async {
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(),
        cardAccess: hx(cardAccessG1Hex),
        pace: paceG1Config(),
      );
      final result = await readOk(FakeNfcSession(chip));
      expect(result.accessProtocol, AccessProtocol.pace);
      expect(result.paceCamStatus, PaceCamStatus.notApplicable);
      expect(result.trace.camKeyId, isNull);
    });

    test('notApplicable: a BAC session', () async {
      final result = await readOk(FakeNfcSession(bacOnlyChip()));
      expect(result.accessProtocol, AccessProtocol.bac);
      expect(result.paceCamStatus, PaceCamStatus.notApplicable);
    });

    test(
      'notApplicable: PACE negotiated CAM but failed; BAC took over',
      () async {
        // The chip advertises the CAM suite but refuses MSE:Set AT, so the
        // ladder's PACE catch-all falls through to BAC and no CAM material
        // exists.
        final chip = EmrtdChipSim(
          mrzKey: specimenMrzInfo,
          files: specimenFilesWithDg14(buildDg14(caOid: caAes)),
          cardAccess: hx(cardAccessCamHex),
          ca: caConfig(caAes),
          mfSelectSw: 0x9000,
          paceMseSw: 0x6A80,
        );
        final result = await readOk(FakeNfcSession(chip));
        expect(result.accessProtocol, AccessProtocol.bac);
        expect(result.paceCamStatus, PaceCamStatus.notApplicable);
      },
    );

    test('the CAM check adds no stage, step or message', () async {
      final stagesSeen = <PassportReadStage>[];
      await reader(
        FakeNfcSession(camChip()),
      ).readPassport(mrzKey: specimenMrzInfo, onStage: stagesSeen.add);
      // Exactly the stage sequence of a read without CAM: the verify hides
      // inside the DG14 stage because it is sub-millisecond local math.
      expect(stagesSeen, [
        PassportReadStage.waitingForTag,
        PassportReadStage.authenticating,
        PassportReadStage.readingDg14,
        PassportReadStage.readingDg1,
        PassportReadStage.readingDg2,
        PassportReadStage.readingDg15,
        PassportReadStage.readingSod,
        PassportReadStage.done,
      ]);
      expect(PassportReadStage.values.last, PassportReadStage.done);
    });
  });

  group('per-chunk progress seam', () {
    /// The alert sequence of a default-knob BAC-only read, which sends no
    /// progress alerts: one `setAlertMessage` per data group. The DG14 and
    /// DG15 probes both send their alert before the `6A 82`; the specimen has
    /// no DG15, so no AA alert follows.
    const nullCaseAlerts = <String>[
      'Hold your iPhone against the passport photo page',
      'Authenticating with the chip...',
      'Reading chip security data...',
      'Reading passport data...',
      'Reading passport photo...',
      'Reading chip authenticity key...',
      'Verifying chip signature data...',
    ];

    /// The stages that name a data-group read, the only ones a progress
    /// value may carry.
    const dgStages = <PassportReadStage>{
      PassportReadStage.readingDg14,
      PassportReadStage.readingDg1,
      PassportReadStage.readingDg2,
      PassportReadStage.readingDg7,
      PassportReadStage.readingDg11,
      PassportReadStage.readingDg12,
      PassportReadStage.readingDg15,
      PassportReadStage.readingSod,
    };

    /// Twelve chunks over the 96-byte DG2 fixture instead of one.
    const eightByteChunks = ReadQuirks(maxReadLength: 8);

    /// `amountRead` of 2, 10, ..., 90 over 96 bytes.
    const dg2Trajectory = <int>[2, 10, 18, 27, 35, 43, 52, 60, 68, 77, 85, 93];

    Future<(PassportReadResult, List<(PassportReadStage, int)>)>
    readWithProgress(
      FakeNfcSession session, {
      ReadQuirks quirks = ReadQuirks.none,
      PassportReaderMessages messages = const PassportReaderMessages(),
    }) async {
      final progress = <(PassportReadStage, int)>[];
      final result =
          await PassportReader(
            session: session,
            quirks: quirks,
            messages: messages,
          ).readPassport(
            mrzKey: specimenMrzInfo,
            onStage: stages.add,
            onProgress: (stage, percent) => progress.add((stage, percent)),
          );
      return (result, progress);
    }

    List<int> dg2Of(List<(PassportReadStage, int)> progress) => [
      for (final (stage, percent) in progress)
        if (stage == PassportReadStage.readingDg2) percent,
    ];

    test(
      'null onProgress + null progressAlert: the alert sequence is unchanged',
      () async {
        final session = FakeNfcSession(bacOnlyChip());
        await readOk(session);
        expect(session.alerts, nullCaseAlerts);
      },
    );

    test('ticks carry DG stages only, in read order, non-decreasing per '
        'stage, all < 100; nothing fires for EF.CardAccess', () async {
      // A PACE chip, so EF.CardAccess is really read before any DG stage.
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(),
        cardAccess: hx(cardAccessG1Hex),
        pace: paceG1Config(),
      );
      // One interleaved log of stage callbacks and progress ticks.
      final events = <Object>[];
      final result = await PassportReader(session: FakeNfcSession(chip))
          .readPassport(
            mrzKey: specimenMrzInfo,
            onStage: events.add,
            onProgress: (stage, percent) => events.add((stage, percent)),
          );
      expect(result.trace.cardAccessPresent, isTrue);
      final progress = events.whereType<(PassportReadStage, int)>().toList();
      expect(progress, isNotEmpty);

      for (final (stage, percent) in progress) {
        expect(dgStages, contains(stage));
        expect(percent, lessThan(100));
      }
      // The CardAccess read precedes even `authenticating`; the first tick
      // lands after it, under the first DG whose file is actually read (the
      // absent DG14 is refused at select and never reaches a chunk).
      expect(
        events.indexWhere((e) => e is (PassportReadStage, int)),
        greaterThan(events.indexOf(PassportReadStage.authenticating)),
      );
      expect(progress.first.$1, PassportReadStage.readingDg1);
      // Every tick sits after its own stage callback and before the next one.
      for (var i = 0; i < events.length; i++) {
        final e = events[i];
        if (e is! (PassportReadStage, int)) continue;
        final lastStage = events
            .sublist(0, i)
            .lastWhere((x) => x is PassportReadStage);
        expect(lastStage, e.$1, reason: 'tick $e under stage $lastStage');
      }
      for (var i = 1; i < progress.length; i++) {
        if (progress[i].$1 == progress[i - 1].$1) {
          expect(progress[i].$2, greaterThanOrEqualTo(progress[i - 1].$2));
        }
      }
      // On the default chunk size the 96-byte DG2 is a single chunk.
      expect(dg2Of(progress), [2]);
    });

    test(
      'the eight-byte chunk trajectory is upstream\'s formula, no 100',
      () async {
        final (_, progress) = await readWithProgress(
          FakeNfcSession(bacOnlyChip()),
          quirks: eightByteChunks,
        );
        expect(dg2Of(progress), dg2Trajectory);
      },
    );

    test('a redo-BAC retry restarts the DG2 sequence; no clamp', () async {
      var injected = false;
      final chip = bacOnlyChip(
        injectSw: (cmd) {
          final pastHeader = ((cmd.p1 << 8) | cmd.p2) > 2;
          if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x0102 && pastHeader) {
            injected = true;
            return 0x6982;
          }
          return null;
        },
      );
      final (result, progress) = await readWithProgress(
        FakeNfcSession(chip),
        quirks: eightByteChunks,
      );
      expect(result.trace.dg2Retries, 1);
      final dg2 = dg2Of(progress);
      expect(dg2, [2, 10, ...dg2Trajectory]);
      final decreases = [
        for (var i = 1; i < dg2.length; i++)
          if (dg2[i] < dg2[i - 1]) i,
      ];
      expect(decreases, hasLength(1), reason: 'the restart is visible');
    });

    test(
      'formatter texts are deduped and sent inside the DG2 window',
      () async {
        final session = FakeNfcSession(bacOnlyChip());
        await readWithProgress(
          session,
          quirks: eightByteChunks,
          messages: const PassportReaderMessages(progressAlert: _photoDecile),
        );

        final start = session.alerts.indexOf('Reading passport photo...');
        final end = session.alerts.indexOf('Reading chip authenticity key...');
        expect(start, greaterThanOrEqualTo(0));
        expect(end, greaterThan(start));
        // Twelve callbacks, ten distinct deciles.
        expect(session.alerts.sublist(start + 1, end), [
          for (var decile = 0; decile <= 90; decile += 10)
            'Reading passport photo... $decile%',
        ]);
        expect([
          ...session.alerts.sublist(0, start + 1),
          ...session.alerts.sublist(end),
        ], nullCaseAlerts);
      },
    );

    test('a formatter that always returns null sends nothing', () async {
      final session = FakeNfcSession(bacOnlyChip());
      await readWithProgress(
        session,
        quirks: eightByteChunks,
        messages: PassportReaderMessages(progressAlert: (_, __, ___) => null),
      );
      expect(session.alerts, nullCaseAlerts);
    });

    test(
      'a formatter that hands the stage string back sends nothing',
      () async {
        final session = FakeNfcSession(bacOnlyChip());
        await readWithProgress(
          session,
          quirks: eightByteChunks,
          messages: PassportReaderMessages(
            progressAlert: (_, message, __) => message,
          ),
        );
        expect(session.alerts, nullCaseAlerts);
      },
    );

    for (final sync in [false, true]) {
      test(
        'a progress send that fails ${sync ? 'synchronously' : 'asynchronously'} '
        'is dropped; the read still succeeds, one finish',
        () async {
          final session = _ProgressRejectingSession(bacOnlyChip(), sync: sync);
          final (result, progress) = await readWithProgress(
            session,
            quirks: eightByteChunks,
            messages: const PassportReaderMessages(progressAlert: _photoDecile),
          );
          expect(result.dg2Raw, hx(dg2Hex));
          expect(dg2Of(progress), dg2Trajectory);
          expect(session.finishCalls, 1);
          expect(session.alerts, nullCaseAlerts);
        },
      );
    }
  });

  group('read profile, chunk fit, ladder, DG2 accounting', () {
    final largeDg2 = buildLargeDg2();
    final body = largeDg2.length - 4;

    /// The READ BINARY Le sequence of one whole-file read at [chunk]: the
    /// 4-byte header read, then full chunks and the remainder.
    List<int> leSequence(int chunk) => [
      4,
      for (var remaining = body; remaining > 0; remaining -= chunk)
        remaining < chunk ? remaining : chunk,
    ];

    EmrtdChipSim largeChip({
      int? Function(SimCommand cmd)? injectSw,
      bool Function(SimCommand cmd)? corruptMac,
    }) => EmrtdChipSim(
      mrzKey: specimenMrzInfo,
      files: specimenFiles(dg2: largeDg2),
      mfSelectSw: 0x6A86,
      injectSw: injectSw,
      corruptMac: corruptMac,
    );

    List<int> dg2Les(EmrtdChipSim chip) => [
      for (final r in chip.readBinaryLog)
        if (r.fid == 0x0102) r.le,
    ];

    List<int> dg2Offsets(EmrtdChipSim chip) => [
      for (final r in chip.readBinaryLog)
        if (r.fid == 0x0102) r.offset,
    ];

    Future<PassportReadResult> readWith(
      EmrtdChipSim chip, {
      ReadProfile profile = ReadProfile.standard,
      ReadQuirks quirks = ReadQuirks.none,
    }) => PassportReader(
      session: FakeNfcSession(chip),
      readProfile: profile,
      quirks: quirks,
    ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

    /// One-shot injection on the first DG2 chunk of [le] bytes.
    int? Function(SimCommand) refuseFirstChunk(int le, int sw) {
      var injected = false;
      return (cmd) {
        if (!injected && cmd.ins == 0xB0 && cmd.fid == 0x0102 && cmd.le == le) {
          injected = true;
          return sw;
        }
        return null;
      };
    }

    test('the fixture is really multi-chunk', () {
      expect(largeDg2.length, 1078);
      expect(leSequence(0xA0), [4, 160, 160, 160, 160, 160, 160, 114]);
      expect(leSequence(0xDF), [4, 223, 223, 223, 223, 182]);
    });

    test('conservative: upstream\'s sequence, 0xA0 chunks', () async {
      final chip = largeChip();
      final result = await readWith(chip, profile: ReadProfile.conservative);
      expect(result.dg2Raw, largeDg2);
      expect(dg2Les(chip), leSequence(0xA0));
      expect(dg2Offsets(chip), [0, 4, 164, 324, 484, 644, 804, 964]);
      expect(result.trace.dg2ChunkSize, 0xA0);
      expect(result.trace.dg2Chunks, 8);
      expect(result.trace.dg2Bytes, 1078);
      expect(result.trace.dg2Retries, 0);
      expect(chip.getChallengeCount, 1);
    });

    test(
      'standard (the default): 0xDF chunks, same files, fewer commands',
      () async {
        final conservative = largeChip();
        await readWith(conservative, profile: ReadProfile.conservative);
        final standard = largeChip();
        final result = await readWith(standard);
        expect(result.dg2Raw, largeDg2);
        expect(dg2Les(standard), leSequence(0xDF));
        expect(dg2Offsets(standard), [0, 4, 227, 450, 673, 896]);
        expect(result.trace.dg2ChunkSize, 0xDF);
        expect(result.trace.dg2Chunks, 6);
        expect(result.trace.dg2Bytes, 1078);

        // The two profiles differ only in READ BINARY Le/offset/count: same
        // select list, same non-read command sequence.
        expect(standard.selectedFids, conservative.selectedFids);
        expect(standard.plainInsLog, conservative.plainInsLog);
        List<int> nonReads(EmrtdChipSim c) => [
          for (final cmd in c.commandLog)
            if (cmd[1] != 0xB0) cmd[1],
        ];
        expect(nonReads(standard), nonReads(conservative));
        expect(
          standard.readBinaryLog.length,
          lessThan(conservative.readBinaryLog.length),
        );
        expect(
          PassportReader(session: FakeNfcSession(largeChip())).readProfile,
          ReadProfile.standard,
        );
      },
    );

    test(
      'extended reads exactly as standard until phase 3 wires the gate',
      () async {
        final chip = largeChip();
        final result = await readWith(chip, profile: ReadProfile.extended);
        expect(dg2Les(chip), leSequence(0xDF));
        expect(result.trace.dg2ChunkSize, 0xDF);
      },
    );

    test('ReadQuirks.maxReadLength wins over the profile', () async {
      final chip = largeChip();
      final result = await readWith(
        chip,
        quirks: const ReadQuirks(maxReadLength: 0xE7),
      );
      expect(dg2Les(chip), leSequence(0xE7));
      expect(result.trace.dg2ChunkSize, 0xE7);
    });

    test('a transport cap below the chunk is honoured at read time', () async {
      // 200 bytes of frame under 3DES fits a 175-byte plaintext:
      // 1 + 2 + (1 + 176) + 4 + 10 + 2 = 196.
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(dg2: largeDg2),
        mfSelectSw: 0x6A86,
        maxTransceiveLength: 200,
      );
      final result = await readWith(chip);
      expect(result.dg2Raw, largeDg2);
      expect(dg2Les(chip).skip(1).first, 175);
      expect(result.trace.dg2ChunkSize, 175);
      expect(result.trace.transceiverMaxLen, 200);
    });

    test(
      '6B 00 on the first 223 chunk: shrink + redo-BAC, then 0xA0',
      () async {
        final chip = largeChip(injectSw: refuseFirstChunk(0xDF, 0x6B00));
        final result = await readWith(chip);
        expect(result.dg2Raw, largeDg2);
        expect(chip.getChallengeCount, 2, reason: 'initial BAC + one redo');
        expect(result.trace.dg2Retries, 1);
        expect(dg2Les(chip), [4, 223, ...leSequence(0xA0)]);
        expect(
          result.trace.dg2ChunkSize,
          0xDF,
          reason: 'the chunk the first attempt began with',
        );
        expect(result.trace.dg2Chunks, 2 + 8);
        expect(result.trace.dg2Bytes, 1078);
        // Per-session: the shrink does not outlive the TagReader.
        final fresh = largeChip();
        await readWith(fresh);
        expect(dg2Les(fresh), leSequence(0xDF));
      },
    );

    test('67 00 and 69 82 shrink too (the redo-BAC rows)', () async {
      for (final sw in [0x6700, 0x6982]) {
        final chip = largeChip(injectSw: refuseFirstChunk(0xDF, sw));
        final result = await readWith(chip);
        expect(chip.getChallengeCount, 2, reason: sw.toRadixString(16));
        expect(dg2Les(chip), [4, 223, ...leSequence(0xA0)]);
        expect(result.trace.dg2Retries, 1);
      }
    });

    test('the plain-retry row shrinks without a redo-BAC', () async {
      final chip = largeChip(injectSw: refuseFirstChunk(0xDF, 0x6F00));
      final result = await readWith(chip);
      expect(result.dg2Raw, largeDg2);
      expect(chip.getChallengeCount, 1, reason: 'no redo-BAC on 6F 00');
      expect(dg2Les(chip), [4, 223, ...leSequence(0xA0)]);
      expect(result.trace.dg2Retries, 1);
    });

    test('the SM-integrity row shrinks and redoes BAC', () async {
      var corrupted = false;
      final chip = largeChip(
        corruptMac: (cmd) {
          if (!corrupted &&
              cmd.ins == 0xB0 &&
              cmd.fid == 0x0102 &&
              cmd.le == 0xDF) {
            corrupted = true;
            return true;
          }
          return false;
        },
      );
      final result = await readWith(chip);
      expect(chip.getChallengeCount, 2);
      expect(dg2Les(chip), [4, 223, ...leSequence(0xA0)]);
      expect(result.trace.dg2Retries, 1);
    });

    test('the shrink is a floor: a retried 0xA0 read stays at 0xA0', () async {
      // First 223 chunk refused, then the first 160 chunk of the retry too:
      // two attempts, the second at 0xA0, and the error propagates.
      var refused = 0;
      final chip = largeChip(
        injectSw: (cmd) {
          if (cmd.ins == 0xB0 &&
              cmd.fid == 0x0102 &&
              cmd.le != 4 &&
              refused < 2) {
            refused++;
            return 0x6982;
          }
          return null;
        },
      );
      final e = await readFail(FakeNfcSession(chip));
      expect(e.step, PassportReadStep.readDg2);
      expect(dg2Les(chip), [4, 223, 4, 160]);
      expect(e.trace.dg2Retries, 1);
      expect(e.trace.dg2ChunkSize, 0xDF);
      expect(e.trace.dg2Chunks, 4);
      expect(e.trace.dg2Bytes, 0, reason: 'no successful attempt');
    });

    test(
      'a read that never reaches DG2 leaves the DG2 accounting empty',
      () async {
        final chip = largeChip(
          injectSw: (cmd) =>
              (cmd.ins == 0xB0 && cmd.fid == 0x0101) ? 0x6E00 : null,
        );
        final e = await readFail(FakeNfcSession(chip));
        expect(e.step, PassportReadStep.readDg1);
        expect(e.trace.dg2ChunkSize, isNull);
        expect(e.trace.dg2Chunks, 0);
        expect(e.trace.dg2Bytes, 0);
      },
    );

    test('PACE (AES) session: 223 chunks fit the 261-byte frame too', () async {
      final chip = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(dg2: largeDg2),
        cardAccess: hx(cardAccessG1Hex),
        pace: paceG1Config(),
      );
      final result = await readWith(chip);
      expect(result.accessProtocol, AccessProtocol.pace);
      expect(result.dg2Raw, largeDg2);
      expect(dg2Les(chip), leSequence(0xDF));
      expect(result.trace.dg2Chunks, 6);
    });
  });

  group('probeChipBuffers (the chip-capability census)', () {
    const atrInfoFid = 0x2F01;
    final ats = hx('80318066b184');

    EmrtdChipSim chip({
      Uint8List? atrInfo,
      Uint8List? historicalBytes,
      int mfSelectSw = 0x6A86,
      bool pace = false,
    }) => EmrtdChipSim(
      mrzKey: specimenMrzInfo,
      files: {...specimenFiles(), if (atrInfo != null) atrInfoFid: atrInfo},
      cardAccess: pace ? hx(cardAccessG1Hex) : null,
      pace: pace ? paceG1Config() : null,
      mfSelectSw: mfSelectSw,
      historicalBytes: historicalBytes,
    );

    Future<PassportReadResult> read(EmrtdChipSim chip, {bool probe = true}) =>
        PassportReader(
          session: FakeNfcSession(chip),
          probeChipBuffers: probe,
        ).readPassport(mrzKey: specimenMrzInfo, onStage: stages.add);

    test('default off: no EF.ATR/INFO select, census fields null', () async {
      final c = chip(atrInfo: buildAtrInfo(), historicalBytes: ats);
      final result = await read(c, probe: false);
      expect(c.selectedFids, isNot(contains(atrInfoFid)));
      expect(
        c.selectedFids.first,
        0x011C,
        reason: 'the stream opens exactly as it does without the census',
      );
      expect(result.trace.atrInfoPresent, isNull);
      expect(result.trace.chipMaxCommandBytes, isNull);
      expect(result.trace.chipMaxResponseBytes, isNull);
      expect(result.trace.chipBufferSource, isNull);
      expect(result.trace.atrInfoMs, 0);
      expect(
        result.trace.atsHistoricalBytes,
        ats,
        reason: 'the raw ATS is a poll fact, recorded regardless',
      );
    });

    test(
      'file present: read before EF.CardAccess, sizes on the trace',
      () async {
        final c = chip(
          atrInfo: buildAtrInfo(
            maxCommandBytes: 0x0400,
            maxResponseBytes: 0x0600,
          ),
        );
        final result = await read(c);
        expect(c.selectedFids.take(2), [atrInfoFid, 0x011C]);
        expect(result.trace.atrInfoPresent, isTrue);
        expect(result.trace.chipMaxCommandBytes, 0x0400);
        expect(result.trace.chipMaxResponseBytes, 0x0600);
        expect(result.trace.chipBufferSource, ChipBufferSource.atrInfo);
        expect(result.trace.atrInfoMs, greaterThanOrEqualTo(0));
        // The probe is pre-auth and unprotected; the read itself is unchanged.
        expect(c.getChallengeCount, 1);
        expect(result.dg2Raw, hx(dg2Hex));
        expect(result.trace.sodHashCheck!.passed, isTrue);
      },
    );

    test('file absent (6A 82): never fatal, present=false', () async {
      final c = chip();
      final result = await read(c);
      expect(c.selectedFids.first, atrInfoFid);
      expect(result.trace.atrInfoPresent, isFalse);
      expect(result.trace.chipBufferSource, isNull);
      expect(result.trace.chipMaxResponseBytes, isNull);
      expect(c.getChallengeCount, 1);
    });

    test('file present but without a 7F66: present=true, sizes null', () async {
      final c = chip(atrInfo: Uint8List.fromList([0x43, 0x01, 0x00]));
      final result = await read(c);
      expect(result.trace.atrInfoPresent, isTrue);
      expect(result.trace.chipBufferSource, isNull);
      expect(result.trace.chipMaxCommandBytes, isNull);
    });

    test('an MF select the fallback does not cover reads as absent', () async {
      final c = chip(atrInfo: buildAtrInfo(), mfSelectSw: 0x6F00);
      final result = await read(c);
      expect(result.trace.atrInfoPresent, isFalse);
      expect(result.accessProtocol, AccessProtocol.bac);
    });

    test(
      'the ATS is the fallback source; the file wins when both state sizes',
      () async {
        final atsWithTemplate = buildAtrInfo(
          maxCommandBytes: 0x0100,
          maxResponseBytes: 0x0200,
        );
        final fromAts = await read(chip(historicalBytes: atsWithTemplate));
        expect(fromAts.trace.atrInfoPresent, isFalse);
        expect(fromAts.trace.chipBufferSource, ChipBufferSource.ats);
        expect(fromAts.trace.chipMaxResponseBytes, 0x0200);
        expect(fromAts.trace.atsHistoricalBytes, atsWithTemplate);

        final both = await read(
          chip(
            atrInfo: buildAtrInfo(
              maxCommandBytes: 0x0800,
              maxResponseBytes: 0x0800,
            ),
            historicalBytes: atsWithTemplate,
          ),
        );
        expect(both.trace.chipBufferSource, ChipBufferSource.atrInfo);
        expect(both.trace.chipMaxResponseBytes, 0x0800);
      },
    );

    test(
      'a COMPACT-TLV ATS states nothing; the raw bytes are still recorded',
      () async {
        final result = await read(chip(historicalBytes: ats));
        expect(result.trace.chipBufferSource, isNull);
        expect(result.trace.atsHistoricalBytes, ats);
      },
    );

    test(
      'PACE chip: the probe precedes EF.CardAccess and PACE still runs',
      () async {
        final c = chip(atrInfo: buildAtrInfo(), pace: true);
        final result = await read(c);
        expect(c.selectedFids.take(2), [atrInfoFid, 0x011C]);
        expect(result.accessProtocol, AccessProtocol.pace);
        expect(result.trace.atrInfoPresent, isTrue);
        expect(result.trace.chipBufferSource, ChipBufferSource.atrInfo);
      },
    );

    test('the polled tag\'s capabilities land on the trace', () async {
      final caps = TagCapabilities(
        type: 'iso7816',
        standard: 'ISO 14443-4 (Type B)',
        protocolInfo: hx('a1b2c3'),
        applicationData: hx('01020304'),
      );
      final c = EmrtdChipSim(
        mrzKey: specimenMrzInfo,
        files: specimenFiles(),
        tagCapabilities: caps,
      );
      final result = await read(c, probe: false);
      expect(
        result.trace.tagCapabilities,
        same(caps),
        reason: 'a poll fact, recorded whether or not the census probe runs',
      );
      expect(result.trace.tagCapabilities!.standard, 'ISO 14443-4 (Type B)');
      expect(result.trace.atsHistoricalBytes, isNull);

      final none = await read(chip(historicalBytes: ats), probe: false);
      expect(
        none.trace.tagCapabilities,
        isNull,
        reason: 'a transport that reports nothing leaves the field null',
      );
      expect(none.trace.atsHistoricalBytes, ats);
    });
  });

  group('an ISO/IEC 39794-5 DG2', () {
    EmrtdChipSim chip(String dg2) => EmrtdChipSim(
      mrzKey: specimenMrzInfo,
      files: specimenFiles(dg2: hx(dg2)),
      mfSelectSw: 0x6A86,
    );

    test('reads to completion, face and format as for 19794-5', () async {
      final result = await readOk(FakeNfcSession(chip(dg2Iso39794Hex)));
      expect(result.dg2.encoding, FaceRecordEncoding.iso39794);
      expect(result.faceImage, hx(dg2FaceJpegHex));
      expect(result.faceImageFormat, FaceImageFormat.jpeg);
      expect(result.dg2Raw, hx(dg2Iso39794Hex));
      expect(result.trace.dg2Retries, 0);
      expect(
        result.trace.sodHashCheck!.dataGroupHashes.keys,
        contains(DataGroupId.DG2),
      );
    });

    test(
      'outside the profile: fails at readDg2, named, after one retry',
      () async {
        final e = await readFail(FakeNfcSession(chip(dg2Iso39794Shape3dHex)));
        expect(e.step, PassportReadStep.readDg2);
        expect(
          e.cause,
          isA<NotYetSupported>().having(
            (c) => c.reason,
            'reason',
            'ISO/IEC 39794-5 DG2 outside the ICAO profile: 3D representation',
          ),
        );
        expect(e.trace.dg2Retries, 1);
      },
    );
  });

  group('NFC availability', () {
    test('nfcAvailability + isNfcAvailable delegate to the session', () async {
      final present = reader(FakeNfcSession(bacOnlyChip()));
      expect(await present.nfcAvailability(), NfcAvailability.available);
      expect(await present.isNfcAvailable(), isTrue);

      final absent = reader(FakeNfcSession(bacOnlyChip(), available: false));
      expect(await absent.nfcAvailability(), NfcAvailability.notSupported);
      expect(await absent.isNfcAvailable(), isFalse);
    });
  });
}

/// The consumer-shaped formatter: DG2 only, rounded down to the decile.
String? _photoDecile(PassportReadStage stage, String message, int percent) =>
    stage == PassportReadStage.readingDg2
    ? '$message ${percent ~/ 10 * 10}%'
    : null;

/// Accepts the thirteen stage strings and rejects every other text (the
/// progress texts) either by throwing synchronously or by returning a failed
/// future, so both of `PassportReader`'s drop paths are exercised.
class _ProgressRejectingSession extends FakeNfcSession {
  _ProgressRejectingSession(super.transceiver, {required this.sync});

  final bool sync;

  static const _defaults = PassportReaderMessages();
  static final Set<String> _stageStrings = {
    _defaults.pollPrompt,
    _defaults.authenticating,
    _defaults.readingDg14,
    _defaults.readingDg1,
    _defaults.readingDg2,
    _defaults.readingDg7,
    _defaults.readingDg11,
    _defaults.readingDg12,
    _defaults.readingDg15,
    _defaults.readingSod,
    _defaults.activeAuthentication,
    _defaults.finishSuccess,
    _defaults.finishError,
  };

  @override
  Future<void> setAlertMessage(String message) {
    if (_stageStrings.contains(message)) return super.setAlertMessage(message);
    if (sync) throw StateError('sheet gone: $message');
    return Future<void>.error(StateError('sheet gone: $message'));
  }
}
