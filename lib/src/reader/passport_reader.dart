// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/PassportReader.swift @ 3bf5456 (2.3.2)
//   minus the CoreNFC session/alert-UI surface (replaced by the NfcSession
//   seam; the app owns classification copy). The behavior is an audited
//   behavioral port of upstream's orchestration.

/// Package-level read orchestration. The plug-and-play entry point upstream
/// ships as `PassportReader.swift`: the session ladder (CardAccess -> PACE
/// catch-all -> re-select AID -> BAC-iff-needed), the DG14-probe + Chip
/// Authentication slot (default ON), the fixed DG1 -> DG2 -> (opt-in
/// DG7/DG11/DG12) -> DG15 read list with no COM read (the extras extend the
/// fixed set, they do not make it COM-driven), the typed per-DG retry loop
/// (every retry shrinks the read chunk), the Active Authentication step after
/// the SOD read (default ON), the SOD hash oracle with fail-the-read
/// semantics, the opt-in on-device passive-authentication step behind
/// `trustStore` (default OFF; verdict-on-result, never fail-the-read), and
/// the NFC session lifecycle over the [NfcSession] seam.
///
/// Mechanism only: no error *classification* and no user-facing copy beyond
/// the injectable iOS alert strings ([PassportReaderMessages]). Everything the
/// read observed lands in [PassportReadTrace] so a consumer can build its own
/// telemetry/policy: e.g. a PACE-only document that refuses BAC is detectable
/// from `(step == bac, trace.cardAccessPresent, trace.paceAttempted,
/// sw ∈ {6982, 6A88})` without the package classifying it.
library;

import 'dart:typed_data';

import '../crypto/rng.dart';
import '../errors.dart';
import '../lds/card_access.dart';
import '../lds/chip_authentication_public_key_info.dart';
import '../lds/data_group.dart';
import '../lds/data_group1.dart';
import '../lds/data_group11.dart';
import '../lds/data_group12.dart';
import '../lds/data_group14.dart';
import '../lds/data_group15.dart';
import '../lds/data_group2.dart';
import '../lds/data_group7.dart';
import '../lds/data_group_id.dart';
import '../lds/data_group_parser.dart';
import '../lds/pace_info.dart';
import '../lds/security_info.dart';
import '../lds/sod.dart';
import '../lds/sod_hash_oracle.dart';
import '../lds/subject_public_key_info.dart';
import '../logging.dart';
import '../pki/csca_trust_store.dart';
import '../pki/passive_auth.dart';
import '../proto/active_authentication.dart';
import '../proto/bac.dart';
import '../proto/chip_authentication.dart';
import '../proto/pace.dart';
import '../lds/atr_info.dart';
import '../proto/read_quirks.dart';
import '../proto/tag_reader.dart';
import '../transport/nfc_kit_transceiver.dart';
import '../transport/nfc_session.dart';
import '../transport/transceiver.dart';
import 'read_profile.dart';

/// Progress stages surfaced through `readPassport`'s `onStage` callback at
/// operation boundaries, and attached to every `onProgress`
/// value so a percent never has to be correlated with the last stage seen.
enum PassportReadStage {
  waitingForTag,
  authenticating,

  /// The DG14 read *and* the CA handshake run under this stage (upstream
  /// shows a DG14 progress message and nothing CA-specific).
  readingDg14,
  readingDg1,
  readingDg2,

  /// The opt-in extras, read in this fixed LDS order after DG2
  /// whenever `extraDataGroups` names them. All three default to the same
  /// neutral message; a consumer that wants distinct copy injects it.
  readingDg7,
  readingDg11,
  readingDg12,

  /// The DG15 read: upstream shows a DG15 progress message and,
  /// separately, `.activeAuthentication` for the handshake below.
  readingDg15,
  readingSod,

  /// INTERNAL AUTHENTICATE + the signature check.
  activeAuthentication,
  done,
}

/// Where in the read the attempt is (the failing step on a throw, the last
/// step reached on success). Wire/telemetry names stay consumer-side (the
/// app's `ChipReadStep` carries the snake_case values).
enum PassportReadStep {
  poll,
  cardAccess,
  pace,
  selectApp,
  bac,
  readDg14,
  chipAuth,
  readDg1,
  readDg2,
  readDg7,
  readDg11,
  readDg12,
  readDg15,
  readSod,
  activeAuth,
  oracle,

  /// The on-device passive-authentication step, reached only when
  /// a `trustStore` was supplied. Local compute, no chip interaction, so it
  /// has no stage and no alert message of its own (the [oracle] precedent).
  passiveAuth,
}

/// Which access-control protocol established the secure-messaging session.
enum AccessProtocol { bac, pace }

/// Outcome of the Chip Authentication slot. Upstream reuses its
/// shared `PassportAuthenticationStatus`; the port dedicates an enum: it has
/// no BAC/PACE status fields to share with ([AccessProtocol] covers those).
enum ChipAuthenticationStatus {
  /// CA was not attempted: `skipChipAuthentication`, no DG14 on the chip, or
  /// a DG14 carrying no `ChipAuthenticationPublicKeyInfo`.
  notDone,
  success,

  /// The handshake threw; the session was re-established and the read
  /// continued (a CA failure never fails the read by itself).
  /// `trace.caFailure` says why, and `trace.reauthentications` how the
  /// session was re-established.
  failed,
}

/// Outcome of the PACE Chip Authentication Mapping check: the 9303-11
/// §4.4.3.5.2 verification of the DO8A the CAM session delivered, against the
/// chip's own DG14 key.
///
/// **It never gates the read**: every value below,
/// `failed` included, reaches the consumer on a successful
/// [PassportReadResult]. What a `failed` means for onboarding is consumer /
/// backend policy, exactly as for CA and AA.
///
/// Note (9303-11 §4.4.3.5.2): "Passive Authentication MUST be performed in
/// combination with the Chip Authentication Mapping". A `verified` here
/// proves the chip holds the private key for a DG14 public key; that the DG14
/// itself is genuine comes from passive authentication (`passiveAuth` with a
/// trust store, or the backend's).
enum PaceCamStatus {
  /// No CAM check applied: the session came from BAC, PACE negotiated a
  /// non-CAM (GM/IM) suite, or PACE failed altogether.
  notApplicable,

  /// A CAM session completed, but `skipChipAuthentication` meant DG14 was
  /// never read, so there was no key to verify against.
  skipped,

  /// DG14 was absent, carried no `ChipAuthenticationPublicKeyInfo`, or none
  /// of its EC keys sit on the PACE curve.
  noMatchingKey,

  /// PK_Map,IC = CA_IC·PK_IC held for a DG14 key: the chip proved
  /// possession of that key's private half. `trace.camKeyId` names the key.
  verified,

  /// The check ran and did not hold: either candidate keys existed and none
  /// matched, or the session's DO8A was missing/undecryptable so the math
  /// could not run at all (9303-11 §4.4.5 makes the DO8A mandatory under
  /// CAM, so its absence is never benign).
  failed,
}

/// Outcome of the Active Authentication slot. Upstream carries a
/// bare `activeAuthenticationPassed` bool plus an
/// `activeAuthenticationSupported` getter; the port dedicates an enum, as it
/// does for CA (vocabulary divergence, recorded in UPSTREAM.md).
enum ActiveAuthenticationStatus {
  /// AA was not attempted: `skipActiveAuthentication`, no DG15 on the chip,
  /// or a DG15 whose key the port could not use ([DataGroup15.publicKey]
  /// null).
  notDone,
  success,

  /// The chip refused INTERNAL AUTHENTICATE or the signature did not
  /// verify. Either way the read completed; whether that should fail
  /// onboarding is consumer policy.
  failed,
}

/// Where the chip-capability census found the chip's stated APDU buffer
/// sizes. EF.ATR/INFO wins when both carry the `7F66` template.
enum ChipBufferSource { atrInfo, ats }

/// iOS system-sheet strings, injectable for localization; defaults are the
/// port's own copy. Thirteen constant strings plus the optional
/// [progressAlert] formatter, which composes per-chunk progress text for the
/// sheet out of the stage's own string.
class PassportReaderMessages {
  const PassportReaderMessages({
    this.pollPrompt = 'Hold your iPhone against the passport photo page',
    this.authenticating = 'Authenticating with the chip...',
    this.readingDg14 = 'Reading chip security data...',
    this.readingDg1 = 'Reading passport data...',
    this.readingDg2 = 'Reading passport photo...',
    this.readingDg7 = 'Reading passport data...',
    this.readingDg11 = 'Reading passport data...',
    this.readingDg12 = 'Reading passport data...',
    this.readingDg15 = 'Reading chip authenticity key...',
    this.readingSod = 'Verifying chip signature data...',
    this.activeAuthentication = 'Verifying chip authenticity...',
    this.finishSuccess = 'Done',
    this.finishError = 'Could not read the passport',
    this.progressAlert,
  });

  final String pollPrompt;
  final String authenticating;

  /// Shown for the DG14 read and the CA handshake.
  final String readingDg14;
  final String readingDg1;
  final String readingDg2;

  /// Shown for the opt-in DG7/DG11/DG12 reads. The package has no idea what
  /// an extra means to a consumer's UX, so all three default to the neutral
  /// DG1 wording.
  final String readingDg7;
  final String readingDg11;
  final String readingDg12;

  /// Shown for the DG15 read.
  final String readingDg15;
  final String readingSod;

  /// Shown for the INTERNAL AUTHENTICATE + verify step (upstream's
  /// `NFCViewDisplayMessage.activeAuthentication` reads "Authenticating.....",
  /// noted in UPSTREAM.md: the port keeps its own copy voice).
  final String activeAuthentication;

  /// `finish` iosAlertMessage on success / iosErrorMessage on failure.
  final String finishSuccess;
  final String finishError;

  /// Optional. Called on every progress callback of every data group with
  /// the stage, that stage's own alert string and the raw percent. Return
  /// the text the sheet should now show, or null to leave it as it is.
  /// Consecutive identical texts are sent once, and a text equal to the
  /// stage's own string is never re-sent. The send is not awaited and its
  /// errors are dropped. iOS only: Android's `setIosAlertMessage` is a no-op
  /// that still crosses the platform channel, so consumers should leave this
  /// null on Android.
  final String? Function(
    PassportReadStage stage,
    String stageMessage,
    int percent,
  )?
  progressAlert;
}

/// Everything the read observed, mutated in place as the read
/// progresses and shared by reference with the result/exception, so a
/// consumer can compose its telemetry record on success *and* failure
/// without the package knowing the schema.
class PassportReadTrace {
  /// Last step reached (== the failing step when the read threw).
  PassportReadStep step = PassportReadStep.poll;

  /// EF.CardAccess was served and parsed.
  bool cardAccessPresent = false;

  /// Every PACEInfo EF.CardAccess advertised (protocol OID + parameter id).
  List<({String oid, int? parameterId})> paceInfos = const [];

  /// The PACEInfo the handler selected (upstream first-wins).
  String? paceOid;
  int? paceParameterId;

  bool paceAttempted = false;

  /// `PACEError.step` when PACE failed: a fixed label, not free text.
  String? paceFailedStep;

  /// `EmrtdException.code` of whatever ended the PACE attempt, or null when
  /// PACE was never attempted or succeeded. Set for **every** typed cause,
  /// unlike [paceFailedStep], which only ever holds a `PACEError`'s step.
  ///
  /// Populated on successful reads too: a chip that refuses PACE and then
  /// succeeds under BAC carries both this and [paceSw] on a success result.
  String? paceFailedCode;

  /// The status word the chip answered the failing PACE command with, as 4
  /// lowercase hex chars, when [paceFailedCode] is `ResponseError`; null
  /// otherwise.
  ///
  /// Which command produced it is deliberately not recorded. A
  /// `63 00` or `63 CX` here can only have come from the final GENERAL
  /// AUTHENTICATE; the ambiguous status words are not attributable without
  /// the INS.
  String? paceSw;

  /// Whether the chip served EF.DG14: `null` when it was never probed
  /// (`skipChipAuthentication`), false when the probe's first attempt
  /// answered `6A 82`.
  bool? dg14Present;

  /// DG14 carried at least one `ChipAuthenticationPublicKeyInfo`.
  bool caSupported = false;

  /// The CA protocol OID the successful handshake used; null otherwise.
  String? caOid;

  /// The chip key id the successful handshake used, as DG14 carried it
  /// (null when the entry had none: the handler treats that as key 0).
  int? caKeyId;

  /// Why the handshake failed when `chipAuthenticationStatus` is `failed`,
  /// as a closed set, never free text; null otherwise. Recorded
  /// before the re-authentication, so it also rides a read that the
  /// re-authentication then fails.
  ChipAuthenticationFailure? caFailure;

  /// The status word the chip refused the handshake with, as 4 lowercase
  /// hex chars (the [sw] shape), when [caFailure] is `chipRefused`; null
  /// otherwise.
  String? caSw;

  /// The DG14 key id the CAM verification matched, as DG14 carried it, set
  /// only when `paceCamStatus` is `verified`, and null there too when the
  /// matching entry carried no keyId.
  int? camKeyId;

  /// Whether the chip served EF.DG15: `null` when it was never probed
  /// (`skipActiveAuthentication`), false when the probe's first attempt
  /// answered `6A 82`.
  bool? dg15Present;

  /// DG15 was read and carried a key the port can verify with.
  bool aaSupported = false;

  /// The digest the AA verification used (`SHA1`...`SHA512`): the AA
  /// verifier's diagnostic field; null when AA never got as far as choosing
  /// one.
  String? aaDigest;

  /// The extras `PassportReader.extraDataGroups` asked for, in the fixed
  /// read order; empty when the knob was left at its default.
  List<DataGroupId> extrasRequested = const [];

  /// The subset of [extrasRequested] the chip answered `6A 82` for, so the
  /// read skipped them. A `null` extra on the result means "not
  /// requested **or** absent"; this list is what disambiguates.
  List<DataGroupId> extrasAbsent = [];

  /// Last status word as 4 hex chars when the failure was a `ResponseError`;
  /// the typed error itself travels on `PassportReadException.cause`.
  String? sw;

  /// The transport's caps, recorded once the poll returns.
  int? transceiverMaxLen;
  bool? transceiverExtended;

  /// The polled tag's ISO-DEP historical bytes, raw, when the transport
  /// knows them, the device-matrix column.
  Uint8List? atsHistoricalBytes;

  /// What the transport's poll response said about the tag:
  /// type, standard, ATQA/SAK or ATQB fields, when it reports them.
  TagCapabilities? tagCapabilities;

  /// The chip-capability census, populated only under
  /// `PassportReader(probeChipBuffers: true)`; every field stays null
  /// otherwise. [atrInfoPresent] is whether EF.ATR/INFO was served;
  /// [chipMaxCommandBytes]/[chipMaxResponseBytes] are the chip's stated
  /// APDU buffer sizes from the `7F66` template, [chipBufferSource] where
  /// they came from, all three null when neither the file nor the ATS
  /// states them.
  bool? atrInfoPresent;
  int? chipMaxCommandBytes;
  int? chipMaxResponseBytes;
  ChipBufferSource? chipBufferSource;

  /// Time spent in the EF.ATR/INFO probe (0 when it never ran).
  int atrInfoMs = 0;

  /// READ BINARY accounting for the DG2 read, the file where
  /// chunk size decides the read's duration. [dg2ChunkSize] is the fitted
  /// chunk (`fitReadLength`) in force when the first attempt began, null
  /// when no DG2 attempt reached its header read; after a mid-read shrink
  /// `dg2Retries ≥ 1` tells the story. [dg2Chunks] counts every READ BINARY
  /// the read loop issued for DG2 across all attempts, the 4-byte header
  /// read included (SELECT and re-authentication excluded). [dg2Bytes] is
  /// the file length the successful attempt returned, 0 on failure. `dg2Ms /
  /// dg2Chunks` is the per-chunk cost; two chunk sizes on one device
  /// separate its fixed and per-byte parts.
  int? dg2ChunkSize;
  int dg2Chunks = 0;
  int dg2Bytes = 0;

  int totalMs = 0;
  int cardAccessMs = 0;
  int paceMs = 0;
  int bacMs = 0;
  int dg14Ms = 0;

  /// Time spent inside `doChipAuthentication` (0 when CA never ran). The
  /// re-authentication a failed handshake triggers is not part of it; its
  /// time is on its `reauthentications` entry.
  int caMs = 0;
  int dg1Ms = 0;
  int dg2Ms = 0;
  int dg7Ms = 0;
  int dg11Ms = 0;
  int dg12Ms = 0;
  int dg15Ms = 0;
  int sodMs = 0;

  /// Time spent in the AA step: INTERNAL AUTHENTICATE plus the verify
  /// (0 when AA never ran).
  int aaMs = 0;

  /// Per-DG in-session retry counts (the retry loop).
  int dg14Retries = 0;
  int dg1Retries = 0;
  int dg2Retries = 0;
  int dg7Retries = 0;
  int dg11Retries = 0;
  int dg12Retries = 0;
  int dg15Retries = 0;
  int sodRetries = 0;

  /// Every in-session re-authentication, in the order they ran;
  /// empty when the read needed none. Each entry is added when its
  /// re-authentication ends, so one whose throw ended the attempt is the last
  /// entry on the exception's trace, with a null `protocol`.
  List<SessionReauthentication> reauthentications = [];

  /// Time spent in the passive-authentication step: the CMS signature check
  /// plus DSC->CSCA path building (0 when no `trustStore` was supplied and the
  /// step never ran).
  int passiveAuthMs = 0;

  /// null = the oracle never ran; on a `PassportReadResult` it is always
  /// present and passed (a failed oracle throws instead).
  SODHashCheckResult? sodHashCheck;
}

/// One in-session re-authentication: the secure-messaging session
/// re-established after a failed Chip Authentication, or after a data-group
/// read failure the retry table answers with a new session.
class SessionReauthentication {
  const SessionReauthentication({
    required this.step,
    required this.paceAttempted,
    required this.paceFailedCode,
    required this.paceFailedStep,
    required this.paceSw,
    required this.protocol,
    required this.ms,
  });

  /// What called for it: `chipAuth` after a failed handshake, or the
  /// data-group step whose first attempt failed.
  final PassportReadStep step;

  /// Whether it tried PACE, which it does when the session it replaced came
  /// from PACE. The ladder's own attempt is
  /// `PassportReadTrace.paceAttempted`.
  final bool paceAttempted;

  /// `EmrtdException.code` of whatever ended its PACE attempt; null when it
  /// did not try PACE, PACE succeeded, or the throw was not an
  /// `EmrtdException`. The vocabulary of `PassportReadTrace.paceFailedCode`,
  /// which records the ladder's attempt only.
  final String? paceFailedCode;

  /// `PACEError.step` when [paceFailedCode] is `PACEError`; null otherwise.
  final String? paceFailedStep;

  /// The status word the chip refused PACE with, as 4 lowercase hex chars,
  /// when [paceFailedCode] is `ResponseError`; null otherwise.
  final String? paceSw;

  /// The protocol that re-established the session: `pace`, or `bac` when the
  /// session came from BAC or PACE failed and BAC followed. Null
  /// when neither did, and its throw ended the attempt.
  final AccessProtocol? protocol;

  /// Wall time from its first command to its last, in milliseconds.
  final int ms;
}

/// A completed read: the parsed files, their raw bytes, and the [trace].
class PassportReadResult {
  PassportReadResult({
    required this.dg1,
    required this.dg2,
    required this.sod,
    required this.dg14,
    required this.dg15,
    required this.dg7,
    required this.dg11,
    required this.dg12,
    required this.accessProtocol,
    required this.paceCamStatus,
    required this.chipAuthenticationStatus,
    required this.activeAuthenticationStatus,
    required this.activeAuthenticationChallenge,
    required this.activeAuthenticationSignature,
    required this.passiveAuth,
    required this.trace,
  });

  final DataGroup1 dg1;
  final DataGroup2 dg2;
  final SOD sod;

  /// The chip's security infos: null when DG14 was absent or the probe was
  /// skipped (`skipChipAuthentication`). Present regardless of whether CA
  /// itself succeeded.
  final DataGroup14? dg14;

  /// The chip's Active Authentication public key: null when DG15 was absent
  /// or the probe was skipped (`skipActiveAuthentication`). Present
  /// regardless of whether AA itself succeeded.
  final DataGroup15? dg15;

  /// The displayed signature / usual mark: null when DG7 was not requested
  /// (`extraDataGroups`) **or** the chip does not carry it; `trace`'s
  /// `extrasRequested`/`extrasAbsent` disambiguate.
  final DataGroup7? dg7;

  /// Additional personal details: null on the same terms as [dg7].
  /// `Dg11Fields.from(dg11)` is the typed view.
  final DataGroup11? dg11;

  /// Additional document details: null on the same terms as [dg7].
  /// `Dg12Fields.from(dg12)` is the typed view.
  final DataGroup12? dg12;

  /// Full file bytes, exactly as read.
  Uint8List get dg1Raw => dg1.data;
  Uint8List get dg2Raw => dg2.data;
  Uint8List get sodRaw => sod.data;
  Uint8List? get dg14Raw => dg14?.data;
  Uint8List? get dg15Raw => dg15?.data;
  Uint8List? get dg7Raw => dg7?.data;
  Uint8List? get dg11Raw => dg11?.data;
  Uint8List? get dg12Raw => dg12?.data;

  /// `dg2.imageData`: may be empty on a pathological chip; rejecting that
  /// is consumer policy, applied post-read.
  Uint8List get faceImage => dg2.imageData;

  FaceImageFormat get faceImageFormat => dg2.faceImageFormat;

  /// The protocol the session ladder established. A later re-authentication
  /// does not change it; `trace.reauthentications` records those.
  final AccessProtocol accessProtocol;

  /// Whether the PACE session's Chip Authentication Mapping proof verified
  /// against DG14. `notApplicable` on every non-CAM read. It is a
  /// **surface, never a gate**: a `failed` arrives on a successful
  /// read and what to do about it is consumer policy.
  final PaceCamStatus paceCamStatus;

  /// Whether Chip Authentication ran and what it concluded.
  /// Whether a `failed` here should fail the read is consumer policy; the
  /// package continues, exactly as upstream does.
  final ChipAuthenticationStatus chipAuthenticationStatus;

  /// Whether Active Authentication ran and what it concluded.
  /// Fail-vs-warn is consumer/backend policy, exactly as for CA.
  final ActiveAuthenticationStatus activeAuthenticationStatus;

  /// The 8-byte challenge sent to the chip (upstream model-field parity);
  /// null when AA never ran.
  final Uint8List? activeAuthenticationChallenge;

  /// The chip's signature over that challenge (upstream model-field parity);
  /// null when AA never ran **or** the INTERNAL AUTHENTICATE APDU failed
  /// (recorded, and the read continues).
  final Uint8List? activeAuthenticationSignature;

  /// The on-device passive-authentication verdict, `null` unless
  /// `PassportReader(trustStore: ...)` was given a store. It is a **verdict,
  /// not a failure**: `invalid` and `unverifiable` reach the consumer on a
  /// successful read, exactly as upstream's `verifyPassport` never throws.
  /// Whether an unverified document should be rejected is consumer policy.
  ///
  /// Its cause is never `dgHashMismatch`: the SOD hash oracle throws on a
  /// hash mismatch before this step runs.
  final PassiveAuthResult? passiveAuth;

  /// == `trace.totalMs` (stamped when the read completes).
  int get durationMs => trace.totalMs;

  /// `sodHashCheck` is always present and passed here.
  final PassportReadTrace trace;
}

/// The single failure surface of `readPassport`. [cause] is the typed
/// error; it is null for the oracle-mismatch case (`step == oracle`,
/// `trace.sodHashCheck` carries the per-DG booleans) and for the defensive
/// wrap of a non-typed error (a bug: `message` carries the diagnostics).
class PassportReadException implements Exception {
  const PassportReadException({
    this.cause,
    required this.step,
    required this.trace,
    required this.message,
  });

  final EmrtdException? cause;
  final PassportReadStep step;
  final PassportReadTrace trace;

  /// Diagnostic, not user-facing copy (classification/copy is consumer
  /// policy).
  final String message;

  @override
  String toString() => 'PassportReadException($step: $message)';
}

/// What the retry loop does after a failed DG read attempt. Every non-abort
/// retry first shrinks the read chunk, so upstream's separate
/// shrink-and-redo-BAC row is the re-authentication row (BAC on a BAC
/// session, PACE on a PACE session).
enum _Recovery { abort, reauthenticate, plainRetry }

/// What a mid-read re-authentication needs: the password, the
/// EF.CardAccess the ladder parsed, and the protocol the current session
/// came from, which a re-authentication that falls back to BAC changes.
final class _SessionAuth {
  _SessionAuth({
    required this.mrzKey,
    required this.cardAccess,
    required this.protocol,
  });

  final String mrzKey;

  /// Null when the ladder parsed none, and then [protocol] is `bac`.
  final CardAccess? cardAccess;

  AccessProtocol protocol;
}

/// The orchestration entry point. Deliberately non-final with an overridable
/// [readPassport] so consumer tests fake it without the chip sim.
class PassportReader {
  PassportReader({
    NfcSession? session,
    this._random,
    this.quirks = ReadQuirks.none,
    this.readProfile = ReadProfile.standard,
    this.probeChipBuffers = false,
    this.transceiveTimeout = const Duration(seconds: 30),
    this.messages = const PassportReaderMessages(),
    this.skipChipAuthentication = false,
    this.skipActiveAuthentication = false,
    this.extraDataGroups = const {},
    this.trustStore,
  }) : _session = session ?? FlutterNfcKitNfcSession() {
    // Knob misuse is construction-time API misuse, not a read error; fail
    // fast rather than silently no-op on an id the reader cannot read (the
    // package's `ArgumentError` stance).
    final unsupported = extraDataGroups.where(
      (id) => !_supportedExtras.contains(id),
    );
    if (unsupported.isNotEmpty) {
      throw ArgumentError.value(
        extraDataGroups,
        'extraDataGroups',
        'only ${_supportedExtras.map((e) => e.getName()).join('/')} can be '
            'requested as extras; got ${unsupported.map((e) => e.getName())}',
      );
    }
  }

  /// The extras the reader knows how to read, in the fixed LDS read order;
  /// iteration order of `extraDataGroups` never matters.
  static const List<DataGroupId> _supportedExtras = [
    DataGroupId.DG7,
    DataGroupId.DG11,
    DataGroupId.DG12,
  ];

  final NfcSession _session;

  /// The randomness seam: tests inject a `FixedRandom` so scripted sessions
  /// are deterministic; null means the live `SystemRandom` path.
  final EmrtdRandom? _random;

  /// Read quirks, selected consumer-side (by issuing state / chip signals)
  /// from a table that ships with ZERO entries, [ReadQuirks.none] until
  /// confirmed field evidence lands a fixture-backed entry.
  /// `timeoutMultiplier` is applied to [transceiveTimeout] at poll time.
  final ReadQuirks quirks;

  /// The READ BINARY chunk the session starts at; `standard` (223) by
  /// default; `conservative` is upstream's 0xA0, and never a larger chunk.
  /// A `quirks.maxReadLength` overrides either. The chunk is fitted to the
  /// transport's frame cap at read time (`fitReadLength`), and any retried
  /// data-group read shrinks it to 0xA0 for the rest of the session.
  final ReadProfile readProfile;

  /// The chip-capability census, **off** by default. When true the read
  /// starts with a pre-authentication EF.ATR/INFO read (master-file
  /// select + SELECT `2F01` + read; about four round trips when the file
  /// exists, a refused SELECT when it does not) and records what it found
  /// on the trace: `atrInfoPresent`, the `7F66` buffer sizes from the file
  /// or the ATS, and `atrInfoMs`. Never fatal: any failure reads as
  /// "absent". With the default false the APDU stream is the same as a read
  /// without the probe.
  final bool probeChipBuffers;

  /// Base per-command transceive timeout (Android knob).
  final Duration transceiveTimeout;

  final PassportReaderMessages messages;

  /// Chip Authentication is **on by default**, as upstream's `skipCA: false`
  /// has it. Setting this true skips the DG14 probe and the handshake
  /// entirely: the escape hatch, consumer policy.
  final bool skipChipAuthentication;

  /// Active Authentication is **on by default**, as upstream has it
  /// (upstream has no skip flag at all; its only opt-out is not requesting
  /// DG15). Setting this true skips the DG15 probe and the handshake
  /// entirely: the read is then the same as one without Active
  /// Authentication.
  final bool skipActiveAuthentication;

  /// The **opt-in** extra files to read, a subset of `{DG7, DG11, DG12}`;
  /// anything else throws [ArgumentError] at construction. They are read in
  /// the fixed LDS order DG7 -> DG11 -> DG12 right after DG2, regardless of
  /// set iteration order.
  ///
  /// Extras are the only **absent-skippable** files in the read list: a
  /// `6A 82` (file not found) on one, at any attempt, skips that DG (it lands
  /// in `trace.extrasAbsent`) and the read continues; DG7/11/12 are OPTIONAL
  /// by ICAO 9303, so absence is not a failure. Every *other* error keeps
  /// the full retry semantics (retry/re-authentication, fatal after two
  /// attempts): a chip that has the file but cannot serve it cleanly must not
  /// silently degrade the result. The core DG1/DG2/SOD stay mandatory.
  ///
  /// With the default empty set the APDU stream is the same as a read without
  /// them.
  final Set<DataGroupId> extraDataGroups;

  /// On-device passive authentication is **opt-in**. Left null (the default)
  /// the read is the same as one without it and `result.passiveAuth` is
  /// null.
  ///
  /// Given a store, the reader runs [verifyPassiveAuth] after the SOD hash
  /// oracle passes (reusing the hash result rather than recomputing it) and
  /// puts the verdict on `result.passiveAuth` with the elapsed time on
  /// `trace.passiveAuthMs`. **It never fails the read**: an `invalid` or
  /// `unverifiable` verdict comes back on a successful `PassportReadResult`
  /// (upstream parity: `verifyPassport` never throws, and the reader stays
  /// policy-free). The oracle's own fail-the-read throw is unchanged
  /// and fires first.
  ///
  /// Building the store is heavyweight: do it once, off the NFC path.
  final CscaTrustStore? trustStore;

  Future<bool> isNfcAvailable() => _session.isAvailable();

  /// Tri-state NFC availability: lets a consumer
  /// distinguish "no hardware" from "NFC disabled" from "available", which
  /// [isNfcAvailable]'s bool cannot. Delegates to the session seam.
  Future<NfcAvailability> nfcAvailability() => _session.availability();

  /// One NFC session; exactly one finish. [mrzKey] is the composed MRZ-info
  /// string; `composeMrzKey` is the companion helper. [aaChallenge] pins the
  /// Active Authentication challenge instead of sampling 8 bytes from the RNG
  /// seam (upstream's mainline `aaChallenge` parameter). It is also the
  /// server-nonce hook: a backend that issues the challenge can re-verify the
  /// signature's freshness itself.
  ///
  /// [onStage] fires at operation boundaries. [onProgress] fires once per
  /// READ BINARY chunk of every data group, before the chunk is sent, with
  /// that data group's stage and the percentage of the file already read (
  /// upstream's formula, unshaped): the first value is near 0, 100 is never
  /// emitted, and the sequence restarts if the in-session retry re-reads the
  /// file. Nothing fires for the EF.CardAccess read. The callback runs inside
  /// the per-DG timed region on the read's critical path, so it must be
  /// cheap.
  Future<PassportReadResult> readPassport({
    required String mrzKey,
    List<int>? aaChallenge,
    void Function(PassportReadStage stage)? onStage,
    void Function(PassportReadStage stage, int percent)? onProgress,
  }) async {
    final trace = PassportReadTrace();
    final total = Stopwatch()..start();
    var success = false;
    try {
      final result = await _doRead(
        mrzKey,
        onStage,
        onProgress,
        trace,
        aaChallenge,
      );
      success = true;
      return result;
    } on PassportReadException {
      rethrow; // the oracle mismatch, thrown below with this trace attached
    } on EmrtdException catch (e) {
      trace._recordSw(e);
      throw PassportReadException(
        cause: e,
        step: trace.step,
        trace: trace,
        message: e.toString(),
      );
    } catch (e) {
      // Defensive: a non-typed error is a bug; wrap it so consumers still
      // get the trace (cause stays null).
      throw PassportReadException(
        step: trace.step,
        trace: trace,
        message: 'unexpected error: $e',
      );
    } finally {
      total.stop();
      trace.totalMs = total.elapsedMilliseconds;
      // Exactly one finish per read, errors swallowed (a dead session must
      // never mask the real outcome or poison the next attempt).
      try {
        await _session.finish(
          iosAlertMessage: success ? messages.finishSuccess : null,
          iosErrorMessage: success ? null : messages.finishError,
        );
      } catch (_) {
        // Session already dead; nothing to clean up.
      }
    }
  }

  Future<PassportReadResult> _doRead(
    String mrzKey,
    void Function(PassportReadStage stage)? onStage,
    void Function(PassportReadStage stage, int percent)? onProgress,
    PassportReadTrace trace,
    List<int>? aaChallenge,
  ) async {
    onStage?.call(PassportReadStage.waitingForTag);
    trace.step = PassportReadStep.poll;
    final transceiver = await _session.poll(
      iosAlertMessage: messages.pollPrompt,
      transceiveTimeout: transceiveTimeout * quirks.timeoutMultiplier,
    );
    trace.transceiverMaxLen = transceiver.maxTransceiveLength;
    trace.transceiverExtended = transceiver.isExtendedLengthApduSupported;
    trace.atsHistoricalBytes = transceiver.historicalBytes;
    trace.tagCapabilities = transceiver.tagCapabilities;

    final tagReader = TagReader(
      transceiver,
      quirks: quirks,
      readChunk: readProfile.readChunk,
    );

    if (probeChipBuffers) {
      await _probeChipBuffers(tagReader, transceiver, trace);
    }

    // ---- session ladder (upstream PassportReader L263-302, verbatim
    // structure).
    onStage?.call(PassportReadStage.authenticating);
    await _session.setAlertMessage(messages.authenticating);

    var paceSucceeded = false;
    // Non-null only when a CAM session reached step 4, the material the
    // DG14 block below verifies.
    PaceCamData? camData;
    // Kept for an in-session re-PACE.
    CardAccess? cardAccess;
    final ladderWatch = Stopwatch()..start();
    try {
      trace.step = PassportReadStep.cardAccess;
      final caData = await tagReader.readCardAccess();
      cardAccess = CardAccess(caData);
      trace._recordCardAccess(cardAccess);
      trace.cardAccessMs = ladderWatch.elapsedMilliseconds;

      trace.step = PassportReadStep.pace;
      trace.paceAttempted = true;
      final handler = PACEHandler(
        cardAccess: cardAccess,
        tagReader: tagReader,
        random: _random,
      );
      await handler.doPACE(mrzKey);
      paceSucceeded = true;
      camData = handler.camData;
    } catch (e) {
      // The upstream catch-all. CardAccess read/parse failures (BAC-only
      // chips) and every PACE failure (a CardAccess with no PACEInfo,
      // an MSE:Set AT refusal, a mapping or token PACEError) fall through to
      // BAC; never fatal by themselves. A lost tag surfaces again at the next
      // command and aborts there.
      //
      // The cause is recorded but never acted on: at package level the PACE
      // password may be a CAN or a PIN, so a refused password is not evidence
      // of a wrong MRZ key. The consumer, which knows what it sent, owns that
      // reading (tag_reader.dart:649-651 declines it for the same reason).
      if (trace.paceAttempted && e is EmrtdException) {
        trace._recordPaceFailure(e);
      }
    }
    if (trace.paceAttempted) {
      trace.paceMs = ladderWatch.elapsedMilliseconds - trace.cardAccessMs;
    } else {
      trace.cardAccessMs = ladderWatch.elapsedMilliseconds;
    }

    // Re-select the eMRTD application OUTSIDE the catch; its failure
    // fails the attempt (PassportReader L289).
    trace.step = PassportReadStep.selectApp;
    await tagReader.selectPassportApplication();

    // BAC iff PACE did not succeed; BAC failure is fatal to the attempt.
    // No classification here: a PACE-only document's BAC refusal propagates
    // as its ResponseError, detectable from the trace by the consumer.
    if (!paceSucceeded) {
      trace.step = PassportReadStep.bac;
      final bacWatch = Stopwatch()..start();
      try {
        await BACHandler(
          tagReader: tagReader,
          random: _random,
        ).performBACAndGetSessionKeys(mrzKey);
      } finally {
        trace.bacMs = bacWatch.elapsedMilliseconds;
      }
    }
    final auth = _SessionAuth(
      mrzKey: mrzKey,
      cardAccess: cardAccess,
      protocol: paceSucceeded ? AccessProtocol.pace : AccessProtocol.bac,
    );

    // ---- DG14 probe + Chip Authentication, immediately after the session
    // ladder and before DG1/DG2/SOD so those reads (and the SOD the hash
    // oracle trusts) travel under the upgraded session. Upstream's slot,
    // minus the COM read the port deliberately lacks: presence is probed by
    // attempting the read, and a FIRST-attempt 6A82 means "no DG14" rather
    // than the retry table's re-authentication row.
    DataGroup14? dg14;
    var caStatus = ChipAuthenticationStatus.notDone;
    // The CAM status, resolved before the probe so the two paths that never
    // reach DG14 are already correct: no CAM session at all ->
    // `notApplicable`; a CAM session whose DO8A was missing or undecryptable
    // -> `failed` regardless of what DG14 holds (9303-11 §4.4.5 makes it
    // mandatory, so the shape is never benign, and the finer `cause` stays on
    // the handler). Otherwise the value below stands only if
    // `skipChipAuthentication` skips the whole slot.
    var camStatus = camData == null
        ? PaceCamStatus.notApplicable
        : camData.cause != null
        ? PaceCamStatus.failed
        : PaceCamStatus.skipped;
    if (!skipChipAuthentication) {
      dg14 =
          await _readDataGroup(
                tagReader: tagReader,
                id: DataGroupId.DG14,
                step: PassportReadStep.readDg14,
                stage: PassportReadStage.readingDg14,
                alert: messages.readingDg14,
                auth: auth,
                onStage: onStage,
                onProgress: onProgress,
                trace: trace,
                absenceProbe: true,
              )
              as DataGroup14?;
      trace.dg14Present = dg14 != null;

      // The CAM verification rides the DG14 block, immediately after
      // the parse and before the CA handshake; the order is irrelevant to CA
      // (this is pure local math over data both already have) and it keeps the
      // whole DG14-consuming story in one place. Sub-millisecond, so it gets
      // no stage/step of its own.
      if (camData != null && camData.cause == null) {
        camStatus = _verifyPaceCam(camData, dg14, trace);
      }

      if (dg14 != null) {
        final caHandler = ChipAuthenticationHandler(
          dg14: dg14,
          tagReader: tagReader,
          random: _random,
        );
        trace.caSupported = caHandler.isChipAuthenticationSupported;
        // Upstream L372 guard: no public key in DG14 -> CA is not attempted.
        if (caHandler.isChipAuthenticationSupported) {
          trace.step = PassportReadStep.chipAuth;
          final caWatch = Stopwatch()..start();
          try {
            await caHandler.doChipAuthentication();
            caStatus = ChipAuthenticationStatus.success;
            trace.caOid = caHandler.usedOid;
            trace.caKeyId = caHandler.usedKeyId;
          } catch (_) {
            // Any throw out of the handshake is a CA failure, never fatal by
            // itself. Its cause is recorded here, before the
            // re-authentication below, so it survives one that fails the
            // attempt.
            caStatus = ChipAuthenticationStatus.failed;
            trace._recordCaFailure(caHandler);
          } finally {
            caWatch.stop();
            trace.caMs = caWatch.elapsedMilliseconds;
          }
          if (caStatus == ChipAuthenticationStatus.failed) {
            // Upstream L382 re-establishes BAC whatever opened the session;
            // the port uses the protocol that did, outside `caMs`. A chip
            // that refuses it fails the attempt.
            await _reauthenticate(
              tagReader: tagReader,
              auth: auth,
              trace: trace,
              step: PassportReadStep.chipAuth,
              onPhase: (phase) => trace.step = phase,
            );
          }
        }
      }
    }

    // ---- fixed read list DG1 -> DG2 -> [DG7 -> DG11 -> DG12] -> DG15 ->
    // SOD, no COM read.
    final dg1 =
        await _readDataGroup(
              tagReader: tagReader,
              id: DataGroupId.DG1,
              step: PassportReadStep.readDg1,
              stage: PassportReadStage.readingDg1,
              alert: messages.readingDg1,
              auth: auth,
              onStage: onStage,
              onProgress: onProgress,
              trace: trace,
            )
            as DataGroup1;

    final dg2 =
        await _readDataGroup(
              tagReader: tagReader,
              id: DataGroupId.DG2,
              step: PassportReadStep.readDg2,
              stage: PassportReadStage.readingDg2,
              alert: messages.readingDg2,
              auth: auth,
              onStage: onStage,
              onProgress: onProgress,
              trace: trace,
            )
            as DataGroup2;

    // ---- the opt-in extras, in fixed LDS order after DG2. Absent-skippable,
    // unlike everything else in the list: `optional: true` turns a `6A 82` at
    // ANY attempt into a skip.
    DataGroup7? dg7;
    DataGroup11? dg11;
    DataGroup12? dg12;
    if (extraDataGroups.isNotEmpty) {
      trace.extrasRequested = [
        for (final id in _supportedExtras)
          if (extraDataGroups.contains(id)) id,
      ];

      if (extraDataGroups.contains(DataGroupId.DG7)) {
        dg7 =
            await _readDataGroup(
                  tagReader: tagReader,
                  id: DataGroupId.DG7,
                  step: PassportReadStep.readDg7,
                  stage: PassportReadStage.readingDg7,
                  alert: messages.readingDg7,
                  auth: auth,
                  onStage: onStage,
                  onProgress: onProgress,
                  trace: trace,
                  optional: true,
                )
                as DataGroup7?;
        if (dg7 == null) trace.extrasAbsent.add(DataGroupId.DG7);
      }

      if (extraDataGroups.contains(DataGroupId.DG11)) {
        dg11 =
            await _readDataGroup(
                  tagReader: tagReader,
                  id: DataGroupId.DG11,
                  step: PassportReadStep.readDg11,
                  stage: PassportReadStage.readingDg11,
                  alert: messages.readingDg11,
                  auth: auth,
                  onStage: onStage,
                  onProgress: onProgress,
                  trace: trace,
                  optional: true,
                )
                as DataGroup11?;
        if (dg11 == null) trace.extrasAbsent.add(DataGroupId.DG11);
      }

      if (extraDataGroups.contains(DataGroupId.DG12)) {
        dg12 =
            await _readDataGroup(
                  tagReader: tagReader,
                  id: DataGroupId.DG12,
                  step: PassportReadStep.readDg12,
                  stage: PassportReadStage.readingDg12,
                  alert: messages.readingDg12,
                  auth: auth,
                  onStage: onStage,
                  onProgress: onProgress,
                  trace: trace,
                  optional: true,
                )
                as DataGroup12?;
        if (dg12 == null) trace.extrasAbsent.add(DataGroupId.DG12);
      }
    }

    // ---- the DG15 slot, probed exactly like DG14 (a first-attempt 6A82
    // means "this chip has no DG15", not the retry table's
    // re-authentication row; chips without AA support are common and the port
    // has no COM read to consult). AA itself runs after the SOD read, below.
    DataGroup15? dg15;
    if (!skipActiveAuthentication) {
      dg15 =
          await _readDataGroup(
                tagReader: tagReader,
                id: DataGroupId.DG15,
                step: PassportReadStep.readDg15,
                stage: PassportReadStage.readingDg15,
                alert: messages.readingDg15,
                auth: auth,
                onStage: onStage,
                onProgress: onProgress,
                trace: trace,
                absenceProbe: true,
              )
              as DataGroup15?;
      trace.dg15Present = dg15 != null;
      trace.aaSupported = dg15?.isActiveAuthenticationSupported ?? false;
    }

    final sod =
        await _readDataGroup(
              tagReader: tagReader,
              id: DataGroupId.SOD,
              step: PassportReadStep.readSod,
              stage: PassportReadStage.readingSod,
              alert: messages.readingSod,
              auth: auth,
              onStage: onStage,
              onProgress: onProgress,
              trace: trace,
            )
            as SOD;

    // ---- Active Authentication, after every file is read and
    // while the session is still open, before the (post-session, upstream)
    // hash checks. Upstream's temporal order verbatim
    // (PassportReader L305-307).
    var aaStatus = ActiveAuthenticationStatus.notDone;
    Uint8List? aaChallengeUsed;
    Uint8List? aaSignature;
    if (dg15 != null && dg15.isActiveAuthenticationSupported) {
      onStage?.call(PassportReadStage.activeAuthentication);
      await _session.setAlertMessage(messages.activeAuthentication);
      trace.step = PassportReadStep.activeAuth;
      final aaWatch = Stopwatch()..start();
      // Upstream L328: `aaChallenge ?? generateRandomUInt8Array(8)`.
      final challenge = aaChallenge ?? (_random ?? SystemRandom()).nextBytes(8);
      aaChallengeUsed = Uint8List.fromList(challenge);
      try {
        final response = await tagReader.doInternalAuthentication(
          challenge: challenge,
        );
        aaSignature = Uint8List.fromList(response.data);
        final verdict = verifyActiveAuthentication(
          dg15: dg15,
          dg14: dg14,
          challenge: challenge,
          signature: response.data,
        );
        trace.aaDigest = verdict.digestAlgorithm;
        aaStatus = verdict.passed
            ? ActiveAuthenticationStatus.success
            : ActiveAuthenticationStatus.failed;
      } on EmrtdException catch (e) {
        // Record and continue: upstream propagates here and discards a
        // fully-read passport. Nothing chip-facing follows AA, so there is no
        // re-authentication either; the status and the status word land on
        // the result/trace and the read finishes.
        aaStatus = ActiveAuthenticationStatus.failed;
        trace._recordSw(e);
        passportReaderLog.severe('Active Authentication APDU failed - $e');
      } finally {
        aaWatch.stop();
        trace.aaMs = aaWatch.elapsedMilliseconds;
      }
    }

    // ---- the SOD hash oracle, fail-the-read semantics baked in: the package
    // never hands back data it just proved inconsistent. A mismatch is read
    // corruption or tampering; the consumer-level retry re-reads, and a
    // recurring failure is checked against the read loop before the parser.
    trace.step = PassportReadStep.oracle;
    final check = checkDataGroupHashes(
      sod: sod,
      dataGroupsRead: {
        DataGroupId.DG1: dg1,
        DataGroupId.DG2: dg2,
        // A DG14 that was actually read joins the oracle map, parity with
        // upstream's model (`addDataGroup(.DG14, ...)` feeds
        // `verifyPassport`); a DG14 the SOD does not cover fails the oracle
        // exactly as any read-but-unlisted DG would.
        if (dg14 != null) DataGroupId.DG14: dg14,
        // A DG15 that was actually read joins the map on the same terms,
        // upstream's `addDataGroup(.DG15, ...)` feeding verifyPassport.
        if (dg15 != null) DataGroupId.DG15: dg15,
        // Likewise every extra that was actually read. An
        // absent-skipped extra is excluded (no false "missing!"); one the
        // chip served but the SOD does not hash fails the oracle, the
        // intended tamper evidence.
        if (dg7 != null) DataGroupId.DG7: dg7,
        if (dg11 != null) DataGroupId.DG11: dg11,
        if (dg12 != null) DataGroupId.DG12: dg12,
        DataGroupId.SOD: sod,
      },
    );
    trace.sodHashCheck = check;
    if (!check.passed) {
      throw PassportReadException(
        step: PassportReadStep.oracle,
        trace: trace,
        // Deliberately hash-free: per-DG booleans travel on the trace.
        message:
            'SOD hash oracle mismatch: data groups read do not match '
            'the SOD hashes',
      );
    }

    // ---- the opt-in passive-authentication step. Runs only with a
    // trust store, only after the oracle passed, and never throws; the
    // verdict rides the result. The hash half is the oracle's `check`,
    // reused rather than recomputed.
    PassiveAuthResult? passiveAuth;
    final store = trustStore;
    if (store != null) {
      trace.step = PassportReadStep.passiveAuth;
      final paWatch = Stopwatch()..start();
      try {
        passiveAuth = verifyPassiveAuthWithHashCheck(
          sod: sod,
          trustStore: store,
          hashCheck: check,
        );
      } finally {
        paWatch.stop();
        trace.passiveAuthMs = paWatch.elapsedMilliseconds;
      }
    }

    onStage?.call(PassportReadStage.done);

    return PassportReadResult(
      dg1: dg1,
      dg2: dg2,
      sod: sod,
      dg14: dg14,
      dg15: dg15,
      dg7: dg7,
      dg11: dg11,
      dg12: dg12,
      accessProtocol: paceSucceeded ? AccessProtocol.pace : AccessProtocol.bac,
      paceCamStatus: camStatus,
      chipAuthenticationStatus: caStatus,
      activeAuthenticationStatus: aaStatus,
      activeAuthenticationChallenge: aaChallengeUsed,
      activeAuthenticationSignature: aaSignature,
      passiveAuth: passiveAuth,
      trace: trace,
    );
  }

  /// EF.ATR/INFO before EF.CardAccess, unprotected (its access is ALWAYS).
  /// Any `EmrtdException` reads as "absent", the stance of the PACE
  /// catch-all: a lost tag surfaces again at the next command and aborts
  /// there.
  Future<void> _probeChipBuffers(
    TagReader tagReader,
    NfcTransceiver transceiver,
    PassportReadTrace trace,
  ) async {
    final watch = Stopwatch()..start();
    Uint8List? atrInfo;
    try {
      atrInfo = await tagReader.readAtrInfo();
    } on EmrtdException catch (e) {
      passportReaderLog.fine('EF.ATR/INFO not served - $e');
    } finally {
      trace.atrInfoMs = watch.elapsedMilliseconds;
    }
    trace.atrInfoPresent = atrInfo != null;

    final fromFile = atrInfo == null ? null : parseExtendedLengthInfo(atrInfo);
    final ats = transceiver.historicalBytes;
    final fromAts = ats == null ? null : parseExtendedLengthInfo(ats);
    final sizes = fromFile ?? fromAts;
    if (sizes == null) {
      return;
    }
    trace.chipMaxCommandBytes = sizes.maxCommandBytes;
    trace.chipMaxResponseBytes = sizes.maxResponseBytes;
    trace.chipBufferSource = fromFile != null
        ? ChipBufferSource.atrInfo
        : ChipBufferSource.ats;
  }

  /// The 9303-11 §4.4.3.5.2 check: PK_Map,IC = KA(CA_IC, PK_IC, D_IC).
  ///
  /// Candidates are [dg14]'s `ChipAuthenticationPublicKeyInfo` entries whose
  /// key is EC **on the PACE curve**: PK_Map,IC lives there, so a key on any
  /// other curve cannot satisfy the equation. The curve test is domain-name
  /// equality: keys in the `standardizedDomainParameters` form and the PACE
  /// domain both come out of the same 9303-11 §9.5.1 table, so they always
  /// name alike. A DG14 encoding the same curve as explicit `ECParameters`
  /// builds a custom domain named `spki-explicit` and would be skipped here (a
  /// hypothetical case, and the first place to look at a surprising
  /// `noMatchingKey`).
  ///
  /// The key comes from DG14 only. EF.CardSecurity is where 9303-11 §9.2.11
  /// primarily homes it, but §9.2.11 also requires the full
  /// SecurityInfos set in DG14; and DG14 is the copy this package already
  /// hash-checks in-session and the backend passively authenticates, so a
  /// CardSecurity-sourced key would carry less assurance, not more.
  ///
  /// Never throws: it is called on a session that already succeeded, and its
  /// only output is a status.
  PaceCamStatus _verifyPaceCam(
    PaceCamData camData,
    DataGroup14? dg14,
    PassportReadTrace trace,
  ) {
    final value = camData.chipAuthenticationValue;
    if (value == null) {
      return PaceCamStatus.failed; // caller filtered these out
    }
    var candidates = 0;
    for (final info in dg14?.securityInfos ?? const <SecurityInfo>[]) {
      if (info is! ChipAuthenticationPublicKeyInfo) continue;
      final key = info.pubKey;
      if (key is! SpkiEcPublicKey) continue;
      if (key.domain.domainName != camData.domain.domainName) continue;
      candidates++;
      if (paceCamVerifyChipAuthenticationData(
        domain: camData.domain,
        chipAuthenticationValue: value,
        chipPublicKey: key.point,
        mappingPublicKey: camData.mappingPublicKey,
      )) {
        trace.camKeyId = info.keyId;
        return PaceCamStatus.verified;
      }
    }
    // No candidate at all is a different diagnosis from "a candidate was there
    // and the proof did not hold"; the latter is the clone signal.
    return candidates == 0 ? PaceCamStatus.noMatchingKey : PaceCamStatus.failed;
  }

  /// Up to 2 attempts per DG, dispatching on typed codes/status words (never
  /// message strings); the DG list is mandatory, nothing is skippable
  /// (upstream's broken remove-and-redo intent is not reproduced). A
  /// re-authentication that itself fails aborts everything.
  ///
  /// With [absenceProbe] (the DG14 and DG15 slots) a **first-attempt**
  /// `6A 82` returns null instead of entering the retry table's
  /// re-authentication row:
  /// without a COM read, "chip has no DG14" and "permission hiccup" are
  /// indistinguishable, and absence is by far the likelier reading for the
  /// very first select of the file (the misclassification risk is accepted;
  /// the outcome lands in the trace). Every other error follows the retry
  /// table unchanged.
  ///
  /// With [optional] (the opt-in extras) the same `6A 82` reading is widened
  /// to **any** attempt: a file-not-found surfacing after a re-authentication
  /// still means the file is not there, and DG7/11/12 are OPTIONAL by spec.
  /// This is also where upstream's broken skip-intent is realized properly,
  /// scoped to the files whose absence is legitimate, never to the mandatory
  /// core. Every other error still follows the retry table in full, so a chip
  /// that *has* the file but cannot serve it cleanly still fails the read.
  /// `69 82` deliberately stays re-authentication->fatal: DG7/11/12 are not
  /// EAC-protected, so a security-status failure there means SM trouble, not
  /// absence.
  Future<DataGroup?> _readDataGroup({
    required TagReader tagReader,
    required DataGroupId id,
    required PassportReadStep step,
    required PassportReadStage stage,
    required String alert,
    required _SessionAuth auth,
    required void Function(PassportReadStage stage)? onStage,
    required void Function(PassportReadStage stage, int percent)? onProgress,
    required PassportReadTrace trace,
    bool absenceProbe = false,
    bool optional = false,
  }) async {
    onStage?.call(stage);
    await _session.setAlertMessage(alert);
    trace.step = step;
    final watch = Stopwatch()..start();
    // Installed per data group rather than once per read so the
    // EF.CardAccess read, which has no stage, never emits.
    final progressAlert = messages.progressAlert;
    if (onProgress != null || progressAlert != null) {
      var lastAlert = alert;
      tagReader.progress = (percent) {
        onProgress?.call(stage, percent);
        final text = progressAlert?.call(stage, alert, percent);
        if (text == null || text == lastAlert) return;
        lastAlert = text;
        try {
          _session.setAlertMessage(text).ignore();
        } catch (_) {
          // A dead session must never mask the read's real outcome.
        }
      };
    }
    // READ BINARY accounting across attempts, recorded for DG2.
    int? chunkSize;
    var chunks = 0;
    var bytes = 0;
    try {
      var attempts = 0;
      while (true) {
        attempts++;
        try {
          final data = await tagReader.readDataGroup(id);
          bytes = data.length;
          return DataGroupParser().parseDG(data: data);
        } on EmrtdException catch (e) {
          final fileNotFound =
              e is ResponseError && ((e.sw1 << 8) | e.sw2) == 0x6A82;
          if (fileNotFound && (optional || (absenceProbe && attempts == 1))) {
            // The DG14/DG15 probes (first attempt only) and the extras (any
            // attempt): the file is not on this chip.
            return null;
          }
          if (attempts >= 2) rethrow; // error propagates after 2 attempts
          final recovery = _recoveryFor(e);
          if (recovery == _Recovery.abort) {
            // Tag-gone class and the fatal set (SM invalidated 69 88, class
            // not supported 6E 00; upstream's effective behavior). Recovery
            // is the consumer-level fresh RF session.
            rethrow;
          }
          // Whatever went wrong, the retry runs at upstream's 0xA0
          // for the rest of the session; a retry is rare, and when one
          // happens reliability beats throughput. A per-session shrink:
          // the next `readPassport` starts at the profile's chunk again.
          trace._bumpRetry(step);
          tagReader.reduceDataReadingAmount();
          if (recovery == _Recovery.reauthenticate) {
            await _reauthenticate(
              tagReader: tagReader,
              auth: auth,
              trace: trace,
              step: step,
            );
          }
          // Otherwise upstream's "some other error" branch: a plain second
          // attempt.
        } finally {
          final stats = tagReader.lastRead;
          if (stats != null) {
            chunkSize ??= stats.chunkSize;
            chunks += stats.chunks;
          }
        }
      }
    } finally {
      tagReader.progress = null;
      trace._setDgMs(step, watch.elapsedMilliseconds);
      if (step == PassportReadStep.readDg2) {
        trace.dg2ChunkSize = chunkSize;
        trace.dg2Chunks = chunks;
        trace.dg2Bytes = bytes;
      }
    }
  }

  _Recovery _recoveryFor(EmrtdException e) {
    if (e is ConnectionError ||
        e is TimeOutError ||
        e is NoConnectedTag ||
        e is UserCanceled) {
      return _Recovery.abort;
    }
    if (e is ResponseError) {
      // 67 00 / 62 82 are upstream's wrong-length and end-of-file rows; 6B 00
      // (wrong P1-P2, one of the length-cap rejections chips send) joins
      // them: a same-size retry of a capped read fails again.
      return switch ((e.sw1 << 8) | e.sw2) {
        0x6988 || 0x6E00 => _Recovery.abort,
        0x6982 ||
        0x6A82 ||
        0x6700 ||
        0x6282 ||
        0x6B00 => _Recovery.reauthenticate,
        _ => _Recovery.plainRetry,
      };
    }
    if (e is InvalidResponseChecksum || e is D087Malformed) {
      // SM objects incorrect -> re-authenticate (upstream parity).
      return _Recovery.reauthenticate;
    }
    return _Recovery.plainRetry;
  }

  /// Re-establishes the session mid-read with the protocol the current
  /// session came from, and adds the outcome to `trace.reauthentications`
  /// whether it succeeded or threw. A throw is left to end the attempt.
  ///
  /// A BAC session is redone with BAC alone, as upstream redoes every session
  /// (PassportReader L382/L456). A PACE session repeats the ladder's PACE
  /// branch: with secure messaging cleared,
  /// [TagReader.selectCardAccess] ends the chip's session (9303-11 §9.8.3)
  /// and returns it to the master file, where PACE runs (§4.4); PACE runs
  /// again on the ladder's EF.CardAccess; the eMRTD application is selected
  /// again; and BAC follows only if PACE failed, as in the ladder. After that
  /// BAC, the session is BAC's, and so is any later re-authentication.
  ///
  /// [onPhase] is told of the select and BAC phases, the only ones whose throw
  /// escapes, so the caller that owns the read's step can report them.
  Future<void> _reauthenticate({
    required TagReader tagReader,
    required _SessionAuth auth,
    required PassportReadTrace trace,
    required PassportReadStep step,
    void Function(PassportReadStep phase)? onPhase,
  }) async {
    final watch = Stopwatch()..start();
    final cardAccess = auth.cardAccess;
    final paceAttempted =
        auth.protocol == AccessProtocol.pace && cardAccess != null;
    EmrtdException? paceFailure;
    AccessProtocol? protocol;
    try {
      var paceSucceeded = false;
      if (paceAttempted) {
        tagReader.secureMessaging = null;
        try {
          await tagReader.selectCardAccess();
          await PACEHandler(
            cardAccess: cardAccess,
            tagReader: tagReader,
            random: _random,
          ).doPACE(auth.mrzKey);
          paceSucceeded = true;
        } catch (e) {
          // The ladder's catch-all: a failed PACE is never fatal by itself.
          if (e is EmrtdException) paceFailure = e;
        }
        onPhase?.call(PassportReadStep.selectApp);
        await tagReader.selectPassportApplication();
      }
      if (!paceSucceeded) {
        onPhase?.call(PassportReadStep.bac);
        await _redoBac(tagReader, auth.mrzKey);
      }
      protocol = paceSucceeded ? AccessProtocol.pace : AccessProtocol.bac;
      auth.protocol = protocol;
    } finally {
      final failure = paceFailure == null ? null : _paceFailureOf(paceFailure);
      trace.reauthentications.add(
        SessionReauthentication(
          step: step,
          paceAttempted: paceAttempted,
          paceFailedCode: failure?.code,
          paceFailedStep: failure?.step,
          paceSw: failure?.sw,
          protocol: protocol,
          ms: watch.elapsedMilliseconds,
        ),
      );
    }
  }

  /// BAC from GET CHALLENGE on, with secure messaging cleared first: the
  /// whole re-authentication of a BAC session, and the fallback of a PACE
  /// session whose PACE failed.
  Future<void> _redoBac(TagReader tagReader, String mrzKey) => BACHandler(
    tagReader: tagReader,
    random: _random,
  ).performBACAndGetSessionKeys(mrzKey);
}

String _swHex(ResponseError e) => _swWordHex((e.sw1 << 8) | e.sw2);

String _swWordHex(int sw) => sw.toRadixString(16).padLeft(4, '0');

/// The three PACE-failure fields of an exception, shared by the ladder's
/// record and a re-authentication's so the two cannot drift.
({String code, String? step, String? sw}) _paceFailureOf(EmrtdException e) => (
  code: e.code,
  step: e is PACEError ? e.step : null,
  sw: e is ResponseError ? _swHex(e) : null,
);

/// Trace mutation stays package-internal: the public trace surface is
/// fields only.
extension _TraceRecording on PassportReadTrace {
  void _recordSw(EmrtdException e) {
    if (e is ResponseError) sw = _swHex(e);
  }

  void _recordPaceFailure(EmrtdException e) {
    final failure = _paceFailureOf(e);
    paceFailedCode = failure.code;
    paceFailedStep = failure.step;
    paceSw = failure.sw;
  }

  void _recordCaFailure(ChipAuthenticationHandler handler) {
    caFailure = handler.failure;
    final failureSw = handler.failureSw;
    if (failureSw != null) caSw = _swWordHex(failureSw);
  }

  void _recordCardAccess(CardAccess cardAccess) {
    cardAccessPresent = true;
    paceInfos = [
      for (final info in cardAccess.securityInfos)
        if (info is PACEInfo)
          (oid: info.getObjectIdentifier(), parameterId: info.getParameterId()),
    ];
    final selected = cardAccess.paceInfo;
    paceOid = selected?.getObjectIdentifier();
    paceParameterId = selected?.getParameterId();
  }

  void _bumpRetry(PassportReadStep dgStep) {
    switch (dgStep) {
      case PassportReadStep.readDg14:
        dg14Retries++;
      case PassportReadStep.readDg1:
        dg1Retries++;
      case PassportReadStep.readDg2:
        dg2Retries++;
      case PassportReadStep.readDg7:
        dg7Retries++;
      case PassportReadStep.readDg11:
        dg11Retries++;
      case PassportReadStep.readDg12:
        dg12Retries++;
      case PassportReadStep.readDg15:
        dg15Retries++;
      case PassportReadStep.readSod:
        sodRetries++;
      default:
        break;
    }
  }

  void _setDgMs(PassportReadStep dgStep, int ms) {
    switch (dgStep) {
      case PassportReadStep.readDg14:
        dg14Ms = ms;
      case PassportReadStep.readDg1:
        dg1Ms = ms;
      case PassportReadStep.readDg2:
        dg2Ms = ms;
      case PassportReadStep.readDg7:
        dg7Ms = ms;
      case PassportReadStep.readDg11:
        dg11Ms = ms;
      case PassportReadStep.readDg12:
        dg12Ms = ms;
      case PassportReadStep.readDg15:
        dg15Ms = ms;
      case PassportReadStep.readSod:
        sodMs = ms;
      default:
        break;
    }
  }
}
