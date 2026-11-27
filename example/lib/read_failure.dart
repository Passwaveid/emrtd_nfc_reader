import 'package:emrtd_core/emrtd_core.dart';

/// What went wrong, at the granularity a user interface can act on.
///
/// `emrtd_core` deliberately classifies nothing and writes no user-facing
/// copy: it reports a typed cause, the step it died at, and everything the
/// read observed, and leaves the meaning to the app. This enum and
/// [classify] are that missing half.
enum ReadFailureKind {
  /// The chip said the entered details do not match it. Route the user back
  /// to the form.
  wrongDetails,

  /// The radio link dropped mid-read. Route to "hold it still and try
  /// again".
  lostConnection,

  /// The OS or the user ended the session (a call, a lock, a cancel).
  interrupted,

  /// The poll expired without a chip ever entering the field. Distinct from
  /// [lostConnection] because nothing about the user's grip was wrong; the
  /// chip was not there at all, so the advice is "where is the chip", not
  /// "hold still".
  neverFound,

  /// Anything else: a chip that will not do BAC, a tampered or unparseable
  /// file, a secure-messaging failure. Route to "try again", and log it;
  /// this is the bucket that holds library bugs.
  couldNotRead,

  /// The device has no NFC hardware. A dead end, not a retry.
  nfcUnsupported,
}

/// A classified failure: the kind, plus the facts a bug report needs.
class ReadFailure {
  const ReadFailure({
    required this.kind,
    this.code,
    this.step,
    this.sw,
    this.paceOnly = false,
  });

  final ReadFailureKind kind;

  /// `EmrtdException.code`: the stable case name, for logs and telemetry.
  /// Null when the exception carried no typed cause.
  final String? code;

  /// Where in the read it died. Null when nothing was attempted.
  final PassportReadStep? step;

  /// `(sw1 << 8) | sw2` when the cause was a `ResponseError`, else null.
  final int? sw;

  /// The chip served EF.CardAccess, PACE was attempted, and BAC was then
  /// refused: a PACE-only chip this library could not complete PACE with.
  /// A distinct signal inside [ReadFailureKind.couldNotRead], because it is
  /// a library or chip problem and never the user's typing.
  final bool paceOnly;
}

/// Maps a `PassportReadException` onto a [ReadFailureKind]. The arms are in
/// priority order and the order matters; each comment says why.
ReadFailure classify(PassportReadException e) {
  final cause = e.cause;
  final sw = cause is ResponseError ? (cause.sw1 << 8) | cause.sw2 : null;

  // 1. The chip answered the PACE password with 63 00 or 63 CX: it has
  // already stated the key is wrong. Whatever the read died of afterwards
  // (a muted tag, a BAC refusal) cannot make the details right, so this
  // outranks every arm below, the PACE-only arm included.
  //
  // The package declines to draw this conclusion because at its level the
  // PACE password may be a CAN or a PIN. An app that sends nothing but an
  // MRZ-derived password knows better, and can.
  if (e.trace.paceAttempted && _paceRefusedPassword(e.trace.paceSw)) {
    return ReadFailure(
      kind: ReadFailureKind.wrongDetails,
      code: cause?.code,
      step: e.step,
      sw: sw,
    );
  }

  // 2. EF.CardAccess was served, PACE was attempted, and BAC came back
  // 6982 / 6A88: a chip that only does PACE, refusing the fallback. This
  // must never be reported as wrong details: the user would retype correct
  // information forever.
  if (e.step == PassportReadStep.bac &&
      e.trace.cardAccessPresent &&
      e.trace.paceAttempted &&
      cause is ResponseError &&
      (sw == 0x6982 || sw == 0x6A88)) {
    return ReadFailure(
      kind: ReadFailureKind.couldNotRead,
      code: cause.code,
      step: e.step,
      sw: sw,
      paceOnly: true,
    );
  }

  // 3. The SOD hash oracle rejected the files: the package throws with no
  // typed cause at `step == oracle`, with the per-file booleans on the
  // trace. The read reached the chip and the chip answered; the data did
  // not match its own signature.
  if (cause == null && e.step == PassportReadStep.oracle) {
    return ReadFailure(kind: ReadFailureKind.couldNotRead, step: e.step);
  }

  // 4. The poll ran out with no chip ever in the field. Only at `poll`: the
  // same two causes past that step mean a chip WAS coupled and then went
  // away, which is a dropped link and gets different advice. `ConnectionError`
  // is deliberately excluded: Android's poll cannot produce one, and on iOS
  // it means a tag that answered and then could not be reached.
  if ((cause is TimeOutError || cause is NoConnectedTag) &&
      e.step == PassportReadStep.poll) {
    return ReadFailure(
      kind: ReadFailureKind.neverFound,
      code: cause?.code,
      step: e.step,
    );
  }

  // 5. Everything else, by cause.
  final kind = switch (cause) {
    InvalidMRZKey() => ReadFailureKind.wrongDetails,
    NFCNotSupported() => ReadFailureKind.nfcUnsupported,
    ConnectionError() ||
    NoConnectedTag() ||
    TimeOutError() => ReadFailureKind.lostConnection,
    UserCanceled() => ReadFailureKind.interrupted,
    // PACEError, parse failures, secure-messaging failures, UnknownError,
    // and the package's defensive wrap of a non-typed error.
    _ => ReadFailureKind.couldNotRead,
  };

  return ReadFailure(kind: kind, code: cause?.code, step: e.step, sw: sw);
}

/// Generic copy, deliberately plain. Real products replace this wholesale:
/// tone, length and the recovery route are product decisions, which is
/// exactly why the library does not ship any of it.
String copyFor(ReadFailureKind kind) => switch (kind) {
  ReadFailureKind.wrongDetails =>
    'Those details do not match this chip. Check the document number and '
        'the two dates, then try again.',
  ReadFailureKind.lostConnection =>
    'The connection dropped while reading. Hold the device still against '
        'the document and try again.',
  ReadFailureKind.interrupted =>
    'The scan was interrupted before it finished. Try again.',
  ReadFailureKind.neverFound =>
    'No chip was found. The chip is usually inside the back cover of a '
        'passport, or the middle of an ID card.',
  ReadFailureKind.couldNotRead =>
    'The chip could not be read. Try again; if it keeps failing, this '
        'document may not be supported.',
  ReadFailureKind.nfcUnsupported =>
    'This device has no NFC hardware, so it cannot read a document chip.',
};

/// `63 00` and the ISO `63 CX` retry-counter range: the two status words by
/// which a chip can only mean "that password was wrong". The ambiguous
/// refusals (`6982`, `6A80`, `6A88`) are excluded: without the failing
/// instruction byte they cannot be told from "this chip does not support
/// this password type".
bool _paceRefusedPassword(String? paceSw) {
  final sw = int.tryParse(paceSw ?? '', radix: 16);
  if (sw == null) return false;
  return sw == 0x6300 || (sw & 0xFFF0) == 0x63C0;
}
