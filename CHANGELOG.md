# Changelog

## 1.0.0 (not yet on pub.dev)

- **First public release.** The source is public from this version, and
  until the package is on pub.dev an app depends on it from git (README,
  Install). Earlier versions were internal, on a package that declared
  `publish_to: none`, and were never released.
- **Dependency:** `flutter_nfc_kit` is a fork of 3.6.2 kept in
  `vendor/flutter_nfc_kit` and resolved by path, from a git checkout as from
  a local one: the same plugin plus the two `NFCTag` capability fields the
  transport reads, which the upstream release does not have. An
  app **must not** depend on `flutter_nfc_kit` itself: pub cannot take one
  package from two sources, so `flutter pub get` fails.
- **`pointycastle` constraint restored to `^4.0.0`.** The `>=3.9.1` floor
  existed for one internal rollout that held a second eMRTD library
  side by side; that rollout is over, and 3.9.x has not been exercised by CI
  since 2026-07-18.
- **`example/`**, a runnable Flutter app with `android/` and `ios/`
  committed: NFC availability gate, manual MRZ entry, live stage and
  per-chunk progress, the parsed result, a JPEG 2000 face decode, and a
  fault classifier. It is the reference an integrator starts
  from.
- **Documentation**: `README.md` is now written for an integrator
  (install, quickstart, platform setup, what you still own, the defaults
  that matter); the maintainer material moved to `CONTRIBUTING.md`.
- **Chip Authentication failures say why.** `PassportReadTrace` gains
  `caFailure`, a `ChipAuthenticationFailure` (`extendedLengthUnsupported`,
  `exceedsTransceiveLength`, `transceiveFailed`, `chipRefused`,
  `responseInvalid`, `localFailure`), and `caSw`, the chip's status word as
  4 lowercase hex chars when it refused. Both are null unless
  `chipAuthenticationStatus` is `failed`, and both ride the trace on
  success and failure alike. `ChipAuthenticationHandler` exposes the same
  as `failure` and `failureSw`. Before this, every handshake failure looked
  the same, so a phone that could not carry a command was indistinguishable
  from a chip that refused one.
- **A command longer than the transport's `maxTransceiveLength` is refused
  before it is sent** (`InvalidDataPassed`), and `TagReader.lastRefusal`
  names which declared cap refused the last command. Android's NFC service
  already refused such a command before it reached the tag, but reported it
  as an `IOException` that arrived here as a lost tag (`ConnectionError`).
- **A DG2 encoded in ISO/IEC 39794-5 is read.** Doc 9303 has required
  inspection systems to read the ISO/IEC 39794 biometric formats since
  1 January 2026; issuers may use them now and must by 2030. Such a DG2
  carries its face record as `7F2E { A1 { 65 ... } }`. It used to fail the
  whole read with `NotYetSupported`; it now parses, as the ICAO eMRTD
  application profile of ISO/IEC 39794-5 constrains it. `faceImage` and
  `faceImageFormat` come out exactly as for an ISO/IEC 19794-5 DG2,
  through the same image checks, and the new `DataGroup2.encoding`
  (`FaceRecordEncoding.iso19794` or `.iso39794`) says which record was
  read. For a 39794-5 record the 19794-5 fields carry what has a 19794-5
  equivalent (`numberOfFacialImages`, `imageDataType`, `imageWidth`,
  `imageHeight`, `imageColorSpace`, `sourceType`, `eyeColor`,
  `hairColor`, `featureMask`, `expression`) and are 0 where it has none,
  and `FaceImageInfo.faceImageType` is null. A 39794-5 record that leaves
  no 2D JPEG or JPEG 2000 image fails with `NotYetSupported`, whose
  reason ends `no representation`, `unknown representation`,
  `3D representation`, `image data format` or `empty image`; a malformed
  one fails with `InvalidDataPassed`.
- **A mid-read re-authentication repeats the protocol that opened the
  session.** After a failed Chip Authentication, and on the retry table's
  re-authentication rows, a session that PACE established is now
  re-established with PACE: the reader drops secure messaging, sends the
  master-file and EF.CardAccess selects again, runs PACE with the
  EF.CardAccess it already parsed, and selects the eMRTD application. If
  that PACE fails, BAC follows, as in the session ladder, and later
  re-authentications in the read use BAC. A BAC session is redone with BAC
  exactly as before. Before this every re-authentication was BAC, so a chip
  that refuses BAC failed the read at the first one.
  `PassportReadTrace.reauthentications` lists each as a
  `SessionReauthentication`: the step it served, whether it tried PACE and
  why that failed, the protocol that re-established the session, and its
  duration. `trace.caMs` no longer includes the re-authentication that
  follows a failed handshake.
- Apart from the re-authentication of a PACE session above, no wire,
  timing or protocol change.
