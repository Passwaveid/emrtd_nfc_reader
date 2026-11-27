# emrtd_core

eMRTD (passport / ID-card chip) reading over NFC for Flutter: BAC, PACE,
secure messaging, and LDS data-group parsing. A Dart port of
[AndyQ/NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)
(MIT), pinned at upstream v2.3.2; see [UPSTREAM.md](UPSTREAM.md) for the pin,
per-file port status, and every deliberate divergence.

## Install

`emrtd_core` is not on pub.dev yet. Until it is, depend on this repository:

```yaml
dependencies:
  emrtd_core:
    git: https://github.com/passwaveid/emrtd_nfc_reader.git
```

`pubspec.lock` records the commit you resolved, and `flutter pub upgrade
emrtd_core` moves it to the newest. To name a commit in `pubspec.yaml`
instead, use the long form, `git: {url: ..., ref: <commit>}`.

Requires Flutter 3.44 / Dart 3.12 or newer, iOS 13.0, Android minSdk 24.

## Quickstart

```dart
import 'package:emrtd_core/emrtd_core.dart';

final reader = PassportReader();

if (await reader.nfcAvailability() != NfcAvailability.available) return;

final result = await reader.readPassport(
  mrzKey: composeMrzKey(
    documentNumber: 'L898902C',   // as printed, no check digit
    dateOfBirth:    '740812',     // YYMMDD
    dateOfExpiry:   '340415',     // YYMMDD
  ),
  onStage:    (stage)           => print('$stage'),
  onProgress: (stage, percent)  => print('$stage $percent%'),
);

final fields = Dg1Fields.from(result.dg1);
print('${fields.primaryIdentifier}, ${fields.documentNumber}');
print('${result.accessProtocol}, ${result.durationMs} ms');
```

`PassportReader()` with no arguments is a working reader; every one of its
eleven parameters is optional.
`composeMrzKey` takes the three values as opaque strings and derives the
access key, including the ICAO check digits. A failed read throws
`PassportReadException`, carrying the typed `cause`, the `step` it died at,
and a `trace` of everything the read observed.

A complete app (availability gate, manual MRZ entry, live progress, the
result, the face photo, and failure handling) is in [`example/`](example/).

## Platform setup

Neither platform works without this, and neither failure is obvious.

| Where | What |
|---|---|
| `ios/Runner/Info.plist` | `NFCReaderUsageDescription`: a sentence shown on the reader sheet. And `com.apple.developer.nfc.readersession.iso7816.select-identifiers` = `[A0000002471001]`, the LDS1 applet AID. That single AID is the standard passport/ID applet; do not speculatively add more. |
| `ios/Runner/Runner.entitlements` | `com.apple.developer.nfc.readersession.formats` = `[TAG]`. The Flutter template does not create this file; add it, and set `CODE_SIGN_ENTITLEMENTS = Runner/Runner.entitlements` in all three Runner build configurations. |
| Apple developer portal | Enable **Near Field Communication Tag Reading** on the App ID, then regenerate the provisioning profiles. Nothing in any repository can do this for you, and without it the app signs but the reader session fails at run time. |
| `android/.../AndroidManifest.xml` | `<uses-permission android:name="android.permission.NFC"/>` and `<uses-feature android:name="android.hardware.nfc" android:required="false"/>`. `required="false"` keeps the app installable on devices with no NFC, so you can show the `notSupported` state instead of being hidden from those users on the Play Store. |

**A physical device is required on both platforms.** CoreNFC does not exist
in the iOS Simulator, and the Android emulator has no NFC.

**Do not depend on `flutter_nfc_kit` directly.** This package carries a fork
of it in `vendor/flutter_nfc_kit`: the same plugin (3.6.2) plus the two
ISO-DEP capability fields the transport needs to size its reads. pub cannot
take one package from two sources, so an app that also depends on
`flutter_nfc_kit` fails at `flutter pub get`. Reach NFC only
through `emrtd_core`.

## What you still own

The package reads the chip and parses it. Four things it deliberately does
not do, each of which is real work:

| | Why it is yours |
|---|---|
| **Capturing the MRZ** | The package takes three opaque strings and derives the keys. It does not read an MRZ and will not: there are no `DateTime`s at its API boundary, because Part 3 §4.8 filler dates are legal input. Manual entry is an afternoon; OCR is days. |
| **Displaying the face image, if it is JPEG 2000** | Which it is, on essentially every e-passport of the last fifteen years. `result.faceImageFormat` tells you which of the three forms you have; decoding is yours. The face record may be ISO/IEC 19794-5 or ISO/IEC 39794-5 (the ICAO profile); both are read, and `result.dg2.encoding` says which. `example/` does it in pure Dart with [`j2k`](https://pub.dev/packages/j2k) on an isolate: that is one dependency and no native build, but the decoder is pre-1.0 and unproven against real documents, so keep a placeholder path. |
| **Error copy and classification** | The package reports mechanism (a typed cause, a step, a trace) and draws no conclusions, because what a failure means to a user is a product decision. Expect roughly 170 lines. `example/lib/read_failure.dart` is a working version with the reasoning behind each distinction written down. |
| **A CSCA trust store, for on-device passive authentication** | Sourcing and refreshing the certificates is never bundled. Pass a built `CscaTrustStore` to `PassportReader(trustStore:)` and the verdict rides on `result.passiveAuth`; leave it null and passive auth simply does not run. |

## Defaults that matter

- **Chip Authentication and Active Authentication both run by default.**
  `skipChipAuthentication` and `skipActiveAuthentication` are the opt-outs.
  Neither failing ever fails the read; the outcome lands on
  `result.chipAuthenticationStatus` / `activeAuthenticationStatus`, and what
  to do about it is your policy.
  When Chip Authentication fails, `result.trace.caFailure` says why: a
  transport cap refused the command, the transport failed, the chip refused
  it (its status word is `trace.caSw`), its answer did not verify, or the
  terminal's own side failed.
- **Passive authentication is off** until you supply a `trustStore`.
- **DG7 / DG11 / DG12 are not read** unless `extraDataGroups` names them.
  Naming anything else throws `ArgumentError` at construction rather than
  silently doing nothing.
- **The SOD hash oracle runs in-session and fails the read** on a mismatch,
  the one place the package does draw a conclusion.

## Contributing

Development setup, the conformance vector suite and pull requests:
[CONTRIBUTING.md](CONTRIBUTING.md).

## Attribution

Derived from NFCPassportReader, copyright (c) 2019 Andy Qua, used under the
MIT License. The composite notice is in [LICENSE](LICENSE); ported files
carry per-file headers.

The ISO/IEC 39794-5 face-record walk in `lib/src/lds/iso39794_face.dart`
makes use of the Schema from ISO/IEC 39794-1 and ISO/IEC 39794-5 within
modifications permitted in the relevant ISO/IEC standard; that file
carries the Schema's licence notice.
