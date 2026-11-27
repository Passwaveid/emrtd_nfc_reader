# emrtd_core example

A complete, runnable app that reads a passport or ID-card chip: NFC
availability gate -> manual MRZ entry -> the read, with live stage and
per-chunk progress -> the parsed document and the face photo. It is meant to
be read and copied, not just run.

## Running it

```
cd example
flutter pub get
flutter run
```

**A physical device is required on both platforms.** Neither the iOS
Simulator nor the Android emulator has NFC hardware; on the Simulator
CoreNFC does not exist at all.

## Before it works on iOS

Three things, in this order:

1. **Change the bundle identifier.** It ships as
   `com.example.emrtdCoreExample`, which is a placeholder you cannot sign.
   Set it to an App ID you own.
2. **Enable "Near Field Communication Tag Reading"** on that App ID in the
   Apple developer portal, then regenerate the provisioning profiles. This
   is an account-holder action; no file in this repository can do it. Without
   it the app builds and signs but the reader session fails at run time.
3. Everything else is already here:
   [`ios/Runner/Runner.entitlements`](ios/Runner/Runner.entitlements)
   declares `com.apple.developer.nfc.readersession.formats = [TAG]` and is
   wired into all three build configurations, and
   [`ios/Runner/Info.plist`](ios/Runner/Info.plist) carries
   `NFCReaderUsageDescription` and the LDS1 applet AID
   (`A0000002471001`) as the ISO 7816 select-identifier.

On Android there is nothing to configure beyond what
[`android/app/src/main/AndroidManifest.xml`](android/app/src/main/AndroidManifest.xml)
already declares: the `NFC` permission, and the `android.hardware.nfc`
feature as `required="false"` so the app still installs on devices without
the hardware and can say so.

**Floors:** iOS 13.0, Android minSdk 24.

## What is here

| File | What it shows |
|---|---|
| [`lib/mrz_input.dart`](lib/mrz_input.dart) | Turning three typed fields into the MRZ key. The whole required integration is this file plus one `readPassport` call. |
| [`lib/read_failure.dart`](lib/read_failure.dart) | Classifying a failure into something a user can act on. The library refuses to do this on purpose; the comments say why each distinction exists. |
| [`lib/face_pixels.dart`](lib/face_pixels.dart) | Decoding the DG2 portrait, and deciding which decoder it needs. |
| [`lib/read_screen.dart`](lib/read_screen.dart) | The screen: availability gate, form, live progress, result, failure. |

## The face photo

Essentially every e-passport of the last fifteen years stores its portrait
as JPEG 2000, which Flutter cannot display. `emrtd_core` detects the format
and stops there (presentation is not a protocol library's job), so this
example decodes it with [`j2k`](https://pub.dev/packages/j2k), a pure-Dart
codec, on a background isolate.

**That choice is the example's, not the package's**, and it carries a
caveat: `j2k` is pre-1.0, and the decode has been proven here only against
synthetic fixtures ([`test/fixtures/`](test/fixtures/)); no real document's
DG2 has been through it. Signed grayscale images, high-bit-rate photos and
some national container variants are the cases that historically break
decoders, and none of them are covered. Treat the decode as working but
unproven, and keep the placeholder path that
[`FaceView`](lib/read_screen.dart) already takes when a decode returns null.

## Tests

```
cd example
flutter test
```

They run with no device and no chip: `PassportReader` is deliberately
non-final with an overridable `readPassport`, so
[`test/fake_reader.dart`](test/fake_reader.dart) replays a scripted read and
the widget tests drive the whole screen from it.
