# Vendored `flutter_nfc_kit`: 3.6.2 plus the ISO-DEP capability fields

**What this is.** The pub.dev `flutter_nfc_kit` 3.6.2 package
(sha256 `a2b324785173930f1b5afac8b190637d612593b994ecfd0a5334b72a841b9298`,
the `pubspec.lock` entry it replaces) copied verbatim, with exactly one
change: `NFCTag` gains `maxTransceiveLength` and
`isExtendedLengthApduSupported`, filled on both platforms. The whole delta
is `../flutter_nfc_kit-isodep-capabilities.patch` (five files: the Android
plugin, the iOS plugin, `NFCTag` and its generated JSON code, the changelog);
`../UPSTREAM_PR.md` is the pull request that carries it upstream.

**Why.** `emrtd_core`'s read loop sizes its READ BINARY chunk to the
transport's real frame cap and gates extended-length APDUs on the
transport's real support (`lib/src/transport/nfc_kit_transceiver.dart`).
3.6.2 exposes neither value, so the package was stuck on the pessimistic
constants 261 / `false`. On Android the plugin already holds the `IsoDep`
and the two values are one call each; CoreNFC has no query API, so iOS
reports the `NFCISO7816APDU` ceiling (65536) and `true`.

**How it is wired.** The package's `pubspec.yaml` declares
`flutter_nfc_kit: {path: vendor/flutter_nfc_kit}` as its main dependency.
A path dependency propagates: a consumer that depends on `emrtd_core` by
path resolves this directory through the sibling checkout, and one that
depends on it by git URL resolves it inside the git checkout (verified
2026-08-24). Consumers need no override. The trade-off: the plugin has no
version constraint, and the package cannot be published to pub.dev in this
form (`publish_to: none` today).

**How it goes away.** When the upstream PR is released (say `3.7.0`):
change the dependency back to the hosted form (`flutter_nfc_kit: ^3.7.0`),
re-run `flutter pub get`, re-verify `nfc_kit_transceiver.dart`'s exception
table and the two capability fields against the released sources (that
table is pinned to the plugin version and re-verified on every upgrade),
delete this directory and the patch.

**How to refresh against a newer upstream** (only if the PR stalls): copy
the new pub.dev tree here, `git apply ../flutter_nfc_kit-isodep-capabilities.patch`,
regenerate the patch with `diff -ruN <pristine> flutter_nfc_kit`.
