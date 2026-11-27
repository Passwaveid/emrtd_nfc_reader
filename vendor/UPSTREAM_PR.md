# Upstream pull request: nfcim/flutter_nfc_kit

Not yet opened: this environment has no GitHub credentials. To open it:
fork `nfcim/flutter_nfc_kit` on GitHub, branch from the `3.6.2` tag,
`git apply flutter_nfc_kit-isodep-capabilities.patch` (paths are relative
to the repository root after stripping the leading `flutter_nfc_kit/`
component: `git apply -p2`), commit, push, and open the PR with the text
below. Record the PR URL in `vendor/flutter_nfc_kit/VENDORING.md` once
it exists.

---

**Title:** Expose ISO-DEP transceive capabilities on `NFCTag`
(`maxTransceiveLength`, `isExtendedLengthApduSupported`)

**Body:**

Applications that move large files over ISO 7816, eMRTD (passport) readers
in particular, need two facts the platform already knows before choosing an
APDU size: how many bytes one `transceive` can carry, and whether
extended-length APDUs are supported. Without them a reader has to assume the
pessimistic ISO-DEP defaults (261 bytes, no extended length) and reads a
20 KB photo in ~115 round trips, or guess and risk a mangled frame.

This PR adds two nullable fields to `NFCTag`, populated for ISO 7816
(ISO-DEP) tags and `null` for every other tag type:

- `maxTransceiveLength` (`int?`)
- `isExtendedLengthApduSupported` (`bool?`)

**Android** reports `IsoDep.getMaxTransceiveLength()` and
`IsoDep.isExtendedLengthApduSupported()` for both Type A and Type B ISO-DEP
tags. `JSONObject(Map)` drops null values, so non-ISO-DEP tags simply omit
the keys.

**iOS**: CoreNFC exposes no transceive cap and chains extended-length APDUs
itself, so the plugin reports the `NFCISO7816APDU` ceiling (65536) and
`true`. If maintainers prefer `null` on iOS ("not reported") that is a
two-line change; the Android half is the one applications cannot get any
other way.

The `NFCTag` constructor gains the two fields as trailing optional
positional parameters, so existing call sites are unaffected;
`flutter_nfc_kit.g.dart` is updated by hand in the same shape `json_serializable`
emits (`build_runner` will regenerate identically).

No behaviour change for callers that ignore the fields. CHANGELOG entry
under "Unreleased".
