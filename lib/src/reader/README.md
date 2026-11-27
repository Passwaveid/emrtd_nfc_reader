# src/reader

The read orchestration upstream ships as `PassportReader.swift`:
`passport_reader.dart`, with the read profiles in `read_profile.dart`.

## What lives here

`PassportReader.readPassport` runs one NFC session end to end:

1. **session ladder**: EF.CardAccess -> PACE (catch-all) -> re-select the
   eMRTD AID -> BAC if and only if PACE did not succeed;
2. **Chip Authentication**: the DG14 probe and handshake, on by default;
   after a CA failure the reader re-authenticates with the protocol that
   opened the session (PACE, then BAC if PACE fails; or BAC) and the read
   continues; a chip that refuses the re-authentication fails the read;
3. **the fixed read list**: DG1 -> DG2 -> the opt-in extras DG7/DG11/DG12 ->
   DG15 -> SOD. No COM read;
4. **Active Authentication**: INTERNAL AUTHENTICATE plus the verify, on by
   default; a chip that refuses it does not fail the read;
5. **the SOD hash oracle**: a mismatch fails the read;
6. **passive authentication**: opt-in behind `trustStore`, a verdict on the
   result, **never** a failed read.

Everything the read observed lands on `PassportReadTrace`, shared by reference
with both the result and the exception.

## Policy stays out

The reader is mechanism only: no error *classification*, no user-facing copy
beyond the injectable iOS alert strings, no decision about what a failed CA,
AA or passive-authentication verdict means. A consumer reads the trace and
applies its own policy: it can recognize a failure pattern from fields such
as `(step, cardAccessPresent, paceAttempted, sw)` without the package naming
it.

## The knobs that change what a read *does*

| Knob | Default | Effect |
|---|---|---|
| `extraDataGroups` | `{}` | Adds DG7/DG11/DG12 to the read list after DG2. Absent-skippable (`6A 82` skips the file), unlike the mandatory core |
| `trustStore` | `null` | Runs on-device passive authentication after the oracle and puts a `PassiveAuthResult` on the result. Local compute only: no extra APDU, no new stage, no alert |
| `readProfile` | `standard` | The READ BINARY chunk the session starts at (`read_profile.dart`): `standard` = 223, `conservative` = upstream's 0xA0 chunk, `extended` = `standard` plus extended-length reads, not wired yet, so it reads as `standard`. Fitted to the transport at read time; every retried DG read shrinks it to 0xA0 |
| `probeChipBuffers` | `false` | Reads EF.ATR/INFO before EF.CardAccess and records its `7F66` buffer sizes on the trace, for a census of chip capabilities. Never fatal |

The first two are off by default, and off they add nothing to the APDU
stream; chip-sim regression tests pin that. `probeChipBuffers` off likewise
adds nothing; `readProfile` is the one knob whose default changes the wire
(223-byte chunks), by design.

`skipChipAuthentication` and `skipActiveAuthentication` are the opposite
shape: escape hatches off a default-on behavior.

## Passive authentication is a verdict, not a failure

With a `trustStore` wired, an `invalid` or `unverifiable` verdict arrives on a
**successful** `PassportReadResult`, as upstream's `verifyPassport` never
throws, and in keeping with the reader's policy-free stance. The only
read-failing integrity check stays the hash oracle, which runs first; a
reader-produced verdict's cause is therefore never `dgHashMismatch`.

Build the store once and off the NFC path: ingestion is heavyweight and
synchronous, and doing it inside a read would stall the session.
