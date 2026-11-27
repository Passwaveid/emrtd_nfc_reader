# Golden APDU transcripts

Ordered expected-command / canned-response pairs, replayed through each side's
transport seam (Dart: `ScriptedTransceiver`; Swift: mock `NFCISO7816Tag` in
`../../swift-runner/ConformanceTests/`). Asserts structured command sequences
on both runners, canonical wire bytes on the Dart side, and identical parsed
output.

**Schema v1** is documented in [../SCHEMA.md](../SCHEMA.md). Within its fixed
frame, the `session` block has a `bac` mode (`mrzKey` + injected `rng`) and
there is a `none` drive op. The hand-authored smoke set covers unprotected
select+read (chunking at 0xA0 and 256), GET RESPONSE segmentation, the split
pairs for upstream's `&&` status check and the `67 00` GENERAL AUTHENTICATE
retry it leaves dead (`*_swift.json` / `*_dart.json`), the field-compatibility
paths (`6C XX` exact-Le retry, `62 82` partial read, MF-select fallback), and
the zero-progress guard. The BAC sessions are `bac_session_efcom` (GET
CHALLENGE -> EXTERNAL AUTHENTICATE -> SM-protected SELECT+READ of EF.COM, ICAO
9303 P11 App D.3/D.4 verbatim through the injected RNG seam) and the
`bac_session_wrong_mrz`/`bac_session_auth_6982` error paths.

The PACE mapping set: `pace_session_dh_gm_aes128` replays ICAO 9303 P11 App
G.2 end to end (RFC 5114 1024/160 DH-GM: every GA command and response is a
published APDU); `pace_session_im_ecdh_aes128` and
`pace_session_im_dh_aes128` carry the App H.1/H.2 Integrated Mapping chains,
synthesized from the published values plus the P11 §4.4.5.2.2 wire rules
because App H prints no APDU listings. All three are authored and re-pinned by
`test/conformance/pace_mapping_transcripts_test.dart` (regenerate with
`REGENERATE_PACE_MAPPING_TRANSCRIPTS=1`) and carry `runners: ["dart"]`, because
upstream reaches neither: its DH-GM abort and IM stub are **swift-only**
fixtures, `pace_session_dh_gm_partial` and `pace_session_im_partial`
(`runners: ["swift"]`), which pin upstream's behavior over the same opening
exchanges.

The optional per-step `cmdFor` field (SCHEMA.md) is a per-runner alternative
to `cmd` for a divergence confined to one command. Today it carries
upstream's MSE:Set AT, without the DO84 parameter-id the port emits (see
`UPSTREAM.md`, Divergences), as `cmdFor.swift` on step 1 of the five
both-runner PACE fixtures: `pace_session_ecdh_gm_aes128`,
`pace_session_cam_aes128`, `aa_session_after_pace_ecdsa`,
`ca_session_after_pace_ecdh_aes128` and the generated
`read_chunk223_pace_aes`. One file serves both runners instead of a
`*_swift.json` / `*_dart.json` pair. The swift-only partials
(`pace_session_dh_gm_partial`, `pace_session_im_partial`) carry upstream's
form directly in `cmd`. Additive within schema v1.

`pace_session_can_ecdh_gm_aes128` is the App G.1 ECDH-GM session with the
**CAN** password in place of the MRZ. It is deliberately a minimal diff
against `pace_session_ecdh_gm_aes128` (same domain, same keypairs, same
nonce) so the only wire differences are the MSE:Set AT's DO83 (`02` instead
of `01`) and everything downstream of the different K_π. It uses the
additive `session.password: {type, value}` field (SCHEMA.md) and is
`runners: ["dart"]`, because upstream's `createPaceKey` can only derive an
MRZ key. No published CAN chain exists (App G, H and I are all MRZ) so the
wire is sim-synthesized; K_π itself is pinned independently by the
python-oracle rows in `kdf_pace.json`. Authored and re-pinned by
`test/conformance/pace_can_cam_transcripts_test.dart` (regenerate with
`REGENERATE_PACE_CAN_CAM_TRANSCRIPTS=1`), which also asserts that replaying
the `pace_session_cam_aes128` fixture yields App I.1's published CA_IC
through `PACEHandler.camData`: the CAM leg is wire-invariant, so that
transcript is both-runner.

The throughput fixtures `read_chunk223_bac` and `read_chunk223_pace_aes` read
a 1078-byte DG2 at the `ReadProfile.standard` chunk of 223
(`drive.args.maxDataLengthToRead`, honoured by both replay runners) under 3DES
and AES respectively: every full chunk is a 244-byte protected response
frame, the arithmetic that makes 223 fit both the 261-byte and the 253-byte
transport caps. Both are sim-synthesized and re-pinned by
`test/conformance/read_chunk_transcripts_test.dart` (regenerate with
`REGENERATE_READ_CHUNK_TRANSCRIPTS=1`), both-runner. `atr_info_absent` and
`atr_info_7f66` drive the `readAtrInfo` op and are `runners: ["dart"]`:
upstream never reads EF.ATR/INFO.

Still to come: a real Italian CIE DH-GM-3DES capture (a capture supersedes the
synthetic DH fixture); oversized-DG2 chaining; more error paths (`6A82`).
Every captured real-passport session becomes a permanent fixture.
