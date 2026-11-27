# Swift-runner session log

Audit trail for the rented-Mac milestone sessions: the Swift side's
stand-in for a CI badge. One entry per session, newest first; milestone gates
cite entries here. `run.sh` emits each entry ready to paste; fields: date,
session id, emrtd_core commit SHA, upstream pin SHA, conformance tree hash,
Xcode/macOS/simulator versions, per-suite results, wall time, cost.

Schedule: **S0** scaffolding (sample suite + runbook shakedown + provider
choice); **S1** the TLV layer (tlv); **S2** BAC and secure messaging
(cipher/kdf/apdu/bac/sm + BAC transcripts, AES-SM frozen-reference generation
if needed); **S3** PACE (PACE suites + transcripts, PACE-CAM
frozen-reference); **S4** the LDS layer / pre-release (full sweep at final
pin); **S5** device rounds (physical iPhone, NOT a rented-Mac session).
Ad-hoc sessions whenever an upstream fix is ported or a parity bug needs
Swift-side debugging.

## Sessions

## S0 (green): 2026-10-05 (session 20261005-105044)
- emrtd_core: 2aba6ea + uncommitted triage fixes; upstream pin: 3bf5456 (verified); seams.patch: cc049e0; conformance tree: d070a120e9643e455d8e9d995d50f17a72efefd7 (the working tree the run read; `run.sh` printed `HEAD:conformance`, 91734c0, which predates the triage's fixture edits)
- Host: macOS 15.7.9; Xcode 26.3; simulator: iPhone 17
- Result: GREEN
- Suites: vectors: cases=943 passed=578 failed=0 skipped=365; transcripts: cases=36 passed=23 failed=0 skipped=13; XCTest: Passed (passed 2, failed 0, skipped 0)
- Wall: 48s; Provider: local Mac, no rental; Cost: none
- Artifacts: session-20261005-105044.tar.gz (kept locally)

## S0: 2026-10-04 (session 20261004-235344)
- emrtd_core: 651b355 + uncommitted S0 runner/runbook fixes; upstream pin: 3bf5456 (verified); seams.patch: cc049e0; conformance tree: 91734c0791b959996c692b8e343845bf6931312b
- Host: macOS 15.7.9 (MacBookPro13,2, Intel); Xcode 26.3 (17C529); simulator: iPhone 17, iOS 26.3.1 (23D8133); OpenSSL-Package 3.6.5000 (resolved, not pinned)
- Result: **RED (exit 65)**, first compile and execution of the Swift runner
- Suites: 2 XCTest methods, both failed; 138 failure lines. Vectors 85 `unknown op` (84 `tlv`, 1 `kdf_bac`), 11 SM `le` 0-vs-256, 3 SOD/DG14 parse divergences; transcripts 39 step mismatches across 14 transcripts (DO84 at MSE:Set AT, `le` 0-vs-256). Per-case pass count not reported by the runner. Triaged off the host; the green run above carries the fixes.
- Wall: 109s (cached build); Provider: local Mac, no rental; Cost: none
- Artifacts: session-20261004-221450.tar.gz (first executing run) and session-20261004-235344.tar.gz (re-run on the pinned defaults; failures identical), kept locally, not sent
