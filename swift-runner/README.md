# swift-runner: rented-Mac milestone sessions

The Swift side of the conformance suite executes the **upstream original**
(`ConformanceTests` XCTest target) on a macOS host against an **iOS
Simulator**: upstream is iOS-only (CoreNFC/CryptoTokenKit/OpenSSL
xcframework), so neither Linux nor a macOS build target can run it.
No Mac is owned and CI has no macOS runners, so execution
happens in **scripted sessions on rented macOS**. [RUNS.md](RUNS.md)
is the audit trail standing in for a CI badge: a gate claiming "green on both
runners" cites its entry there.

The iOS Simulator has no NFC, so a session runs the suite's vectors and
transcripts only. Reading a physical chip on an iPhone is a separate exercise
that this runner does not cover.

**New to this?** Read [../conformance/SCHEMA.md](../conformance/SCHEMA.md)
first: it defines the vector format, the `runners` field and the op
registry, which together say what every case means. Then read
[../conformance/transcripts/README.md](../conformance/transcripts/README.md),
on how golden APDU transcripts replay through the mock ISO7816 tag. This file
is the runbook: how to run a session, how to read its result, and what to
send back.

## How the Swift side is assembled (no fork, no submodule)

Everything needed lives in **this repo**. `run.sh` reconstructs the build tree
from three pieces:

| Piece | What it is |
|---|---|
| upstream `Sources/` | fetched at PIN `3bf5456` (= release 2.3.2) from **public GitHub**, then **SHA-verified** |
| [`seams.patch`](seams.patch) | our test-enabling changes to `Sources/` + `Package.swift`; 345 lines: the `ConformanceTests` target declaration, injectable RNG/ephemeral-key seams, two new `*TestSeams.swift` files, and a handful of access-level relaxations |
| [`ConformanceTests/`](ConformanceTests/) | our 15-file / 3,142-line XCTest runner: the ops registry, mock ISO7816 tag, and transcript replay |

Git object names are content-addressed, so a matching SHA after fetch is proof
the tree is byte-identical to what the port was written against; that check
replaces the old submodule gitlink as the pin mechanism. The reconstruction has
been verified byte-exact against the original fork tree.

The build tree lands in `.upstream-build/` (gitignored, rebuilt from scratch
every run). It sits two levels below the repo root (the same depth the old
submodule occupied), so the runner's `#filePath` walk up to `../conformance`
resolves unchanged. `run.sh` also exports `CONFORMANCE_DIR` explicitly.

**The `test-seams` rule still governs `seams.patch`:** it carries *only*
test-enabling changes: test targets, injectable seams, access-level
relaxations. Never protocol changes. Editing upstream behavior would mean the
oracle tests our edits rather than upstream's, which voids the exercise.

### Offline / upstream-vanished fallback

Set `UPSTREAM_BUNDLE=<path-to>.bundle` and the fetch reads from an archival
`git bundle` instead of the network. An archival bundle of the full history
(280 commits, 51 tags) exists outside the repo; keep a copy somewhere durable.
This is the answer to "what if AndyQ deletes the repo": the pin stays
reachable without depending on GitHub's availability.

Unless `UPSTREAM_BUNDLE` names a bundle, or `UPSTREAM_URL` a mirror the host
can reach, `run.sh` fetches upstream from GitHub at the pin, so the host
needs outbound access to GitHub.

## Pins

| What | Pinned value |
|---|---|
| Upstream | **`3bf545665c2a1c4c9f95e59e715239d71d1caeb7`** (= tag 2.3.2), SHA-verified every run |
| Xcode | **Xcode 26.3** (17C529), pinned at S0 2026-10-04 (`XCODE_PIN` in `run.sh` + this table). 26.3 is the newest Xcode that runs on macOS 15; 26.4+ needs macOS 26 |
| Simulator | **iPhone 17**, iOS 26.3.1 runtime (23D8133), pinned at S0 2026-10-04 (`SIMULATOR_NAME` in `run.sh` + this table). Install the runtime with `xcodebuild -downloadPlatform iOS` |
| OpenSSL-Package | **3.6.5000** (`4ac3f9a`), pinned by [Package.resolved](Package.resolved); upstream declares `.upToNextMinor(from: "3.6.0001")` and commits no resolved file |
| macOS | recorded per session in RUNS.md |

Changing a pin is a deliberate, RUNS.md-recorded event, not drift.

Advancing the upstream pin is not part of a session. It is a separate change
that follows the sync procedure in [../UPSTREAM.md](../UPSTREAM.md).

## Session runbook

1. **Pre-session** (any machine): note the target commit SHA. Both
   repositories involved, this one and upstream, are public, so the session
   needs no credential.
2. **On the rented Mac**:
   - `xcodebuild -version`: must match the pin above.
   - `git clone https://github.com/passwaveid/emrtd_nfc_reader.git`:
     a plain clone; no `--recurse-submodules`, nothing to init.
   - `cd emrtd_nfc_reader && git checkout <target SHA>`
   - `cd swift-runner && ./run.sh`
3. `run.sh` fetches and verifies upstream at the pin, applies `seams.patch`,
   stages `ConformanceTests/`, resolves SPM deps, runs the `xcodebuild test`
   invocation scoped to `ConformanceTests`, prints the per-case conformance
   summary and the XCTest summary + visible skips,
   **packages a portable artifact bundle**, and emits a ready-to-paste RUNS.md
   entry.
4. **Post-session**: send back `session-<id>.tar.gz` (see below), commit
   the RUNS.md entry, release the instance.

Hygiene: never place personal or org-wide SSH keys, or any other
credential, on rented hardware; the session needs none. Budget: S0 up
to half a day (provider onboarding + runbook shakedown); later sessions target
≤30 minutes.

The suite holds no real passport data and no production credentials. Its
fixtures are synthetic, published test vectors (ICAO Doc 9303's worked
examples, NIST and RFC vectors), or public certificates (upstream's example
CSCA list). If that ever changes, flag it before the tree reaches a rented
host.

Provider: MacinCloud pay-as-you-go is the default first choice: it bills
by the hour with no minimum, where AWS EC2 Mac and Scaleway bill a
24-hour minimum. Each RUNS.md entry records the provider and cost of its
session.

## What a run prints

The first dependency resolution on a host is slow, because the OpenSSL
xcframework is large. It has not hung.

The runner prints a line for each case, `[conformance] PASS (swift)` or
`[conformance] FAIL (swift)`, and a `[conformance] SKIP (swift)` line for each
suite, case or transcript that does not apply to Swift. A failed assertion
names its suite and case and what it got against what it expected; for a
vector's output, `<suite> / <case>: got <actual>, expected <expected>`.
Each layer ends with a summary line:

    [conformance] SUMMARY (swift) vectors: cases=N passed=N failed=N skipped=N

There is one for `vectors` and one for `transcripts`. `run.sh` joins them
into the "Suites" field of the RUNS.md entry it prints.

## Reading the result

Failures are diagnosed off the Mac, from the artifact bundle described in
*Sending results back*. On the host, the aim is a complete run, captured.

Each case runs only on the runners its `runners` field names (the case's
own field, or else its suite's; see `../conformance/SCHEMA.md`):

- `runners: ["dart"]` cases skip here, and each skip is printed: one line
  per case, or one for a whole suite marked `["dart"]`. `run.sh` collects
  the skip lines into `skips.txt`. The `vectors` summary's
  `skipped` count should equal the number of vector cases that resolve to
  `["dart"]` in the commit under test, and the `transcripts` count the
  number of `["dart"]` transcripts.
- `runners: ["swift"]` cases assert upstream's behavior where the port
  deliberately departs from it, usually to fix an upstream defect (for
  example, upstream reports a status word of `63 00` as success). Each has a
  `["dart"]` sibling asserting the port's behavior. The `["swift"]` cases
  must pass here.

A failure belongs to one of three kinds:

| Kind | Examples | What to do |
|---|---|---|
| Environment or toolchain | wrong simulator name, Xcode pin, SPM resolution, `xcresulttool` syntax, missing simulator runtime | Fix it on the host, commit the fix, and re-run. |
| Compile error in `ConformanceTests/` | API drift after the Xcode pin moves, a type error, a seam that does not build | Fix it if the intent is clear, commit the fix, and re-run; otherwise leave it. Send the log either way. |
| Test assertion failure | `got <actual>, expected <expected>`, a wrong error code, a transcript step mismatch | Do not fix it on the host. Capture it and send it. |

An assertion failure means either the port is wrong or the port's reading of
upstream's source is wrong, and telling those apart needs work off the host.
Changing a case's expectation until it passes, or changing upstream's
behavior in `seams.patch`, would hide the difference. Never edit upstream's
`Sources/` beyond what the seams rule above allows.

Let the run finish. `xcodebuild test` continues past assertion failures by
default, so one log reports every failure in the run.

A session is complete once the bundle of every run has been sent back,
whether the runs were red or green. A green run is not a complete result if
its `skipped` counts differ from the `["dart"]` counts.

Rented hours are the cost. Do not keep a host running while a failure is
analysed: send the bundle, release the host, and start a fresh session once
a fix lands. Where this runbook and the host disagree in a way that would
cost rented hours, ask before spending them.

For comparison, the Dart runner runs wherever Flutter is installed:
`flutter test` at the repository root. Its skips are the `["swift"]` cases,
and any test whose optional sample files are absent.

## Sending results back

Results go to whoever asked for the session. On the public repository, that
is the issue the session is for: attach the bundle there.

`run.sh` writes one tarball per run, including a run that failed to build,
and prints its path at the end:

    == SEND THIS FILE BACK ==
      <repo>/swift-runner/session-<id>.tar.gz

A run that stops before the build (a pin or Xcode mismatch, a failed fetch,
a `seams.patch` that does not apply) writes no tarball: send its terminal
output instead.

| File in the bundle | What it holds |
|---|---|
| `xcodebuild.log` | The full log, and the authoritative record. Every failure names its case with what it got and what it expected. |
| `failures.txt` | The error and assertion lines from the log, with line numbers. |
| `skips.txt` | Every `[conformance] SKIP` line. |
| `results.txt` | Every `[conformance] PASS`, `FAIL`, `SKIP` and `SUMMARY` line. Its SUMMARY lines are the RUNS.md "Suites" field. |
| `test-results.json` | A structured `xcresulttool` export. Best effort: the command's syntax differs between Xcode versions, so it may be a stub. |
| `env.txt` | Tool versions, the commit, seams and conformance hashes, `git status`, and the available simulators. |
| `local-diff-*.patch` | The uncommitted changes to tracked files made on the host, in this repository and in the build tree (`git diff`; a new file shows only by name, in `env.txt`'s `git status`). Part of the result: do not strip it. |
| `Package.resolved` | The dependency versions the build resolved. |

The `.xcresult` bundle can only be read on macOS, and the tarball carries
what is needed from it, so do not send it.

- Send the bundle even when nothing compiled. Its log holds the compile
  errors.
- Send one bundle per run. If you fix and re-run on the host, send every
  bundle, in the order the runs happened.
- A fix made off the host comes back as a commit. Check it out, re-run, and
  send the new bundle.
- Paste the RUNS.md entry that `run.sh` prints, fill in the session label and
  each `<fill>` field, and commit it. If you cannot commit, send it with the
  bundle.

## Maintaining seams.patch

If a session needs a change to the seams (not to upstream behavior; see the
rule above), edit inside `.upstream-build/`, then regenerate:

```bash
cd .upstream-build && git add -A -- Package.swift Sources && git diff --cached -- Package.swift Sources > ../seams.patch
```

`run.sh` applies the patch with `--index`, so the seams are staged and
`git diff` shows only edits made on the host. Regenerating through the index
keeps new files (the two `*TestSeams.swift`) in the patch; the path filter
keeps the copied-in `Tests/ConformanceTests/` and our `Package.resolved` out.

Changes to the test runner itself are ordinary edits to `ConformanceTests/`
in this repo; `run.sh` copies that directory in fresh on every run, so the
build tree never needs to be the source of truth.
