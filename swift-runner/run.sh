#!/usr/bin/env bash
# swift-runner/run.sh: rented-Mac session script.
#
# Run on the rented Mac from a plain clone of this repo (no submodules):
#   cd emrtd_nfc_reader/swift-runner && ./run.sh
#
# Self-contained by design. There is no fork and no submodule: this script
# fetches upstream NFCPassportReader at the pinned SHA from public GitHub,
# applies seams.patch (our test-enabling changes to Sources/ + Package.swift),
# drops in our ConformanceTests/, then builds and runs. The pin is verified by
# SHA after fetch: git object names are content-addressed, so a matching SHA
# is proof the tree is byte-identical to what the port was written against.
#
# Offline / upstream-vanished fallback: set UPSTREAM_BUNDLE to an archival
# `git bundle` of the repo and the fetch reads from that instead of the
# network. See README.md.
set -euo pipefail

# ---- pins -------------------------------------------------------------------
# Finalized at session S0 and mirrored in README.md. Changing any is a
# deliberate, RUNS.md-recorded event, not drift.
XCODE_PIN="Xcode 26.3"                        # substring of `xcodebuild -version`; the last Xcode that runs on macOS 15
SIMULATOR_NAME="${SIMULATOR_NAME:-iPhone 17}" # on the iOS 26.3.1 (23D8133) simulator runtime
UPSTREAM_PIN="3bf545665c2a1c4c9f95e59e715239d71d1caeb7"  # = release tag 2.3.2 (UPSTREAM.md)
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/AndyQ/NFCPassportReader.git}"
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
# Two levels below the repo root, matching the old submodule depth, so the
# runner's #filePath walk up to <repo>/conformance resolves unchanged.
PKG_DIR="$SCRIPT_DIR/.upstream-build"
PATCH="$SCRIPT_DIR/seams.patch"
TESTS_SRC="$SCRIPT_DIR/ConformanceTests"
SESSION_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_BUNDLE="$SCRIPT_DIR/session-$SESSION_ID.xcresult"
LOG="$SCRIPT_DIR/session-$SESSION_ID.log"
DEST="platform=iOS Simulator,name=$SIMULATOR_NAME"
START_TS="$(date +%s)"

echo "== emrtd_core swift-runner session $SESSION_ID =="
XCV="$(xcodebuild -version | sed -n 1p)"
echo "$XCV / simulator: $SIMULATOR_NAME"
if [[ "$XCODE_PIN" == "TBD-S0" ]]; then
  echo "NOTE: Xcode pin not set yet; S0 records it here and in README.md."
elif [[ "$XCV" != *"$XCODE_PIN"* ]]; then
  echo "FATAL: '$XCV' does not match pin '$XCODE_PIN'." >&2
  exit 1
fi

for f in "$PATCH" "$TESTS_SRC" "$SCRIPT_DIR/Package.resolved"; do
  [[ -e "$f" ]] || { echo "FATAL: missing $f; incomplete checkout?" >&2; exit 1; }
done

# ---- build tree: upstream @ PIN + our seams + our tests ----------------------
echo "== preparing upstream tree at $UPSTREAM_PIN =="
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"
git -C "$PKG_DIR" init -q
if [[ -n "${UPSTREAM_BUNDLE:-}" ]]; then
  echo "   source: bundle $UPSTREAM_BUNDLE (offline mode)"
  git -C "$PKG_DIR" fetch -q "$UPSTREAM_BUNDLE" "$UPSTREAM_PIN"
else
  echo "   source: $UPSTREAM_URL"
  git -C "$PKG_DIR" remote add origin "$UPSTREAM_URL"
  # Fetching a bare SHA needs server support; fall back to a full fetch.
  git -C "$PKG_DIR" fetch -q --depth 1 origin "$UPSTREAM_PIN" \
    || { echo "   (SHA fetch unsupported: falling back to full fetch)"
         git -C "$PKG_DIR" fetch -q origin; }
fi
git -C "$PKG_DIR" checkout -q "$UPSTREAM_PIN"

GOT="$(git -C "$PKG_DIR" rev-parse HEAD)"
if [[ "$GOT" != "$UPSTREAM_PIN" ]]; then
  echo "FATAL: pin mismatch; wanted $UPSTREAM_PIN, got $GOT." >&2
  exit 1
fi
echo "   pin verified: $GOT"

echo "== applying seams.patch =="
git -C "$PKG_DIR" apply --index --whitespace=nowarn "$PATCH"
rm -rf "$PKG_DIR/Tests/ConformanceTests"
mkdir -p "$PKG_DIR/Tests"
cp -R "$TESTS_SRC" "$PKG_DIR/Tests/ConformanceTests"
echo "   seams applied; $(ls "$PKG_DIR/Tests/ConformanceTests" | wc -l | tr -d ' ') test files staged"
cp "$SCRIPT_DIR/Package.resolved" "$PKG_DIR/Package.resolved"
OPENSSL_PIN="$(/usr/bin/python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["object"]["pins"][0]; print(p["package"], p["state"]["version"])' "$SCRIPT_DIR/Package.resolved")"
echo "   OpenSSL pinned by Package.resolved: $OPENSSL_PIN"

# As a fallback, the runner also resolves this by walking up from #filePath,
# which works because PKG_DIR sits at the old submodule depth.
export CONFORMANCE_DIR="$REPO_ROOT/conformance"

echo "== resolving SPM dependencies (OpenSSL xcframework is heavyweight; first run is slow) =="
# A single-product package gets a scheme named after the package, not the
# "<name>-Package" scheme Xcode generates for multi-product packages.
# Package.resolved is ours: upstream commits none, and
# OpenSSL-Package is declared `.upToNextMinor`, so without it every session
# resolves afresh.
STATUS=0
(cd "$PKG_DIR" && xcodebuild -resolvePackageDependencies \
  -scheme NFCPassportReader -destination "$DEST" \
  -disableAutomaticPackageResolution) >"$LOG" 2>&1 || STATUS=$?

if [[ $STATUS -eq 0 ]]; then
  echo "== xcodebuild test (-only-testing keeps upstream's own suite out of milestone runs) =="
  (cd "$PKG_DIR" && xcodebuild test -scheme NFCPassportReader \
    -destination "$DEST" \
    -only-testing:ConformanceTests \
    -disableAutomaticPackageResolution \
    -resultBundlePath "$RESULT_BUNDLE") 2>&1 | tee -a "$LOG" || STATUS=$?
else
  echo "FAILED: dependency resolution (exit $STATUS), tests not run; see $LOG"
  tail -5 "$LOG"
fi

WALL=$(( $(date +%s) - START_TS ))

echo "== summary =="
SUMMARY=""
# Xcode 16+ syntax first; log grep as fallback. S0 shakes this down against
# the rented host's actual xcresulttool.
if OUT="$(xcrun xcresulttool get test-results summary --path "$RESULT_BUNDLE" 2>/dev/null)"; then
  SUMMARY="$(printf '%s' "$OUT" | /usr/bin/python3 -c '
import json, sys
d = json.load(sys.stdin)
print("%s: passed %s, failed %s, skipped %s" % (
    d.get("result"), d.get("passedTests"), d.get("failedTests"),
    d.get("skippedTests")))
' 2>/dev/null || true)"
fi
if [[ -z "$SUMMARY" ]]; then
  SUMMARY="$(grep -E "Test Suite '(ConformanceTests|All tests)' (passed|failed)" "$LOG" | tail -1 || true)"
fi
[[ -z "$SUMMARY" ]] && SUMMARY="(extract manually from $RESULT_BUNDLE)"
echo "$SUMMARY"
grep -F '[conformance] SKIP' "$LOG" || true
CONF_SUMMARY="$(grep -F '[conformance] SUMMARY (swift)' "$LOG" | sed 's/.*SUMMARY (swift) //' | paste -sd '|' - | sed 's/|/; /g' || true)"
echo "${CONF_SUMMARY:-(no SUMMARY lines: the runner did not reach the end of a layer)}"

MAIN_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
CONF_TREE="$(git -C "$REPO_ROOT" rev-parse HEAD:conformance)"
PATCH_SHA="$(git hash-object "$PATCH")"
MACOS_VER="$(sw_vers -productVersion 2>/dev/null || echo '?')"

# ---- portable artifact bundle (README.md, "Sending results back") -----------
# The .xcresult bundle can only be read on a Mac, and failures are analysed off
# the rented host. Everything needed to diagnose remotely gets flattened into
# one tarball. Best-effort throughout: artifact capture must NEVER change the
# session's exit status.
ART="$SCRIPT_DIR/session-$SESSION_ID-artifacts"
mkdir -p "$ART"
{
  cp "$LOG" "$ART/xcodebuild.log" 2>/dev/null || true

  # Failures and skips, pre-extracted so the interesting lines are findable
  # without reading a multi-MB log. The log stays authoritative.
  grep -nE "error:|XCTAssert.* failed|failed -|Fatal error|warning: no rule" \
    "$LOG" >"$ART/failures.txt" 2>/dev/null || true
  grep -F '[conformance] SKIP' "$LOG" >"$ART/skips.txt" 2>/dev/null || true
  grep -E '^\[conformance\] (PASS|FAIL|SKIP|SUMMARY)' "$LOG" >"$ART/results.txt" 2>/dev/null || true

  # Structured results. xcresulttool syntax moved between Xcode versions, so
  # try newest first and keep whichever lands; the log is the fallback.
  xcrun xcresulttool get test-results tests --path "$RESULT_BUNDLE" \
    --format json >"$ART/test-results.json" 2>/dev/null \
    || xcrun xcresulttool get test-results summary --path "$RESULT_BUNDLE" \
      --format json >"$ART/test-results.json" 2>/dev/null \
    || xcrun xcresulttool get --path "$RESULT_BUNDLE" --format json --legacy \
      >"$ART/test-results.json" 2>/dev/null \
    || xcrun xcresulttool get --path "$RESULT_BUNDLE" --format json \
      >"$ART/test-results.json" 2>/dev/null \
    || echo '{"note":"xcresulttool export failed; see xcodebuild.log"}' \
      >"$ART/test-results.json"

  # Environment + provenance, so results are reproducible and attributable.
  {
    echo "session:        $SESSION_ID"
    echo "date:           $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "exit status:    $STATUS"
    echo "wall seconds:   $WALL"
    echo "emrtd_core:     $MAIN_SHA"
    echo "upstream pin:   $UPSTREAM_PIN (verified)"
    echo "upstream src:   ${UPSTREAM_BUNDLE:-$UPSTREAM_URL}"
    echo "seams.patch:    $PATCH_SHA"
    echo "conformance:    $CONF_TREE"
    echo "macOS:          $MACOS_VER"
    echo "xcode:          $XCV"
    echo "xcode pin:      $XCODE_PIN"
    echo "simulator:      $SIMULATOR_NAME"
    echo "openssl:        $OPENSSL_PIN (pinned, swift-runner/Package.resolved)"
    echo "swift:          $(swift --version 2>&1 | sed -n 1p)"
    echo
    echo "== git status (emrtd_core) =="
    git -C "$REPO_ROOT" status --short 2>&1 || true
    echo "== available simulators =="
    xcrun simctl list devices available 2>&1 || true
  } >"$ART/env.txt" 2>&1

  # Any local fixes made on the host: these are part of the finding.
  git -C "$REPO_ROOT" diff >"$ART/local-diff-emrtd_core.patch" 2>/dev/null || true
  # Host edits made directly in the built tree (the seams are staged by
  # `apply --index`, so this is empty unless someone edited on the host;
  # anything here belongs back in seams.patch or ConformanceTests/).
  git -C "$PKG_DIR" diff >"$ART/local-diff-build-tree.patch" 2>/dev/null || true
  # Upstream declares OpenSSL as .upToNextMinor, so the resolved version can
  # differ between sessions; this records which one the oracle ran against.
  cp "$PKG_DIR/Package.resolved" "$ART/Package.resolved" 2>/dev/null || true

  tar -czf "$SCRIPT_DIR/session-$SESSION_ID.tar.gz" \
    -C "$SCRIPT_DIR" "session-$SESSION_ID-artifacts" 2>/dev/null || true
} || true

echo
echo "== SEND THIS FILE BACK =="
echo "  $SCRIPT_DIR/session-$SESSION_ID.tar.gz"
echo "  ($(du -h "$SCRIPT_DIR/session-$SESSION_ID.tar.gz" 2>/dev/null | cut -f1 || echo '?'))"
echo "  Contents: xcodebuild.log; failures.txt; skips.txt; results.txt; test-results.json"
echo "            env.txt; local-diff-*.patch"
echo "  Do this even if the run failed to compile, especially then."
# -----------------------------------------------------------------------------

cat <<EOF

== ready-to-paste RUNS.md entry (fill session label, provider, cost) ==
## S?: $(date +%Y-%m-%d) (session $SESSION_ID)
- emrtd_core: $MAIN_SHA; upstream pin: ${UPSTREAM_PIN:0:7} (verified); seams.patch: ${PATCH_SHA:0:7}; conformance tree: $CONF_TREE
- Host: macOS $MACOS_VER; $XCV; simulator: $SIMULATOR_NAME
- Result: $([[ $STATUS -eq 0 ]] && echo GREEN || echo "RED (exit $STATUS)")
- Suites: ${CONF_SUMMARY:-<no per-case summary>}; XCTest: $SUMMARY
- Wall: ${WALL}s; Provider: <fill>; Cost: <fill>
- Artifacts: session-$SESSION_ID.tar.gz (sent <fill: to whom, when>)
EOF

exit "$STATUS"
