# Contributing to emrtd_core

## Getting started

```
git clone https://github.com/passwaveid/emrtd_nfc_reader.git
cd emrtd_nfc_reader
flutter pub get          # resolves ./example too
flutter test             # includes the conformance suite
cd example && flutter test
```

`flutter analyze` from the root covers `example/` as well; `flutter test`
from the root does not, so the example's suite is a separate command.

## Layout

```
lib/
  emrtd_core.dart      curated barrel export
  src/transport/       the ONLY directory allowed to import Flutter/plugin APIs
  src/proto/           crypto, BAC, secure messaging, PACE
  src/lds/             TLV, data groups, SOD
  src/pki/             CMS, X.509, passive authentication
  src/reader/          read orchestration
example/               a runnable reference app
conformance/           language-neutral vector suite (SCHEMA.md) + transcripts
test/conformance/      Dart runner: runs under `flutter test`
swift-runner/          rented-Mac session scripts + RUNS.md audit trail
```

All protocol and LDS code is Flutter-free by construction (only
`lib/src/transport/` may import Flutter or plugin APIs), so a later split
into a pure-Dart core package is a mechanical move.

## Conformance runners

The port is held to upstream's behaviour by a language-neutral vector suite
that both implementations run.

- **Dart**: `test/conformance/runner_test.dart` discovers
  `conformance/vectors/*.json` and runs on every push.
- **Swift (upstream original)**: a `ConformanceTests` XCTest target,
  reconstructed by `swift-runner/run.sh` from `swift-runner/seams.patch` and
  `swift-runner/ConformanceTests/` against upstream fetched at the pin, and
  executed on a Mac against an iOS Simulator at each
  milestone. CI has no macOS runners, so there is no Swift job in it.
  How to run one: [swift-runner/README.md](swift-runner/README.md).
  Results: [swift-runner/RUNS.md](swift-runner/RUNS.md). A claim of "green on
  both runners" cites its RUNS.md entry.

The vector schema is [conformance/SCHEMA.md](conformance/SCHEMA.md).

## Pull requests

Pull requests are welcome. They are not merged on GitHub: a maintainer
applies the change as a patch, with you as its author, and closes the pull
request with a link to the commit that carries it.

## Specifications

The specifications this port implements are cited constantly in the code and
are all freely downloadable, but their text is copyrighted and is not
redistributed here.

| Cited as | Where to get it |
|---|---|
| ICAO Doc 9303 Parts 3, 4, 5, 9, 10, 11, 12 | <https://www.icao.int/publications/pages/publication.aspx?docnum=9303>: the consolidated 8th edition, free |
| BSI TR-03110-3 (Advanced Security Mechanisms, Common Specifications) | <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/tr-03110.html> |
| BSI TR-03111 (Elliptic Curve Cryptography) | <https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03111/TR-03111_node.html> |

Part 11 is the one to have open: BAC, PACE (GM/IM/CAM), secure messaging,
key derivation, the standardized domain parameters, and the worked examples
in Appendices D through I that most of the conformance vectors come from.

## Conventions

- **No wire change without a vector.** Anything that alters an APDU, its
  timing, or its ordering needs a conformance case pinning both the old and
  the new behaviour, and a `UPSTREAM.md` Divergences row if it departs from
  upstream deliberately.
- **Upstream fidelity is the default.** A bug in upstream is reproduced
  unless there is a written decision not to; the ones that were fixed are
  all listed in `UPSTREAM.md`.
- `dart format` and `flutter analyze` are enforced in CI.
