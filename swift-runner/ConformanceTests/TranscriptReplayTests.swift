// Golden-transcript replay runner (Swift side).
//
// Mirrors the Dart transcript runner
// (test/conformance/transcript_runner_test.dart): enumerates
// conformance/transcripts/*.json, invokes drive.op on the *unmodified*
// upstream TagReader over MockISO7816Tag, asserts each emitted command
// structurally (the `wire` field is a Dart-runner-only assertion),
// then asserts expect.out deep-equality or the thrown error case name, and
// that every step was consumed. Split fixtures (`runners`) keep upstream's
// own behavior pinned on this side (such as its status check, which passes
// any status word ending `00`). First executed at session S2.

import CoreNFC
import Foundation
import XCTest

@testable import NFCPassportReader

private let runnerName = "swift"
private let supportedSchemaVersion = 1

final class TranscriptReplayTests: ConformanceTallyTestCase {

    func testTranscriptReplay() throws {
        let dir = try locateConformanceDir()
            .appendingPathComponent("transcripts", isDirectory: true)
        let files = try FileManager.default
            .contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        XCTAssertFalse(files.isEmpty, "no *.json under \(dir.path)")

        var skipped: [String] = []
        var tally = Tally()
        for file in files {
            try runTranscript(file: file, skipped: &skipped, tally: &tally)
        }
        for entry in skipped {
            print("[conformance] SKIP (\(runnerName)): \(entry)")
        }
        printSummary(layer: "transcripts", tally: tally)
    }

    private func runTranscript(
        file: URL, skipped: inout [String], tally: inout Tally
    ) throws {
        let json = try JSONSerialization.jsonObject(
            with: Data(contentsOf: file))
        let t = try XCTUnwrap(
            json as? [String: Any],
            "\(file.lastPathComponent): not a JSON object")
        let name = t["transcript"] as? String ?? file.lastPathComponent

        // Omitted runners = both (SCHEMA.md).
        let runners = t["runners"] as? [String] ?? ["swift", "dart"]
        guard runners.contains(runnerName) else {
            skipped.append("transcript \(name) (runners: \(runners))")
            tally.skipped += 1
            return
        }

        runConformanceCase("transcript \(name)", layer: "transcripts", tally: &tally) {
            XCTAssertEqual(
                t["schemaVersion"] as? Int, supportedSchemaVersion,
                "\(name): unsupported schemaVersion")
            let session = t["session"] as? [String: Any]
            let smMode = session?["secureMessaging"] as? String
            XCTAssertTrue(
                smMode == "none" || smMode == "bac" || smMode == "pace",
                "\(name): session.secureMessaging must be \"none\" or "
                    + "\"bac\" (mrzKey + rng establish the session before "
                    + "drive.op; the handshake steps are part of the transcript)")
            do {
                try replay(t, name: name)
            } catch {
                XCTFail("\(name): \(error)")
            }
        }
    }

    private func replay(_ t: [String: Any], name: String) throws {
        let steps = try (t["steps"] as? [[String: Any]] ?? []).map(parseStep)
        let tag = MockISO7816Tag(steps: steps) { XCTFail("\(name): \($0)") }
        let reader = TagReader(tag: tag)

        let session = t["session"] as? [String: Any]
        let smMode = session?["secureMessaging"] as? String

        let drive = try XCTUnwrap(
            t["drive"] as? [String: Any], "\(name): missing drive")
        let op = try XCTUnwrap(drive["op"] as? String)
        let args = drive["args"] as? [String: Any] ?? [:]
        if let maxRead = args["maxDataLengthToRead"] as? Int {
            reader.overrideDataAmountToRead(newAmount: maxRead)
        }

        let expectation = try XCTUnwrap(
            t["expect"] as? [String: Any], "\(name): missing expect")
        let expectedError = expectation["error"] as? String

        let outcome: Result<Any, Error> = Result {
            // For a BAC session the handshake (GET CHALLENGE +
            // EXTERNAL AUTHENTICATE) runs first, driven by BACHandler with
            // the injected RND.IFD/K.IFD; the wrapped drive.op follows over
            // the now-installed SecureMessaging. Error fixtures throw here,
            // before drive (op "none").
            if smMode == "bac" {
                guard let mrzKey = session?["mrzKey"] as? String,
                    let rngHex = session?["rng"] as? String
                else {
                    throw ConformanceOpError(code: "MalformedInput")
                }
                let rng = try self.hexArg(["rng": rngHex], "rng")
                try withFixedRandom(rng) {
                    let bac = BACHandler(tagReader: reader)
                    try awaitTagReaderCall {
                        try await bac.performBACAndGetSessionKeys(mrzKey: mrzKey)
                    }
                }
            } else if smMode == "pace" {
                // Inject both PACE private scalars so the whole MSE:AT +
                // GA handshake is deterministic; the steps are scripted like any
                // other. A partial (DH-GM/IM) session throws here, before drive.
                guard let mrzKey = session?["mrzKey"] as? String,
                    let caHex = session?["cardAccess"] as? String
                else {
                    throw ConformanceOpError(code: "MalformedInput")
                }
                let eph = session?["ephemeralKeys"] as? [String: Any] ?? [:]
                _emrtdPaceMappingPrivateKey =
                    (eph["mappingKey"] as? String).map { try! self.hexArg(["k": $0], "k") }
                _emrtdPaceEphemeralPrivateKey =
                    (eph["ephemeralKey"] as? String).map { try! self.hexArg(["k": $0], "k") }
                defer {
                    _emrtdPaceMappingPrivateKey = nil
                    _emrtdPaceEphemeralPrivateKey = nil
                }
                let cardAccess = try CardAccess(try self.hexArg(["c": caHex], "c"))
                let handler = try PACEHandler(cardAccess: cardAccess, tagReader: reader)
                try awaitTagReaderCall { try await handler.doPACE(mrzKey: mrzKey) }
            }
            return try self.runDrive(op, args: args, reader: reader)
        }

        switch outcome {
        case .success(let out):
            if let expectedError = expectedError {
                XCTFail("\(name): expected error \(expectedError), got \(out)")
            } else if let expectedHex = expectation["out"] as? String {
                XCTAssertEqual(
                    out as? String, expectedHex, "\(name): output mismatch")
            } else if let expectedMap = expectation["out"] as? [String: Any] {
                let got = try XCTUnwrap(
                    out as? [String: Any], "\(name): op returned \(out)")
                XCTAssertTrue(
                    NSDictionary(dictionary: got).isEqual(to: expectedMap),
                    "\(name): got \(got), expected \(expectedMap)")
            } else {
                XCTFail("\(name): expect has neither out nor error")
            }
        case .failure(let e as ConformanceOpError):
            if let expectedError = expectedError {
                XCTAssertEqual(e.code, expectedError, "\(name): wrong error")
            } else {
                XCTFail("\(name): unexpected error \(e.code)")
            }
        case .failure(let e):
            XCTFail("\(name): unexpected error \(e)")
        }
        XCTAssertTrue(
            tag.exhausted,
            "\(name): \(steps.count - tag.consumed) unconsumed step(s); "
                + "the implementation stopped early")
    }

    private func runDrive(
        _ op: String, args: [String: Any], reader: TagReader
    ) throws -> Any {
        switch op {
        case "selectFileAndRead":
            let tagBytes = try hexArg(args, "tag")
            let out = try awaitTagReaderCall {
                try await reader.selectFileAndRead(tag: tagBytes)
            }
            return hex(out)
        case "readCardAccess":
            let out = try awaitTagReaderCall { try await reader.readCardAccess() }
            return hex(out)
        case "doMutualAuthentication":
            let cmdData = try hexArg(args, "cmdData")
            let rep = try awaitTagReaderCall {
                try await reader.doMutualAuthentication(cmdData: Data(cmdData))
            }
            return rapduMap(rep)
        case "sendGeneralAuthenticate":
            guard let isLast = args["isLast"] as? Bool else {
                throw ConformanceOpError(code: "MalformedInput")
            }
            let data = try hexArg(args, "data")
            let lengthExpected = args["lengthExpected"] as? Int ?? 256
            let rep = try awaitTagReaderCall {
                try await reader.sendGeneralAuthenticate(
                    data: data, lengthExpected: lengthExpected, isLast: isLast)
            }
            return rapduMap(rep)
        case "selectPassportApplication":
            let rep = try awaitTagReaderCall {
                try await reader.selectPassportApplication()
            }
            return rapduMap(rep)
        case "chipAuthentication":
            // The CA handshake runs over whatever session the `session` block
            // installed, with the ephemeral scalar injected; the first post-CA
            // protected command then proves the derived keys. A failed
            // handshake throws before it is sent.
            let dg14Bytes = try hexArg(args, "dg14")
            _emrtdCaEphemeralPrivateKey = try hexArg(args, "ephemeralKey")
            defer { _emrtdCaEphemeralPrivateKey = nil }
            let dg14 = try DataGroup14(dg14Bytes)
            let handler = ChipAuthenticationHandler(dg14: dg14, tagReader: reader)
            try awaitTagReaderCall { try await handler.doChipAuthentication() }
            let rep = try awaitTagReaderCall {
                try await reader.selectPassportApplication()
            }
            return rapduMap(rep)
        case "activeAuthentication":
            // INTERNAL AUTHENTICATE runs over whatever session the
            // `session` block installed, followed by the model's own
            // verification of the returned signature. The `challenge` arg is
            // fixed, so replay is deterministic with no new seam (upstream's
            // aaChallenge parameter is the mainline equivalent).
            let dg15Bytes = try hexArg(args, "dg15")
            let challenge = try hexArg(args, "challenge")
            let rep = try awaitTagReaderCall {
                try await reader.doInternalAuthentication(
                    challenge: challenge, useExtendedMode: false)
            }
            let model = NFCPassportModel()
            model.addDataGroup(.DG15, dataGroup: try DataGroup15(dg15Bytes))
            if args["dg14"] != nil {
                model.addDataGroup(
                    .DG14, dataGroup: try DataGroup14(try hexArg(args, "dg14")))
            }
            model.verifyActiveAuthentication(
                challenge: challenge, signature: rep.data)
            return [
                "passed": model.activeAuthenticationPassed,
                "signature": hex(rep.data),
            ]
        case "none":
            // The session establishment itself is under test (BAC/PACE
            // error fixtures); nothing to drive afterwards.
            return ""
        default:
            XCTFail(
                "unknown drive op \"\(op)\": extend both replay runners and "
                    + "the transcript schema in conformance/SCHEMA.md")
            throw ConformanceOpError(code: "MalformedInput")
        }
    }

    // MARK: - fixture parsing

    private func parseStep(_ raw: [String: Any]) throws -> MockISO7816Tag.Step {
        let cmd = try XCTUnwrap(
            (raw["cmdFor"] as? [String: Any])?[runnerName] as? [String: Any]
                ?? raw["cmd"] as? [String: Any],
            "step missing cmd")
        let resp = try XCTUnwrap(raw["resp"] as? [String: Any], "step missing resp")
        let sw = try hexArg(resp, "sw")
        guard sw.count == 2 else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        return MockISO7816Tag.Step(
            expected: MockISO7816Tag.ExpectedCommand(
                cla: try byteArg(cmd, "cla"),
                ins: try byteArg(cmd, "ins"),
                p1: try byteArg(cmd, "p1"),
                p2: try byteArg(cmd, "p2"),
                data: try hexArg(cmd, "data"),
                le: cmd["le"] as? Int ?? -1),
            respData: Data(try hexArg(resp, "data")),
            sw1: sw[0], sw2: sw[1])
    }

    private func byteArg(_ m: [String: Any], _ key: String) throws -> UInt8 {
        guard let hex = m[key] as? String, let v = UInt8(hex, radix: 16) else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        return v
    }

    private func hexArg(_ m: [String: Any], _ key: String) throws -> [UInt8] {
        guard let hexStr = m[key] as? String else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        guard hexStr.count % 2 == 0, hexStr.allSatisfy({ $0.isHexDigit }) else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        var bytes: [UInt8] = []
        var idx = hexStr.startIndex
        while idx < hexStr.endIndex {
            let next = hexStr.index(idx, offsetBy: 2)
            bytes.append(UInt8(hexStr[idx..<next], radix: 16)!)
            idx = next
        }
        return bytes
    }

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func rapduMap(_ r: ResponseAPDU) -> [String: Any] {
        ["data": hex(r.data), "sw": String(format: "%02x%02x", r.sw1, r.sw2)]
    }

    /// CONFORMANCE_DIR env override, else resolved #filePath-relative through
    /// the superproject's submodule layout (mirror of ConformanceRunnerTests).
    private func locateConformanceDir() throws -> URL {
        if let env = ProcessInfo.processInfo.environment["CONFORMANCE_DIR"],
            !env.isEmpty
        {
            return URL(fileURLWithPath: env, isDirectory: true)
        }
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // -> Tests/ConformanceTests/
            .deletingLastPathComponent()  // -> Tests/
            .deletingLastPathComponent()  // -> fork root (submodule checkout)
            .deletingLastPathComponent()  // -> upstream/
            .deletingLastPathComponent()  // -> superproject root
            .appendingPathComponent("conformance", isDirectory: true)
    }
}
