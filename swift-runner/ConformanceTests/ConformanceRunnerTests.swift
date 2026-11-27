// Conformance runner (Swift side).
//
// Lives on the fork's `test-seams` branch so it can `@testable import` the
// library (key upstream types are internal). Mirrors the Dart
// runner: enumerates conformance/vectors/*.json, validates schemaVersion,
// dispatches each case through an op registry, asserts deep equality on
// `expect.out` or the thrown code on `expect.error`. Skips are visible,
// never silent; an unknown op fails. Executed on rented-Mac sessions via
// the superproject's swift-runner/run.sh.

import Foundation
import XCTest

@testable import NFCPassportReader

private let runnerName = "swift"
private let supportedSchemaVersion = 1

/// Thrown by ops; `code` must equal the vector's `expect.error` string.
/// (Internal, not private: op files like CryptoOps.swift share it.)
struct ConformanceOpError: Error {
    let code: String
}

/// Setup problems (missing vector tree etc.), fails the run, never skips:
/// a session must not go green without having seen the vectors.
private struct HarnessSetupError: Error, CustomStringConvertible {
    let description: String
}

typealias ConformanceOp = ([String: Any]) throws -> [String: Any]

/// Op registry: dispatch key is the case's `op` field. Every entry has a row
/// in conformance/SCHEMA.md. New ops extend ONLY this map (and that
/// table); each area's op group lives in its own file
/// (CryptoOps.swift, ...) and is merged here.
private let ops: [String: ConformanceOp] = {
    var all: [String: ConformanceOp] = [:]
    all.merge(tlvOps) { a, _ in a }
    all.merge(cryptoOps) { a, _ in a }
    all.merge(apduOps) { a, _ in a }
    all.merge(smOps) { a, _ in a }
    all.merge(paceOps) { a, _ in a }
    all.merge(ldsOps) { a, _ in a }
    all.merge(chipAuthOps) { a, _ in a }
    all.merge(activeAuthOps) { a, _ in a }
    all.merge(extLdsOps) { a, _ in a }
    all.merge(passiveAuthOps) { a, _ in a }
    all.merge(paceMappingOps) { a, _ in a }
    return all
}()

final class ConformanceRunnerTests: ConformanceTallyTestCase {

    func testConformanceVectors() throws {
        let vectorsDir = try locateConformanceDir()
            .appendingPathComponent("vectors", isDirectory: true)
        let files = try FileManager.default
            .contentsOfDirectory(at: vectorsDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        XCTAssertFalse(files.isEmpty, "no *.json under \(vectorsDir.path)")

        var skipped: [String] = []
        var tally = Tally()
        for file in files {
            try runSuite(file: file, skipped: &skipped, tally: &tally)
        }
        // Visible skips, never silent (SCHEMA.md). Shows up in the xcodebuild
        // log and therefore in run.sh's RUNS.md summary.
        for entry in skipped {
            print("[conformance] SKIP (\(runnerName)): \(entry)")
        }
        printSummary(layer: "vectors", tally: tally)
    }

    private func runSuite(
        file: URL, skipped: inout [String], tally: inout Tally
    ) throws {
        let data = try Data(contentsOf: file)
        let suite = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any],
            "\(file.lastPathComponent): not a JSON object")
        let suiteName = suite["suite"] as? String ?? file.lastPathComponent
        XCTAssertEqual(
            suite["schemaVersion"] as? Int, supportedSchemaVersion,
            "\(suiteName): unsupported schemaVersion")

        let cases = try XCTUnwrap(
            suite["cases"] as? [[String: Any]], "\(suiteName): missing cases")
        let suiteRunners = suite["runners"] as? [String] ?? [runnerName]
        guard suiteRunners.contains(runnerName) else {
            skipped.append("suite \(suiteName) (runners: \(suiteRunners))")
            tally.skipped += cases.count
            return
        }

        for c in cases {
            let name = c["name"] as? String ?? "<unnamed>"
            let label = "\(suiteName) / \(name)"
            if let caseRunners = c["runners"] as? [String],
                !caseRunners.contains(runnerName) {
                skipped.append("case \(label) (runners: \(caseRunners))")
                tally.skipped += 1
                continue
            }
            runConformanceCase(label, layer: "vectors", tally: &tally) {
                runCase(c, label: label)
            }
        }
    }

    private func runCase(_ c: [String: Any], label: String) {
        guard let opName = c["op"] as? String,
            let input = c["input"] as? [String: Any],
            let expectation = c["expect"] as? [String: Any]
        else {
            XCTFail("\(label): malformed case")
            return
        }
        guard let op = ops[opName] else {
            XCTFail(
                "\(label): unknown op \"\(opName)\"; add it to the runner "
                    + "registry and the SCHEMA.md op table (a runner "
                    + "encountering an unknown op fails)")
            return
        }
        let expectedError = expectation["error"] as? String
        do {
            let out = try op(input)
            if let expectedError = expectedError {
                XCTFail("\(label): expected error \(expectedError), got \(out)")
            } else if let expectedOut = expectation["out"] as? [String: Any] {
                XCTAssertTrue(
                    NSDictionary(dictionary: out).isEqual(to: expectedOut),
                    "\(label): got \(out), expected \(expectedOut)")
            } else {
                XCTFail("\(label): expect has neither out nor error")
            }
        } catch let e as ConformanceOpError {
            if let expectedError = expectedError {
                XCTAssertEqual(
                    e.code, expectedError, "\(label): wrong error code")
            } else {
                XCTFail("\(label): unexpected error \(e.code)")
            }
        } catch {
            XCTFail("\(label): unexpected error \(error)")
        }
    }

    /// CONFORMANCE_DIR env override (standalone fork checkouts), else resolved
    /// #filePath-relative through the superproject's submodule layout:
    ///   <repo>/upstream/NFCPassportReader/Tests/ConformanceTests/<this file>
    ///   -> <repo>/conformance
    private func locateConformanceDir() throws -> URL {
        let env = ProcessInfo.processInfo.environment["CONFORMANCE_DIR"]
        if let env = env, !env.isEmpty {
            let url = URL(fileURLWithPath: env, isDirectory: true)
            guard FileManager.default.fileExists(atPath: url.path) else {
                throw HarnessSetupError(
                    description: "CONFORMANCE_DIR points at \(url.path), "
                        + "which does not exist")
            }
            return url
        }
        let dir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // -> Tests/ConformanceTests/
            .deletingLastPathComponent()  // -> Tests/
            .deletingLastPathComponent()  // -> fork root (submodule checkout)
            .deletingLastPathComponent()  // -> upstream/
            .deletingLastPathComponent()  // -> superproject root
            .appendingPathComponent("conformance", isDirectory: true)
        guard FileManager.default.fileExists(atPath: dir.path) else {
            throw HarnessSetupError(
                description: "conformance dir not found at \(dir.path). "
                    + "Standalone fork checkout? Set CONFORMANCE_DIR to the "
                    + "superproject's conformance/ directory")
        }
        return dir
    }
}
