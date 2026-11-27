// APDU conformance ops (Swift side): SCHEMA.md registry.
//
// apdu.parse drives NFCISO7816APDU(data:) directly (nil -> "UnexpectedError",
// the upstream call-site mapping). apdu.response and
// apdu.commandBuild drive the unmodified TagReader over MockISO7816Tag; the
// async send pipeline is bridged with a semaphore (TagReader is nonisolated
// at the pin, so blocking the XCTest thread is safe). apdu.encode and
// apdu.statusMessages are dart-only (SCHEMA.md: CoreNFC never exposed wire
// encoding; decodeError is private). First executed at session S2.

import CoreNFC
import Foundation
import XCTest

@testable import NFCPassportReader

let apduOps: [String: ConformanceOp] = [
    "apdu.parse": apduParse,
    "apdu.response": apduResponse,
    "apdu.commandBuild": apduCommandBuild,
]

// --- hex plumbing (harness-internal, mirror of CryptoOps) ----------------

private func apduHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    guard hex.count % 2 == 0, hex.allSatisfy({ $0.isHexDigit }) else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    var bytes: [UInt8] = []
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        bytes.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return bytes
}

private func apduHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func apduErrorCode(_ e: NFCPassportReaderError) -> String {
    let mirror = Mirror(reflecting: e)
    if let label = mirror.children.first?.label {
        return label
    }
    return String(describing: e)
}

// --- structured-command codec (SCHEMA.md) -----------------------------------

func apduToMap(_ apdu: NFCISO7816APDU) -> [String: Any] {
    [
        "cla": String(format: "%02x", apdu.instructionClass),
        "ins": String(format: "%02x", apdu.instructionCode),
        "p1": String(format: "%02x", apdu.p1Parameter),
        "p2": String(format: "%02x", apdu.p2Parameter),
        "data": apduHex([UInt8](apdu.data ?? Data())),
        "le": conformanceLe(apdu),
    ]
}

private func apduFromMap(_ m: [String: Any]) throws -> NFCISO7816APDU {
    guard let claHex = m["cla"] as? String, let cla = UInt8(claHex, radix: 16),
        let insHex = m["ins"] as? String, let ins = UInt8(insHex, radix: 16),
        let p1Hex = m["p1"] as? String, let p1 = UInt8(p1Hex, radix: 16),
        let p2Hex = m["p2"] as? String, let p2 = UInt8(p2Hex, radix: 16)
    else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let data = try apduHexBytes(m, "data")
    let le = m["le"] as? Int ?? -1
    return NFCISO7816APDU(
        instructionClass: cla, instructionCode: ins, p1Parameter: p1,
        p2Parameter: p2, data: Data(data), expectedResponseLength: le)
}

func mockSteps(fromResponses responses: [[String: Any]]) throws -> [MockISO7816Tag.Step] {
    try responses.map { r in
        let data = try apduHexBytes(r, "data")
        let sw = try apduHexBytes(r, "sw")
        guard sw.count == 2 else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        return MockISO7816Tag.Step(
            expected: nil, respData: Data(data), sw1: sw[0], sw2: sw[1])
    }
}

// --- async bridge -----------------------------------------------------------

/// Swift forbids nesting a type inside a generic function, so the result
/// slot for `awaitTagReaderCall` lives at file scope.
private final class TagReaderResultBox<U>: @unchecked Sendable {
    var result: Result<U, Error>?
}

/// Runs an async TagReader call to completion from a synchronous op.
/// Library errors map to their case names; anything else re-throws.
func awaitTagReaderCall<T>(_ body: @escaping () async throws -> T) throws -> T {
    let box = TagReaderResultBox<T>()
    let sema = DispatchSemaphore(value: 0)
    Task.detached {
        do {
            box.result = .success(try await body())
        } catch {
            box.result = .failure(error)
        }
        sema.signal()
    }
    sema.wait()
    switch box.result! {
    case .success(let value):
        return value
    case .failure(let e as NFCPassportReaderError):
        throw ConformanceOpError(code: apduErrorCode(e))
    case .failure(let e):
        throw e
    }
}

// --- ops --------------------------------------------------------------------

private func apduParse(_ input: [String: Any]) throws -> [String: Any] {
    let raw = try apduHexBytes(input, "raw")
    guard let apdu = NFCISO7816APDU(data: Data(raw)) else {
        // Upstream call sites map the initializer's nil to UnexpectedError;
        // the op pins that mapping.
        throw ConformanceOpError(code: "UnexpectedError")
    }
    return apduToMap(apdu)
}

private func apduResponse(_ input: [String: Any]) throws -> [String: Any] {
    guard let cmdMap = input["cmd"] as? [String: Any],
        let responses = input["responses"] as? [[String: Any]]
    else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let cmd = try apduFromMap(cmdMap)
    let tag = MockISO7816Tag(steps: try mockSteps(fromResponses: responses)) {
        XCTFail("apdu.response: \($0)")
    }
    let reader = TagReader(tag: tag)
    let rep = try awaitTagReaderCall { try await reader.send(cmd: cmd) }
    if !tag.exhausted {
        XCTFail("apdu.response: send() left canned responses unconsumed")
    }
    return [
        "data": apduHex(rep.data),
        "sw": String(format: "%02x%02x", rep.sw1, rep.sw2),
    ]
}

private func apduCommandBuild(_ input: [String: Any]) throws -> [String: Any] {
    guard let method = input["method"] as? String,
        let args = input["args"] as? [String: Any]
    else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    // sendGeneralAuthenticate unwraps a 7C DO from the response; everything
    // else just needs 90 00.
    let respData: Data = method == "sendGeneralAuthenticate" ? Data([0x7C, 0x00]) : Data()
    let tag = MockISO7816Tag(
        steps: [.init(expected: nil, respData: respData, sw1: 0x90, sw2: 0x00)]
    ) {
        XCTFail("apdu.commandBuild: \($0)")
    }
    let reader = TagReader(tag: tag)

    switch method {
    case "getChallenge":
        _ = try awaitTagReaderCall { try await reader.getChallenge() }
    case "doMutualAuthentication":
        let cmdData = try apduHexBytes(args, "cmdData")
        _ = try awaitTagReaderCall {
            try await reader.doMutualAuthentication(cmdData: Data(cmdData))
        }
    case "selectFile":
        let fileTag = try apduHexBytes(args, "tag")
        _ = try awaitTagReaderCall { try await reader.selectFile(tag: fileTag) }
    case "selectPassportApplication":
        _ = try awaitTagReaderCall { try await reader.selectPassportApplication() }
    case "sendMSESetATMutualAuth":
        // Upstream has no parameterId parameter: the DO84 case is dart-only
        // (runners-gated), so this op never sees one.
        guard let oid = args["oid"] as? String,
            let keyType = args["keyType"] as? Int
        else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        _ = try awaitTagReaderCall {
            try await reader.sendMSESetATMutualAuth(oid: oid, keyType: UInt8(keyType))
        }
    case "sendGeneralAuthenticate":
        guard let isLast = args["isLast"] as? Bool else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        let data = try apduHexBytes(args, "data")
        let lengthExpected = args["lengthExpected"] as? Int ?? 256
        _ = try awaitTagReaderCall {
            try await reader.sendGeneralAuthenticate(
                data: data, lengthExpected: lengthExpected, isLast: isLast)
        }
    default:
        throw ConformanceOpError(code: "MalformedInput")
    }

    guard tag.received.count == 1 else {
        XCTFail("apdu.commandBuild expects exactly one emitted command, got \(tag.received.count)")
        throw ConformanceOpError(code: "MalformedInput")
    }
    return apduToMap(tag.received[0])
}
