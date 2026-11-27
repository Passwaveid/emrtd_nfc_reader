// BAC / secure-messaging conformance ops (Swift side): SCHEMA.md registry.
//
// sm.protect/sm.unprotect/sm.exchange drive the unmodified upstream
// SecureMessaging (DES + AES); the bac.* ops drive the unmodified BACHandler
// derivation methods (@testable reaches the internal ones). The split cases
// in bac_auth.json/sm_aes.json feed tampered input on the swift side to pin
// upstream's accept-anything behavior (an AES response MAC that always
// matches, a DO99 check that passes a wrong length, a BAC mutual-auth
// response whose MAC and echoed RND.IFD are never checked): these ops
// therefore return successfully where the dart side throws. Randomness is
// injected through the `_emrtdRandomSource` test seam. First executed at
// rented-Mac session S2/S3.

import CoreNFC
import Foundation
import XCTest

@testable import NFCPassportReader

let smOps: [String: ConformanceOp] = [
    "sm.protect": smProtect,
    "sm.unprotect": smUnprotect,
    "sm.exchange": smExchange,
    "bac.generateInitialKseed": bacGenerateInitialKseed,
    "bac.deriveDocumentBasicAccessKeys": bacDeriveDocumentBasicAccessKeys,
    "bac.authentication": bacAuthentication,
    "bac.sessionKeys": bacSessionKeys,
    // bac.composeMrzKey is dart-only (no upstream equivalent;
    // runners-gated, so this side never sees the op).
]

// --- hex plumbing (harness-internal, mirror of APDUOps) ------------------

private func smHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
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

private func smHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func smErrorCode(_ e: NFCPassportReaderError) -> String {
    let mirror = Mirror(reflecting: e)
    if let label = mirror.children.first?.label {
        return label
    }
    return String(describing: e)
}

private func smMapError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        throw ConformanceOpError(code: smErrorCode(e))
    }
}

// --- SM construction --------------------------------------------------------

private func smAlgo(_ input: [String: Any]) throws -> SecureMessagingSupportedAlgorithms {
    switch input["algo"] as? String {
    case "DES": return .DES
    case "AES": return .AES
    default: throw ConformanceOpError(code: "MalformedInput")
    }
}

private func makeSM(_ input: [String: Any]) throws -> SecureMessaging {
    SecureMessaging(
        encryptionAlgorithm: try smAlgo(input),
        ksenc: try smHexBytes(input, "ksenc"),
        ksmac: try smHexBytes(input, "ksmac"),
        ssc: try smHexBytes(input, "ssc"))
}

/// Builds an NFCISO7816APDU from a `{cla,ins,p1,p2,data,le}` map (SCHEMA.md).
private func smApduFromMap(_ m: [String: Any]) throws -> NFCISO7816APDU {
    guard let claHex = m["cla"] as? String, let cla = UInt8(claHex, radix: 16),
        let insHex = m["ins"] as? String, let ins = UInt8(insHex, radix: 16),
        let p1Hex = m["p1"] as? String, let p1 = UInt8(p1Hex, radix: 16),
        let p2Hex = m["p2"] as? String, let p2 = UInt8(p2Hex, radix: 16)
    else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let data = try smHexBytes(m, "data")
    let le = m["le"] as? Int ?? -1
    return NFCISO7816APDU(
        instructionClass: cla, instructionCode: ins, p1Parameter: p1,
        p2Parameter: p2, data: Data(data), expectedResponseLength: le)
}

private func smRapduFromMap(_ m: [String: Any]) throws -> ResponseAPDU {
    let sw = try smHexBytes(m, "sw")
    guard sw.count == 2 else { throw ConformanceOpError(code: "MalformedInput") }
    let data = try smHexBytes(m, "data")
    return ResponseAPDU(data: data, sw1: sw[0], sw2: sw[1])
}

private func smRapduMap(_ r: ResponseAPDU) -> [String: Any] {
    ["data": smHex(r.data), "sw": String(format: "%02x%02x", r.sw1, r.sw2)]
}

// --- SM ops -----------------------------------------------------------------

private func smProtect(_ input: [String: Any]) throws -> [String: Any] {
    guard let cmdMap = input["cmd"] as? [String: Any] else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let sm = try makeSM(input)
    let apdu = try smApduFromMap(cmdMap)
    let ext = input["useExtendedMode"] as? Bool ?? false
    let out = try smMapError { try sm.protect(apdu: apdu, useExtendedMode: ext) }
    return apduToMap(out)
}

private func smUnprotect(_ input: [String: Any]) throws -> [String: Any] {
    guard let rapduMap = input["rapdu"] as? [String: Any] else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let sm = try makeSM(input)
    let out = try smMapError { try sm.unprotect(rapdu: try smRapduFromMap(rapduMap)) }
    return smRapduMap(out)
}

private func smExchange(_ input: [String: Any]) throws -> [String: Any] {
    guard let exchanges = input["exchanges"] as? [[String: Any]] else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let sm = try makeSM(input)
    var out: [[String: Any]] = []
    for e in exchanges {
        guard let cmdMap = e["cmd"] as? [String: Any],
            let rapduMap = e["rapdu"] as? [String: Any]
        else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        let ext = e["useExtendedMode"] as? Bool ?? false
        let protected = try smMapError {
            try sm.protect(apdu: try smApduFromMap(cmdMap), useExtendedMode: ext)
        }
        let unprotected = try smMapError {
            try sm.unprotect(rapdu: try smRapduFromMap(rapduMap))
        }
        out.append(["cmd": apduToMap(protected), "rapdu": smRapduMap(unprotected)])
    }
    return ["exchanges": out]
}

// --- BAC ops ----------------------------------------------------------------

/// Runs `body` with the RNG seam feeding `bytes` front-to-back, then
/// clears it. Exhaustion (a run consuming more than recorded) is a parity
/// failure, mirror of the dart FixedRandom throw. Internal, not private:
/// the transcript replay runner installs the same seam for BAC sessions.
func withFixedRandom<T>(_ bytes: [UInt8], _ body: () throws -> T) rethrows -> T {
    var offset = 0
    _emrtdRandomSource = { size in
        precondition(offset + size <= bytes.count, "FixedRandom exhausted")
        defer { offset += size }
        return Array(bytes[offset..<offset + size])
    }
    defer { _emrtdRandomSource = nil }
    return try body()
}

private func bacGenerateInitialKseed(_ input: [String: Any]) throws -> [String: Any] {
    guard let kmrz = input["kmrz"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return ["kseed": smHex(BACHandler().generateInitialKseed(kmrz: kmrz))]
}

private func bacDeriveDocumentBasicAccessKeys(_ input: [String: Any]) throws -> [String: Any] {
    guard let mrz = input["mrz"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let (ksenc, ksmac) = try smMapError {
        try BACHandler().deriveDocumentBasicAccessKeys(mrz: mrz)
    }
    return ["ksenc": smHex(ksenc), "ksmac": smHex(ksmac)]
}

/// Derives keys and drives `authentication` with the injected RND.IFD/K.IFD.
private func primedBAC(_ input: [String: Any]) throws -> (BACHandler, [UInt8]) {
    guard let mrz = input["mrz"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let rndIfd = try smHexBytes(input, "rndIfd")
    let kifd = try smHexBytes(input, "kifd")
    let rndIcc = try smHexBytes(input, "rndIcc")
    let bac = BACHandler()
    _ = try smMapError { try bac.deriveDocumentBasicAccessKeys(mrz: mrz) }
    let cmdData = withFixedRandom(rndIfd + kifd) { bac.authentication(rnd_icc: rndIcc) }
    return (bac, cmdData)
}

private func bacAuthentication(_ input: [String: Any]) throws -> [String: Any] {
    let (_, cmdData) = try primedBAC(input)
    return ["cmdData": smHex(cmdData)]
}

private func bacSessionKeys(_ input: [String: Any]) throws -> [String: Any] {
    let (bac, _) = try primedBAC(input)
    let response = try smHexBytes(input, "response")
    let (ksenc, ksmac, ssc) = try smMapError { try bac.sessionKeys(data: response) }
    return ["ksenc": smHex(ksenc), "ksmac": smHex(ksmac), "ssc": smHex(ssc)]
}
