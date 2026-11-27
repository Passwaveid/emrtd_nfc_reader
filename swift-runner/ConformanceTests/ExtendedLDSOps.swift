// Extended data-group (DG7/DG11/DG12) conformance ops (Swift side):
// SCHEMA.md registry.
//
// These ops drive the unmodified upstream extended-DG parsers:
//   - dg7.parse    (DataGroup7: one 5F43 image, the discarded 02 count)
//   - dg11.parse   (DataGroup11: the twelve String? elements)
//   - dg12.parse   (DataGroup12: eight fields; `otherPersonsDetails` is
//                   deliberately NOT emitted: upstream declares it and never
//                   assigns it, so it is always nil, and the port drops
//                   it. Emitting it would put a permanently-null key in
//                   the shared shape for no signal.)
//
// No new seams and no mainline patches were needed: all three `init`s are
// `required init` (internal, reachable via @testable) and every field is
// `public private(set)`.
//
// The three dart-only ops (dg7.imageFormat, dg11.otherNames,
// dg12.otherPersons) are absent here by design and their cases are gated
// runners:["dart"]: upstream has no image-format surface on DG7, drops
// DG11's A0 group whole, and its DG12 A0 branch is a literal
// `// Not yet handled` no-op. Likewise the truncation cases, which crash
// upstream rather than throwing.
//
// Images travel as SHA-256, never as bytes, as in dg2.parse.

import Foundation
import XCTest

@testable import NFCPassportReader

let extLdsOps: [String: ConformanceOp] = [
    "dg7.parse": dg7Parse,
    "dg11.parse": dg11Parse,
    "dg12.parse": dg12Parse,
]

// --- hex plumbing (harness-internal, mirror of LDSOps) -------------------

private func extLdsHexString(_ hex: String) throws -> [UInt8] {
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

private func extLdsHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try extLdsHexString(hex)
}

private func extLdsHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// `NFCPassportReaderError` cases map to their case names (the shared
/// convention). The extended DGs throw nothing else.
private func extLdsMapError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        let mirror = Mirror(reflecting: e)
        throw ConformanceOpError(code: mirror.children.first?.label ?? "\(e)")
    }
}

/// Optionals travel as JSON null so the shape matches the Dart runner's map.
private func extLdsOptional(_ value: String?) -> Any {
    value ?? NSNull()
}

// --- DG7 --------------------------------------------------------------------

private func dg7Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try extLdsHexBytes(input, "data")
    let dg7 = try extLdsMapError { try DataGroup7(data) }
    return ["imageSha256": extLdsHex(calcSHA256Hash(dg7.imageData))]
}

// --- DG11 -------------------------------------------------------------------

private func dg11Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try extLdsHexBytes(input, "data")
    let dg11 = try extLdsMapError { try DataGroup11(data) }
    return [
        "fullName": extLdsOptional(dg11.fullName),
        "personalNumber": extLdsOptional(dg11.personalNumber),
        "dateOfBirth": extLdsOptional(dg11.dateOfBirth),
        "placeOfBirth": extLdsOptional(dg11.placeOfBirth),
        "address": extLdsOptional(dg11.address),
        "telephone": extLdsOptional(dg11.telephone),
        "profession": extLdsOptional(dg11.profession),
        "title": extLdsOptional(dg11.title),
        "personalSummary": extLdsOptional(dg11.personalSummary),
        "proofOfCitizenship": extLdsOptional(dg11.proofOfCitizenship),
        "tdNumbers": extLdsOptional(dg11.tdNumbers),
        "custodyInfo": extLdsOptional(dg11.custodyInfo),
    ]
}

// --- DG12 -------------------------------------------------------------------

private func dg12Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try extLdsHexBytes(input, "data")
    let dg12 = try extLdsMapError { try DataGroup12(data) }
    return [
        "issuingAuthority": extLdsOptional(dg12.issuingAuthority),
        "dateOfIssue": extLdsOptional(dg12.dateOfIssue),
        "endorsementsOrObservations": extLdsOptional(dg12.endorsementsOrObservations),
        "taxOrExitRequirements": extLdsOptional(dg12.taxOrExitRequirements),
        "frontImageSha256": dg12.frontImage.map { extLdsHex(calcSHA256Hash($0)) } ?? NSNull(),
        "rearImageSha256": dg12.rearImage.map { extLdsHex(calcSHA256Hash($0)) } ?? NSNull(),
        "personalizationTime": extLdsOptional(dg12.personalizationTime),
        "personalizationDeviceSerialNr": extLdsOptional(dg12.personalizationDeviceSerialNr),
    ]
}
