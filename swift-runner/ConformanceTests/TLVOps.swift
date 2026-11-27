// Byte/TLV conformance ops (Swift side): SCHEMA.md registry.
//
// Every op calls the upstream declaration SCHEMA.md names: the public free
// functions in Utils.swift, OpenSSLUtils.asn1EncodeOID (internal, reached via
// @testable) and Apple's TKBERTLVRecord for the TlvRecord ops. Op functions
// carry a `tlv` prefix so they never shadow the upstream globals they call.

import CryptoTokenKit
import Foundation
import XCTest

@testable import NFCPassportReader

let tlvOps: [String: ConformanceOp] = [
    "asn1Length": tlvAsn1Length,
    "toAsn1Length": tlvToAsn1Length,
    "tlvRecord.encode": tlvRecordEncode,
    "tlvRecord.fromRecords": tlvRecordFromRecords,
    "tlvRecord.parse": tlvRecordParse,
    "tlvRecord.sequenceOfRecords": tlvRecordSequenceOfRecords,
    "wrapDO": tlvWrapDO,
    "unwrapDO": tlvUnwrapDO,
    "oid.encode": tlvOidEncode,
    "oid.toBytes": tlvOidToBytes,
    // oid.decode is dart-only (SCHEMA.md: no upstream decoder).
    "pad": tlvPad,
    "unpad": tlvUnpad,
    "hexRepToBin": tlvHexRepToBin,
    "intToBin": tlvIntToBin,
    "binToInt": tlvBinToInt,
    "binToHexBytes": tlvBinToHexBytes,
    "intToBytes": tlvIntToBytes,
    "xor": tlvXor,
    "binToHexRep": tlvBinToHexRep,
]

// --- plumbing (harness-internal, mirror of APDUOps) ----------------------

private func tlvHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
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

private func tlvHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func tlvInt(_ input: [String: Any], _ key: String) throws -> Int {
    guard let value = input[key] as? Int else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return value
}

private func tlvBool(_ input: [String: Any], _ key: String) throws -> Bool {
    guard let value = input[key] as? Bool else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return value
}

private func tlvString(_ input: [String: Any], _ key: String) throws -> String {
    guard let value = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return value
}

/// Tags travel as hex strings read as the raw tag bytes' big-endian value
/// (SCHEMA.md), exactly TKTLVTag's representation.
private func tlvTag(_ input: [String: Any], _ key: String) throws -> UInt64 {
    guard let hex = input[key] as? String, let tag = UInt64(hex, radix: 16) else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return tag
}

private func tlvTagByte(_ input: [String: Any], _ key: String) throws -> UInt8 {
    guard let tag = UInt8(exactly: try tlvTag(input, key)) else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return tag
}

/// Lowercase, minimal, even width: the Dart harness's `_tagHex`.
private func tlvTagHex(_ tag: UInt64) -> String {
    let hex = String(tag, radix: 16)
    return hex.count % 2 == 1 ? "0" + hex : hex
}

private func tlvRecordMap(_ record: TKTLVRecord) -> [String: Any] {
    ["tag": tlvTagHex(record.tag), "value": tlvHex([UInt8](record.value))]
}

private func tlvMapError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        throw ConformanceOpError(code: Mirror(reflecting: e).children.first?.label ?? "\(e)")
    }
}

// --- ops --------------------------------------------------------------------

private func tlvAsn1Length(_ input: [String: Any]) throws -> [String: Any] {
    let data = try tlvHexBytes(input, "data")
    let (length, lengthBytes) = try tlvMapError { try asn1Length(data) }
    return ["length": length, "lengthBytes": lengthBytes]
}

private func tlvToAsn1Length(_ input: [String: Any]) throws -> [String: Any] {
    let length = try tlvInt(input, "length")
    return ["data": tlvHex(try tlvMapError { try toAsn1Length(length) })]
}

private func tlvRecordEncode(_ input: [String: Any]) throws -> [String: Any] {
    let record = TKBERTLVRecord(
        tag: try tlvTag(input, "tag"), value: Data(try tlvHexBytes(input, "value")))
    return ["data": tlvHex([UInt8](record.data))]
}

private func tlvRecordFromRecords(_ input: [String: Any]) throws -> [String: Any] {
    guard let children = input["records"] as? [[String: Any]] else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let records: [TKTLVRecord] = try children.map { child in
        TKBERTLVRecord(
            tag: try tlvTag(child, "tag"), value: Data(try tlvHexBytes(child, "value")))
    }
    let record = TKBERTLVRecord(tag: try tlvTag(input, "tag"), records: records)
    return ["data": tlvHex([UInt8](record.data))]
}

private func tlvRecordParse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try tlvHexBytes(input, "data")
    guard let record = TKBERTLVRecord(from: Data(data)) else {
        return ["record": NSNull()]
    }
    return ["record": tlvRecordMap(record)]
}

private func tlvRecordSequenceOfRecords(_ input: [String: Any]) throws -> [String: Any] {
    let data = try tlvHexBytes(input, "data")
    guard let records = TKBERTLVRecord.sequenceOfRecords(from: Data(data)) else {
        return ["records": NSNull()]
    }
    return ["records": records.map(tlvRecordMap)]
}

private func tlvWrapDO(_ input: [String: Any]) throws -> [String: Any] {
    let tag = try tlvTagByte(input, "tag")
    return ["data": tlvHex(wrapDO(b: tag, arr: try tlvHexBytes(input, "value")))]
}

private func tlvUnwrapDO(_ input: [String: Any]) throws -> [String: Any] {
    let tag = try tlvTagByte(input, "tag")
    let data = try tlvHexBytes(input, "data")
    let value = try tlvMapError { try unwrapDO(tag: tag, wrappedData: data) }
    return ["value": tlvHex(value)]
}

private func tlvOidEncode(_ input: [String: Any]) throws -> [String: Any] {
    ["data": tlvHex(OpenSSLUtils.asn1EncodeOID(oid: try tlvString(input, "oid")))]
}

private func tlvOidToBytes(_ input: [String: Any]) throws -> [String: Any] {
    let oid = try tlvString(input, "oid")
    let replaceTag = try tlvBool(input, "replaceTag")
    return ["data": tlvHex(oidToBytes(oid: oid, replaceTag: replaceTag))]
}

private func tlvPad(_ input: [String: Any]) throws -> [String: Any] {
    let data = try tlvHexBytes(input, "data")
    let blockSize = try tlvInt(input, "blockSize")
    return ["data": tlvHex(pad(data, blockSize: blockSize))]
}

private func tlvUnpad(_ input: [String: Any]) throws -> [String: Any] {
    ["data": tlvHex(unpad(try tlvHexBytes(input, "data")))]
}

private func tlvHexRepToBin(_ input: [String: Any]) throws -> [String: Any] {
    ["data": tlvHex(hexRepToBin(try tlvString(input, "hex")))]
}

private func tlvIntToBin(_ input: [String: Any]) throws -> [String: Any] {
    let value = try tlvInt(input, "value")
    let width = try tlvInt(input, "pad")
    return ["data": tlvHex(intToBin(value, pad: width))]
}

private func tlvBinToInt(_ input: [String: Any]) throws -> [String: Any] {
    ["value": binToInt(try tlvHexBytes(input, "data"))]
}

private func tlvBinToHexBytes(_ input: [String: Any]) throws -> [String: Any] {
    let value: UInt64 = binToHex(try tlvHexBytes(input, "data"))
    guard let int = Int(exactly: value) else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return ["value": int]
}

private func tlvIntToBytes(_ input: [String: Any]) throws -> [String: Any] {
    let value = try tlvInt(input, "value")
    let removePadding = try tlvBool(input, "removePadding")
    return ["data": tlvHex(intToBytes(val: value, removePadding: removePadding))]
}

private func tlvXor(_ input: [String: Any]) throws -> [String: Any] {
    let a = try tlvHexBytes(input, "a")
    let b = try tlvHexBytes(input, "b")
    return ["data": tlvHex(xor(a, b))]
}

private func tlvBinToHexRep(_ input: [String: Any]) throws -> [String: Any] {
    let data = try tlvHexBytes(input, "data")
    let asArray = try tlvBool(input, "asArray")
    return ["rep": binToHexRep(data, asArray: asArray)]
}
