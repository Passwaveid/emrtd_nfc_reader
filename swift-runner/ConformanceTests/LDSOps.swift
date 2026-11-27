// LDS / SOD-oracle conformance ops (Swift side): SCHEMA.md registry.
//
// These ops drive the unmodified upstream LDS classes (DataGroup base walk,
// DataGroupParser dispatch, COM/DataGroup1/DataGroup2/SOD, FaceImageInfo)
// plus the NFCPassportModel hash-oracle slice via the test-seams
// private->internal patch (parseSODSignatureContent /
// ensureReadDataNotBeenTamperedWith).
//
// dg2.faceImageFormat is dart-only (upstream computes the branch in
// a dead private enum and exposes nothing) and is absent here; its cases are
// gated runners:["dart"].
//
// Error-code mapping: NFCPassportReaderError cases map to their case names
// (the shared convention); the upstream-only OpenSSLError /
// PassiveAuthenticationError enums (dropped by the port) map to
// THEIR case names: split vectors pin dart codes and swift codes
// separately.
//
// First executed at rented-Mac milestone session S4.

import Foundation
import XCTest

@testable import NFCPassportReader

let ldsOps: [String: ConformanceOp] = [
    "dg.parseDG": dgParseDG,
    "dg.hash": dgHash,
    "com.parse": comParse,
    "dg1.parse": dg1Parse,
    "dg2.parse": dg2Parse,
    "faceImageInfo.from": faceImageInfoFrom,
    "sod.parse": sodParse,
    "sod.encapsulatedContent": sodEncapsulatedContent,
    "sod.parseSignatureContent": sodParseSignatureContent,
    "sod.checkDataGroupHashes": sodCheckDataGroupHashes,
]

// --- hex plumbing (harness-internal, mirror of PACEOps) ------------------

private func ldsHexString(_ hex: String) throws -> [UInt8] {
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

private func ldsHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try ldsHexString(hex)
}

private func ldsHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Maps thrown upstream errors to the vector's error-code strings:
/// NFCPassportReaderError, OpenSSLError, and PassiveAuthenticationError all
/// map to their case names via Mirror.
private func ldsMapError<T>(_ body: () throws -> T) throws -> T {
    func caseName(_ e: Error) -> String {
        let mirror = Mirror(reflecting: e)
        return mirror.children.first?.label ?? "\(e)"
    }
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        throw ConformanceOpError(code: caseName(e))
    } catch let e as OpenSSLError {
        throw ConformanceOpError(code: caseName(e))
    } catch let e as PassiveAuthenticationError {
        throw ConformanceOpError(code: caseName(e))
    }
}

// --- DataGroup / parser ops -------------------------------------------------

private func dgParseDG(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let dg = try ldsMapError { try DataGroupParser().parseDG(data: data) }
    return [
        "type": String(describing: type(of: dg)),
        "datagroupType": dg.datagroupType.getName(),
        "body": ldsHex(dg.body),
    ]
}

private func dgHash(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    guard let algorythm = input["algorythm"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let dg = try ldsMapError { try DataGroupParser().parseDG(data: data) }
    return ["hash": ldsHex(dg.hash(algorythm))]
}

private func comParse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let com = try ldsMapError { try COM(data) }
    return [
        "version": com.version,
        "unicodeVersion": com.unicodeVersion,
        "dataGroupsPresent": com.dataGroupsPresent,
    ]
}

private func dg1Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let dg1 = try ldsMapError { try DataGroup1(data) }
    return ["elements": dg1.elements]
}

private func dg2Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let dg2 = try ldsMapError { try DataGroup2(data) }
    return [
        "nrImages": dg2.nrImages,
        "versionNumber": dg2.versionNumber,
        "lengthOfRecord": dg2.lengthOfRecord,
        "numberOfFacialImages": dg2.numberOfFacialImages,
        "facialRecordDataLength": dg2.facialRecordDataLength,
        "nrFeaturePoints": dg2.nrFeaturePoints,
        "gender": dg2.gender,
        "eyeColor": dg2.eyeColor,
        "hairColor": dg2.hairColor,
        "featureMask": dg2.featureMask,
        "expression": dg2.expression,
        "poseAngle": dg2.poseAngle,
        "poseAngleUncertainty": dg2.poseAngleUncertainty,
        "faceImageType": dg2.faceImageType,
        "imageDataType": dg2.imageDataType,
        "imageWidth": dg2.imageWidth,
        "imageHeight": dg2.imageHeight,
        "imageColorSpace": dg2.imageColorSpace,
        "sourceType": dg2.sourceType,
        "deviceType": dg2.deviceType,
        "quality": dg2.quality,
        "imageSha256": ldsHex(calcSHA256Hash(dg2.imageData)),
    ]
}

private func faceImageInfoFrom(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let dg2 = try ldsMapError { try DataGroup2(data) }
    let info = FaceImageInfo.from(dg2: dg2)
    func name<T>(_ v: T?) -> Any {
        v.map { String(describing: $0) } ?? NSNull()
    }
    // The port decodes the feature bitmask to a set; upstream's
    // exact-single-value Optional is emitted as [] / [name] so the shared
    // shape is a list and split cases stay comparable.
    let features: [String] = info.features.map { [String(describing: $0)] } ?? []
    return [
        "expression": name(info.expression),
        "eyeColor": name(info.eyeColor),
        "faceImageType": name(info.faceImageType),
        "features": features,
        "hairColor": name(info.hairColor),
        "imageColorSpace": name(info.imageColorSpace),
        "imageDataType": name(info.imageDataType),
        "sourceType": name(info.sourceType),
    ]
}

// --- SOD / oracle ops -------------------------------------------------------

private func sodParse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    let sod = try ldsMapError { try SOD(data) }
    return ["pkcs7CertificateData": ldsHex(sod.pkcs7CertificateData)]
}

private func sodEncapsulatedContent(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    return try ldsMapError {
        let sod = try SOD(data)
        return ["content": ldsHex([UInt8](try sod.getEncapsulatedContent()))]
    }
}

private func sodParseSignatureContent(_ input: [String: Any]) throws -> [String: Any] {
    let data = try ldsHexBytes(input, "data")
    return try ldsMapError {
        let sod = try SOD(data)
        let signedData = try sod.getEncapsulatedContent()
        let asn1Text = try OpenSSLUtils.ASN1Parse(data: signedData)
        // Internal only through seams.patch.
        let (algo, hashes) = try NFCPassportModel().parseSODSignatureContent(asn1Text)
        var hashesOut: [String: Any] = [:]
        for (id, hex) in hashes {
            hashesOut[id.getName()] = hex
        }
        return ["algorythm": algo, "hashes": hashesOut]
    }
}

private func sodCheckDataGroupHashes(_ input: [String: Any]) throws -> [String: Any] {
    let sodBytes = try ldsHexBytes(input, "sod")
    guard let dgs = input["dataGroups"] as? [String: String] else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try ldsMapError {
        let sod = try SOD(sodBytes)
        let model = NFCPassportModel()
        model.addDataGroup(.SOD, dataGroup: sod)
        let parser = DataGroupParser()
        for (name, hexData) in dgs {
            let id = DataGroupId.getIDFromName(name: name)
            let dg = try parser.parseDG(data: try ldsHexString(hexData))
            model.addDataGroup(id, dataGroup: dg)
        }

        // Algorithm via the same slice the comparison consumes.
        let asn1Text = try OpenSSLUtils.ASN1Parse(data: try sod.getEncapsulatedContent())
        let (algo, _) = try model.parseSODSignatureContent(asn1Text)

        // The dummy-signature fixture always fails CMS verification and falls
        // into the getEncapsulatedContent branch, exactly the path the Dart
        // port takes. Internal only through seams.patch.
        var errors = ""
        var passed = true
        do {
            try model.ensureReadDataNotBeenTamperedWith(useCMSVerification: false)
        } catch PassiveAuthenticationError.InvalidDataGroupHash(let msg) {
            errors = msg
            passed = false
        }

        var hashesOut: [String: Any] = [:]
        for (id, dgh) in model.dataGroupHashes {
            hashesOut[id.getName()] = [
                "id": dgh.id,
                "sodHash": dgh.sodHash,
                "computedHash": dgh.computedHash,
                "match": dgh.match,
            ]
        }
        return [
            "algorythm": algo,
            "hashes": hashesOut,
            "errors": errors,
            "passed": passed,
        ]
    }
}
