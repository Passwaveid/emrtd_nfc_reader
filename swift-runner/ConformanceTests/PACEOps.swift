// PACE / CardAccess conformance ops (Swift side): SCHEMA.md registry.
//
// These ops drive the unmodified upstream PACEInfo / CardAccess public API:
//   - paceInfo.oidInfo / paceInfo.protocolOIDString  (PACEInfo dispatch)
//   - cardAccess.securityInfos / cardAccess.paceInfo (EF.CardAccess walk)
// The OpenSSL-construction ops (pace.encodePublicKey / generateAuthentication-
// Token / dhMappedGenerator / paceInfo.parameterSpec) are dart-only vectors:
// they are validated on this side end-to-end by the pace_session_* transcripts,
// which replay the real PACEHandler through OpenSSL with keys injected
// through the PACE test seam (see TranscriptReplayTests). First executed at
// rented-Mac session S3.

import Foundation
import XCTest

@testable import NFCPassportReader

let paceOps: [String: ConformanceOp] = [
    "paceInfo.oidInfo": paceInfoOidInfo,
    "paceInfo.protocolOIDString": paceInfoProtocolOIDString,
    "cardAccess.securityInfos": cardAccessSecurityInfos,
    "cardAccess.paceInfo": cardAccessPaceInfo,
]

// --- hex plumbing (harness-internal, mirror of SMOps) --------------------

private func paceHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String, hex.count % 2 == 0,
        hex.allSatisfy({ $0.isHexDigit })
    else {
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

/// Maps a thrown NFCPassportReaderError to the vector's error-code string.
private func paceMapError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        let mirror = Mirror(reflecting: e)
        throw ConformanceOpError(code: mirror.children.first?.label ?? "\(e)")
    }
}

private func mappingTypeName(_ t: PACEMappingType) -> String {
    switch t {
    case .GM: return "GM"
    case .IM: return "IM"
    case .CAM: return "CAM"
    }
}

// --- paceInfo ops -----------------------------------------------------------

private func paceInfoOidInfo(_ input: [String: Any]) throws -> [String: Any] {
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let info = PACEInfo(oid: oid, version: 2, parameterId: nil)
    return try paceMapError {
        [
            "mappingType": mappingTypeName(try info.getMappingType()),
            "keyAgreementAlgorithm": try info.getKeyAgreementAlgorithm(),
            "cipherAlgorithm": try info.getCipherAlgorithm(),
            "digestAlgorithm": try info.getDigestAlgorithm(),
            "keyLength": try info.getKeyLength(),
        ]
    }
}

private func paceInfoProtocolOIDString(_ input: [String: Any]) throws -> [String: Any] {
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let info = PACEInfo(oid: oid, version: 2, parameterId: nil)
    return ["name": info.getProtocolOIDString()]
}

// --- cardAccess ops ---------------------------------------------------------

private func securityInfoMap(_ si: SecurityInfo) -> [String: Any] {
    if let pace = si as? PACEInfo {
        return [
            "oid": pace.getObjectIdentifier(),
            "version": pace.getVersion(),
            // Int? -> JSON null when absent (the 4-child PACEInfo case).
            "parameterId": pace.getParameterId() as Any? ?? NSNull(),
        ]
    }
    return ["oid": si.getObjectIdentifier()]
}

private func cardAccessSecurityInfos(_ input: [String: Any]) throws -> [String: Any] {
    let data = try paceHexBytes(input, "data")
    let ca = try paceMapError { try CardAccess(data) }
    return ["infos": ca.securityInfos.map(securityInfoMap)]
}

private func cardAccessPaceInfo(_ input: [String: Any]) throws -> [String: Any] {
    let data = try paceHexBytes(input, "data")
    let ca = try paceMapError { try CardAccess(data) }
    guard let pace = ca.paceInfo else {
        return ["present": false]
    }
    return [
        "oid": pace.getObjectIdentifier(),
        "version": pace.getVersion(),
        "parameterId": pace.getParameterId() as Any? ?? NSNull(),
    ]
}
