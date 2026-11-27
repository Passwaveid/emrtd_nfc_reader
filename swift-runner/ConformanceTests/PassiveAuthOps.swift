// Passive-authentication conformance ops (Swift side): SCHEMA.md registry.
//
// These ops drive the unmodified upstream passive-authentication path:
//   - pa.sodSignature  OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod:)
//                      (a throw is {valid: false})
//   - pa.trust         OpenSSLUtils.verifyTrustAndGetIssuerCertificate(
//                      x509:CAFile:) over a temp PEM written from the case's
//                      `trust` DER list (the upstream function takes a URL)
//   - pa.verify        NFCPassportModel + addDataGroup + verifyPassport(
//                      masterListURL:useCMSVerification:false), reading the
//                      three model booleans
//
// No new seams and no mainline patches were needed: `verifyPassport`,
// `addDataGroup` and the three booleans are `public`, and the two OpenSSLUtils
// statics are internal (reachable via @testable).
//
// The five dart-only ops (pa.sodSignature.detail, pa.trust.detail,
// pa.verdict, pa.masterList and x509.parse) are absent here by design and
// their cases are gated runners:["dart"]: upstream has no verdict
// taxonomy, no cause vocabulary, no weak-digest annotation, no
// signed-.ml ingestion at all, and its X509Wrapper renders dates as
// ASN1_TIME_print text with no SKI/AKI/basicConstraints accessors, so no
// field is byte-comparable. Likewise the certless-SOD case, which
// force-unwrap-crashes upstream rather than throwing.
//
// Time: OpenSSL's chain check has no time injection, so the `verificationTime`
// input is ignored here. The fixtures make that correct: every certificate
// on a valid path runs to 2126 and the expired ones are expired on any real
// clock.

import Foundation
import XCTest

@testable import NFCPassportReader

let passiveAuthOps: [String: ConformanceOp] = [
    "pa.sodSignature": paSodSignature,
    "pa.trust": paTrust,
    "pa.verify": paVerify,
]

// --- hex plumbing (harness-internal, mirror of LDSOps) -------------------

private func passiveAuthHexString(_ hex: String) throws -> [UInt8] {
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

private func passiveAuthHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try passiveAuthHexString(hex)
}

// --- trust material --------------------------------------------------------

/// The case's `trust` array is a list of certificate DERs as hex.
/// `verifyTrustAndGetIssuerCertificate` wants a PEM **file**, so the op writes
/// one to a temporary path for the duration of the call. An empty
/// list is written as an empty file: the "no anchors" case.
private func withTrustPemFile<T>(
    _ input: [String: Any],
    _ body: (URL) throws -> T
) throws -> T {
    let hexCerts = (input["trust"] as? [String]) ?? []
    var pem = ""
    for hex in hexCerts {
        let der = Data(try passiveAuthHexString(hex))
        pem += "-----BEGIN CERTIFICATE-----\n"
        pem += der.base64EncodedString(options: [.lineLength64Characters,
                                                 .endLineWithLineFeed])
        pem += "\n-----END CERTIFICATE-----\n"
    }
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("passive-auth-trust-\(UUID().uuidString).pem")
    try pem.write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }
    return try body(url)
}

/// The DSC upstream verifies: the first certificate of the SOD's PKCS7
/// certificate set. This mirrors `validateAndExtractSigningCertificates`'
/// `.first!`, which crashes on a certless SOD; those cases are
/// dart-only, so the force-unwrap is never reached here.
private func documentSigningCertificate(_ sod: SOD) throws -> X509Wrapper {
    try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der: Data(sod.body)).first!
}

// --- ops -------------------------------------------------------------------

/// `{valid}`: the manual RFC 5652 walk upstream uses by default
/// (`useCMSVerification: false`). Any throw is a failed verification, which is
/// exactly how `ensureReadDataNotBeenTamperedWith` treats it before swallowing
/// it.
private func paSodSignature(_ input: [String: Any]) throws -> [String: Any] {
    let sodBytes = try passiveAuthHexBytes(input, "sod")
    let sod: SOD
    do {
        sod = try SOD(sodBytes)
    } catch {
        return ["valid": false]
    }
    do {
        _ = try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
        return ["valid": true]
    } catch {
        return ["valid": false]
    }
}

/// `{trusted}`: `verifyTrustAndGetIssuerCertificate` success/failure. Note
/// the preserved quirk it carries: the built chain must be longer than one, so
/// a self-signed DSC sitting in the store fails.
private func paTrust(_ input: [String: Any]) throws -> [String: Any] {
    let sodBytes = try passiveAuthHexBytes(input, "sod")
    return try withTrustPemFile(input) { caFile in
        do {
            let sod = try SOD(sodBytes)
            let dsc = try documentSigningCertificate(sod)
            switch OpenSSLUtils.verifyTrustAndGetIssuerCertificate(
                x509: dsc, CAFile: caFile
            ) {
            case .success:
                return ["trusted": true]
            case .failure:
                return ["trusted": false]
            }
        } catch {
            return ["trusted": false]
        }
    }
}

/// The boolean triple, straight off the model: the shared shape the Dart
/// runner computes from its verification verdict.
private func paVerify(_ input: [String: Any]) throws -> [String: Any] {
    let sodBytes = try passiveAuthHexBytes(input, "sod")
    let dgs = (input["dataGroups"] as? [String: String]) ?? [:]
    return try withTrustPemFile(input) { caFile in
        let model = NFCPassportModel()
        let sod = try SOD(sodBytes)
        model.addDataGroup(.SOD, dataGroup: sod)
        let parser = DataGroupParser()
        for (name, hexData) in dgs {
            let id = DataGroupId.getIDFromName(name: name)
            let dg = try parser.parseDG(data: try passiveAuthHexString(hexData))
            model.addDataGroup(id, dataGroup: dg)
        }
        // `verifyPassport` never throws: it accumulates into
        // verificationErrors and leaves the booleans as the record.
        model.verifyPassport(masterListURL: caFile, useCMSVerification: false)
        return [
            "passportCorrectlySigned": model.passportCorrectlySigned,
            "documentSigningCertificateVerified":
                model.documentSigningCertificateVerified,
            "passportDataNotTampered": model.passportDataNotTampered,
        ]
    }
}
