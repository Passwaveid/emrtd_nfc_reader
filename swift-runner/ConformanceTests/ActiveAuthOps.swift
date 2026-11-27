// Active Authentication / DG15 conformance ops (Swift side):
// SCHEMA.md registry.
//
// These ops drive the unmodified upstream AA classes:
//   - aaInfo.signatureAlgorithm / aaInfo.protocolOIDString
//       (ActiveAuthenticationInfo's two friendly-name tables)
//   - dg15.parse
//       (DataGroup15 over d2i_EC_PUBKEY-then-d2i_RSA_PUBKEY: the oracle for
//        the port's DG15 parse; the key fields are read back with
//        RSA_get0_key / the EC_GROUP extractors ChipAuthOps already uses)
//   - aa.verify
//       (NFCPassportModel.verifyActiveAuthentication + the public
//        activeAuthenticationPassed flag: the real thing. `scheme` and
//        `digestAlgorithm` have no upstream getter, so the two selections are
//        mirrored inline below: which DG15 key field is non-nil, and either
//        the ISO 10118-3 trailer table or verifySignature's digest chain.
//        SCHEMA.md records the substitution.)
//
// Cases that crash upstream (an RSA modulus shorter than the digest plus two
// bytes, and the zero-length ECDSA signature) are gated runners:["dart"] in
// active_auth.json and never reach this file.

import Foundation
import OpenSSL
import XCTest

@testable import NFCPassportReader

let activeAuthOps: [String: ConformanceOp] = [
    "aaInfo.signatureAlgorithm": aaInfoSignatureAlgorithm,
    "aaInfo.protocolOIDString": aaInfoProtocolOIDString,
    "dg15.parse": dg15Parse,
    "aa.verify": aaVerify,
]

// --- hex plumbing (harness-internal, mirror of ChipAuthOps) -----------------

private func activeAuthHexString(_ hex: String) throws -> [UInt8] {
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

private func activeAuthHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try activeAuthHexString(hex)
}

private func activeAuthHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func activeAuthMapError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        let mirror = Mirror(reflecting: e)
        throw ConformanceOpError(code: mirror.children.first?.label ?? "\(e)")
    } catch {
        let mirror = Mirror(reflecting: error)
        throw ConformanceOpError(code: mirror.children.first?.label ?? "\(error)")
    }
}

/// BIGNUM -> minimal big-endian hex ("" for zero): the harness convention.
private func activeAuthBnHex(_ bn: OpaquePointer?) -> String {
    guard let bn = bn else { return "" }
    let n = Int((BN_num_bits(bn) + 7) / 8)
    if n == 0 { return "" }
    var buf = [UInt8](repeating: 0, count: n)
    _ = BN_bn2bin(bn, &buf)
    return activeAuthHex(buf)
}

// --- aaInfo ops -------------------------------------------------------------

private func aaInfoSignatureAlgorithm(_ input: [String: Any]) throws -> [String: Any] {
    // `oid` is deliberately nullable here: an AA entry without a third child
    // carries no signature algorithm at all.
    let oid = input["oid"] as? String
    let info = ActiveAuthenticationInfo(
        oid: SecurityInfo.ID_AA_OID, version: 1, signatureAlgorithmOID: oid)
    return ["name": info.getSignatureAlgorithmOIDString() as Any? ?? NSNull()]
}

private func aaInfoProtocolOIDString(_ input: [String: Any]) throws -> [String: Any] {
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return ["name": ActiveAuthenticationInfo(oid: oid, version: 1)
        .getProtocolOIDString()]
}

// --- dg15.parse -------------------------------------------------------------

private func dg15Parse(_ input: [String: Any]) throws -> [String: Any] {
    let data = try activeAuthHexBytes(input, "data")
    let dg15 = try activeAuthMapError { try DataGroup15(data) }

    if let ec = dg15.ecdsaPublicKey {
        guard let raw = OpenSSLUtils.getPublicKeyData(from: ec), !raw.isEmpty,
            let ecKey = EVP_PKEY_get1_EC_KEY(ec)
        else { return ["keyType": "none"] }
        defer { EC_KEY_free(ecKey) }
        guard let group = EC_KEY_get0_group(ecKey) else {
            return ["keyType": "none"]
        }
        let ctx = BN_CTX_new()
        defer { BN_CTX_free(ctx) }
        let p = BN_new(), a = BN_new(), b = BN_new()
        defer {
            BN_free(p)
            BN_free(a)
            BN_free(b)
        }
        guard EC_GROUP_get_curve(group, p, a, b, ctx) == 1,
            let generator = EC_GROUP_get0_generator(group)
        else { return ["keyType": "none"] }
        let form = POINT_CONVERSION_UNCOMPRESSED
        let len = EC_POINT_point2oct(group, generator, form, nil, 0, nil)
        var gBytes = [UInt8](repeating: 0, count: Int(len))
        _ = EC_POINT_point2oct(group, generator, form, &gBytes, len, nil)
        let order = EC_GROUP_get0_order(group)
        let cofactor = EC_GROUP_get0_cofactor(group)
        return [
            "keyType": "ec",
            "publicKey": activeAuthHex(raw),
            "domain": [
                "p": activeAuthBnHex(p),
                "a": activeAuthBnHex(a),
                "b": activeAuthBnHex(b),
                "g": activeAuthHex(gBytes),
                "n": activeAuthBnHex(order),
                "h": cofactor == nil ? 1 : Int(BN_get_word(cofactor)),
            ],
        ]
    }

    if let rsaKey = dg15.rsaPublicKey {
        guard let rsa = EVP_PKEY_get1_RSA(rsaKey) else {
            return ["keyType": "none"]
        }
        defer { RSA_free(rsa) }
        var n: OpaquePointer?
        var e: OpaquePointer?
        var d: OpaquePointer?
        RSA_get0_key(rsa, &n, &e, &d)
        return [
            "keyType": "rsa",
            "modulus": activeAuthBnHex(n),
            "exponent": activeAuthBnHex(e),
        ]
    }

    // Both readers returned nil (garbage, a truncated structure, or a DH SPKI):
    // AA is silently unsupported.
    return ["keyType": "none"]
}

// --- aa.verify --------------------------------------------------------------

private func aaVerify(_ input: [String: Any]) throws -> [String: Any] {
    let dg15Bytes = try activeAuthHexBytes(input, "dg15")
    let challenge = try activeAuthHexBytes(input, "challenge")
    let signature = try activeAuthHexBytes(input, "signature")

    let model = NFCPassportModel()
    let dg15 = try activeAuthMapError { try DataGroup15(dg15Bytes) }
    model.addDataGroup(.DG15, dataGroup: dg15)
    var dg14: DataGroup14?
    if let dg14Hex = input["dg14"] as? String {
        dg14 = try activeAuthMapError { try DataGroup14(try activeAuthHexString(dg14Hex)) }
        model.addDataGroup(.DG14, dataGroup: dg14!)
    }

    // The real thing.
    model.verifyActiveAuthentication(challenge: challenge, signature: signature)

    return [
        "passed": model.activeAuthenticationPassed,
        "scheme": aaScheme(dg15) as Any? ?? NSNull(),
        "digestAlgorithm": aaDigestAlgorithm(dg15: dg15, dg14: dg14, signature: signature)
            as Any? ?? NSNull(),
    ]
}

/// Which branch of `verifyActiveAuthentication` ran (no upstream getter).
private func aaScheme(_ dg15: DataGroup15) -> String? {
    if dg15.rsaPublicKey != nil { return "rsa" }
    if dg15.ecdsaPublicKey != nil { return "ecdsa" }
    return nil
}

/// The digest that branch selected: the same two tables, inline.
private func aaDigestAlgorithm(
    dg15: DataGroup15, dg14: DataGroup14?, signature: [UInt8]
) -> String? {
    if let rsaKey = dg15.rsaPublicKey {
        // verifyActiveAuthentication's trailer walk (NFCPassportModel:322-348).
        guard
            var decrypted = try? OpenSSLUtils.decryptRSASignature(
                signature: Data(signature), pubKey: rsaKey)
        else { return nil }
        var trailer = decrypted.popLast() ?? 0x00
        if trailer == 0xCC { trailer = decrypted.popLast() ?? 0x00 }
        switch trailer {
        case 0xBC, 0x33: return "SHA1"
        case 0x34: return "SHA256"
        case 0x35: return "SHA512"
        case 0x36: return "SHA384"
        case 0x38: return "SHA224"
        default: return nil
        }
    }
    guard dg15.ecdsaPublicKey != nil else { return nil }
    // verifySignature's lowercase-contains chain (OpenSSLUtils:441-453),
    // including its SHA-256 default, and its missing ripemd160 arm.
    var name = ""
    if let dg14 = dg14,
        let aa = dg14.securityInfos.compactMap({ $0 as? ActiveAuthenticationInfo })
            .first
    {
        name = aa.getSignatureAlgorithmOIDString() ?? ""
    }
    name = name.lowercased()
    if name.contains("sha1") { return "SHA1" }
    if name.contains("sha224") { return "SHA224" }
    if name.contains("sha256") || name.contains("rsassapss") { return "SHA256" }
    if name.contains("sha384") { return "SHA384" }
    if name.contains("sha512") { return "SHA512" }
    return "SHA256"
}
