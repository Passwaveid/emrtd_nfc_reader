// Chip Authentication / DG14 conformance ops (Swift side):
// SCHEMA.md registry.
//
// These ops drive the unmodified upstream CA classes:
//   - chipAuthInfo.oidInfo / chipAuthPublicKeyInfo.protocolOIDString
//       (ChipAuthenticationInfo / ChipAuthenticationPublicKeyInfo dispatch)
//   - spki.publicKeyData
//       (d2i_PUBKEY + OpenSSLUtils.getPublicKeyData: the oracle for the
//        port's Dart SubjectPublicKeyInfo parser)
//   - chipAuth.deriveSessionKeys
//       (restartSecureMessaging's body minus the SecureMessaging install)
//   - chipAuth.inferOid
//       (the same table ChipAuthenticationHandler.inferOID holds; that method
//        is private and needs a DG14 + TagReader to reach, so it is spelled
//        out here: SCHEMA.md records the substitution)
//   - dg14.securityInfos  (DataGroup14 over SecurityInfo.getInstance)
//
// Reject cases that are only observable on the Dart side (RSA keys, hybrid
// point encodings, unknown named curves, non-zero BIT STRING unused-bits) are
// gated runners:["dart"] in chip_auth.json; d2i_PUBKEY either accepts them or
// returns nil indistinguishably from the other nil paths.

import Foundation
import OpenSSL
import XCTest

@testable import NFCPassportReader

let chipAuthOps: [String: ConformanceOp] = [
    "chipAuthInfo.oidInfo": chipAuthInfoOidInfo,
    "chipAuthPublicKeyInfo.protocolOIDString": chipAuthPublicKeyInfoOIDString,
    "spki.publicKeyData": spkiPublicKeyData,
    "chipAuth.deriveSessionKeys": chipAuthDeriveSessionKeys,
    "chipAuth.inferOid": chipAuthInferOid,
    "dg14.securityInfos": dg14SecurityInfos,
]

// --- hex plumbing (harness-internal, mirror of LDSOps) -------------------

private func chipAuthHexString(_ hex: String) throws -> [UInt8] {
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

private func chipAuthHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try chipAuthHexString(hex)
}

private func chipAuthHex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func chipAuthMapError<T>(_ body: () throws -> T) throws -> T {
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

/// BIGNUM -> minimal big-endian hex ("" for zero): the harness's BigInt
/// convention (SCHEMA.md), and exactly BN_bn2bin's output.
private func bnHex(_ bn: OpaquePointer?) -> String {
    guard let bn = bn else { return "" }
    let n = Int((BN_num_bits(bn) + 7) / 8)
    if n == 0 { return "" }
    var buf = [UInt8](repeating: 0, count: n)
    _ = BN_bn2bin(bn, &buf)
    return chipAuthHex(buf)
}

// --- chipAuthInfo / chipAuthPublicKeyInfo ops -------------------------------

private func chipAuthInfoOidInfo(_ input: [String: Any]) throws -> [String: Any] {
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    return try chipAuthMapError {
        [
            "keyAgreementAlgorithm": try ChipAuthenticationInfo
                .toKeyAgreementAlgorithm(oid: oid),
            "cipherAlgorithm": try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid),
            "keyLength": try ChipAuthenticationInfo.toKeyLength(oid: oid),
            "protocolOIDString": ChipAuthenticationInfo(oid: oid, version: 1)
                .getProtocolOIDString(),
        ]
    }
}

/// A canned EC SubjectPublicKeyInfo: `ChipAuthenticationPublicKeyInfo`
/// requires a non-optional `pubKey`, which `getProtocolOIDString()` never
/// reads (SCHEMA.md).
private let cannedSpkiHex =
    "3059301306072a8648ce3d020106082a8648ce3d030107034200045fe81cc7fb7e41a3"
    + "eb257eb565c7608a7d133e1098a0ab8777a3e07dd54aad91e15bb5f150e5b2a1df3e"
    + "56cc14ac79031687ea81eadffb28c17dcb1cd7dffcc7"

private func decodePublicKey(_ der: [UInt8]) -> OpaquePointer? {
    var key: OpaquePointer?
    _ = der.withUnsafeBytes { ptr in
        var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
        key = d2i_PUBKEY(nil, &newPtr, der.count)
    }
    return key
}

private func chipAuthPublicKeyInfoOIDString(_ input: [String: Any]) throws
    -> [String: Any]
{
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    guard let canned = decodePublicKey(try chipAuthHexString(cannedSpkiHex)) else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    defer { EVP_PKEY_free(canned) }
    let info = ChipAuthenticationPublicKeyInfo(oid: oid, pubKey: canned)
    return ["name": info.getProtocolOIDString()]
}

// --- spki.publicKeyData -----------------------------------------------------

private func spkiPublicKeyData(_ input: [String: Any]) throws -> [String: Any] {
    let der = try chipAuthHexBytes(input, "data")
    guard let key = decodePublicKey(der) else {
        return ["parsed": false]
    }
    defer { EVP_PKEY_free(key) }
    guard let raw = OpenSSLUtils.getPublicKeyData(from: key), !raw.isEmpty else {
        // Neither the DH nor the EC branch fired (e.g. an RSA key): upstream
        // would hand ChipAuthenticationHandler a key it cannot use. The port
        // refuses the entry outright, so those cases are dart-only.
        return ["parsed": false]
    }

    let keyType = EVP_PKEY_get_base_id(key)
    if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
        guard let dh = EVP_PKEY_get1_DH(key) else { return ["parsed": false] }
        defer { DH_free(dh) }
        var p: OpaquePointer?
        var q: OpaquePointer?
        var g: OpaquePointer?
        DH_get0_pqg(dh, &p, &q, &g)
        return [
            "parsed": true,
            "kind": "dh",
            "publicKey": chipAuthHex(raw),
            "domain": [
                "p": bnHex(p),
                "g": bnHex(g),
                "q": q == nil ? NSNull() : bnHex(q) as Any,
            ],
        ]
    }

    guard let ec = EVP_PKEY_get1_EC_KEY(key) else { return ["parsed": false] }
    defer { EC_KEY_free(ec) }
    guard let group = EC_KEY_get0_group(ec) else { return ["parsed": false] }
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
    else { return ["parsed": false] }

    let form = POINT_CONVERSION_UNCOMPRESSED
    let len = EC_POINT_point2oct(group, generator, form, nil, 0, nil)
    var gBytes = [UInt8](repeating: 0, count: Int(len))
    _ = EC_POINT_point2oct(group, generator, form, &gBytes, len, nil)

    let order = EC_GROUP_get0_order(group)
    let cofactor = EC_GROUP_get0_cofactor(group)
    return [
        "parsed": true,
        "kind": "ec",
        "publicKey": chipAuthHex(raw),
        "domain": [
            "p": bnHex(p),
            "a": bnHex(a),
            "b": bnHex(b),
            "g": chipAuthHex(gBytes),
            "n": bnHex(order),
            "h": cofactor == nil ? 1 : Int(BN_get_word(cofactor)),
        ],
    ]
}

// --- chipAuth.deriveSessionKeys / inferOid ----------------------------------

private func chipAuthDeriveSessionKeys(_ input: [String: Any]) throws
    -> [String: Any]
{
    guard let oid = input["oid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    let keySeed = try chipAuthHexBytes(input, "keySeed")
    return try chipAuthMapError {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(
            keySeed: keySeed, cipherAlgName: cipherAlg, keyLength: keyLength,
            mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(
            keySeed: keySeed, cipherAlgName: cipherAlg, keyLength: keyLength,
            mode: .MAC_MODE)
        return ["ksEnc": chipAuthHex(ksEnc), "ksMac": chipAuthHex(ksMac)]
    }
}

private func chipAuthInferOid(_ input: [String: Any]) throws -> [String: Any] {
    guard let oid = input["publicKeyOid"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    // ChipAuthenticationHandler.inferOID, spelled out (it is private there and
    // reachable only through a live handshake).
    if oid == SecurityInfo.ID_PK_ECDH_OID {
        return ["oid": SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID]
    }
    if oid == SecurityInfo.ID_PK_DH_OID {
        return ["oid": SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID]
    }
    return ["oid": NSNull()]
}

// --- dg14.securityInfos -----------------------------------------------------

private func securityInfoRow(_ si: SecurityInfo) -> [String: Any] {
    if let ca = si as? ChipAuthenticationInfo {
        return [
            "type": "ChipAuthenticationInfo",
            "oid": ca.getObjectIdentifier(),
            "version": ca.version,
            "keyId": ca.keyId as Any? ?? NSNull(),
        ]
    }
    if let pk = si as? ChipAuthenticationPublicKeyInfo {
        return [
            "type": "ChipAuthenticationPublicKeyInfo",
            "oid": pk.getObjectIdentifier(),
            "keyId": pk.keyId as Any? ?? NSNull(),
        ]
    }
    if let pace = si as? PACEInfo {
        return [
            "type": "PACEInfo",
            "oid": pace.getObjectIdentifier(),
            "version": pace.getVersion(),
            "parameterId": pace.getParameterId() as Any? ?? NSNull(),
        ]
    }
    if let aa = si as? ActiveAuthenticationInfo {
        return [
            "type": "ActiveAuthenticationInfo",
            "oid": aa.getObjectIdentifier(),
            "version": aa.version,
            "signatureAlgorithmOID": aa.signatureAlgorithmOID as Any? ?? NSNull(),
        ]
    }
    return ["type": String(describing: type(of: si)), "oid": si.getObjectIdentifier()]
}

private func dg14SecurityInfos(_ input: [String: Any]) throws -> [String: Any] {
    let data = try chipAuthHexBytes(input, "data")
    let dg14 = try chipAuthMapError { try DataGroup14(data) }
    return ["infos": dg14.securityInfos.map(securityInfoRow)]
}
