// Crypto primitive conformance ops (Swift side): SCHEMA.md registry.
//
// Cipher/MAC/hash/KDF ops call the library's own declarations (the KDF class
// is internal: @testable). The ec_dh ops have no single upstream
// declaration: they are shims over the same OpenSSL BN/EC_POINT/DH/EVP
// routines PACEHandler uses, so the primitive layer is cross-checked on its
// own, apart from the PACE handshake that composes it. First executed at
// rented-Mac session S2.

import CommonCrypto
import Foundation
import OpenSSL
import XCTest

@testable import NFCPassportReader

// --- hex plumbing (harness-internal, strict) --------------------------------

private func hexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
    guard let hex = input[key] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    guard hex.count % 2 == 0,
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

private func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// BigInts travel as minimal-form hex ("" = zero); see the Dart harness.
private func minimalHex(_ bytes: [UInt8]) -> String {
    var i = 0
    while i < bytes.count && bytes[i] == 0 { i += 1 }
    return hexString(Array(bytes[i...]))
}

/// Maps a thrown library error to the code string vectors assert on
/// (upstream case names: SCHEMA.md).
private func errorCode(_ e: NFCPassportReaderError) -> String {
    let mirror = Mirror(reflecting: e)
    if let label = mirror.children.first?.label {
        return label
    }
    return String(describing: e)
}

private func mapLibraryError<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let e as NFCPassportReaderError {
        throw ConformanceOpError(code: errorCode(e))
    }
}

// --- OpenSSL helpers --------------------------------------------------------

private func nid(forCurve name: String) throws -> Int32 {
    switch name {
    case "secp192r1": return NID_X9_62_prime192v1
    case "brainpoolp192r1": return NID_brainpoolP192r1
    case "secp224r1": return NID_secp224r1
    case "brainpoolp224r1": return NID_brainpoolP224r1
    case "secp256r1": return NID_X9_62_prime256v1
    case "brainpoolp256r1": return NID_brainpoolP256r1
    case "brainpoolp320r1": return NID_brainpoolP320r1
    case "secp384r1": return NID_secp384r1
    case "brainpoolp384r1": return NID_brainpoolP384r1
    case "brainpoolp512r1": return NID_brainpoolP512r1
    case "secp521r1": return NID_secp521r1
    default: throw ConformanceOpError(code: "UnknownCurve")
    }
}

private func withGroup<T>(
    _ input: [String: Any], _ body: (OpaquePointer, Int) throws -> T
) throws -> T {
    guard let curveName = input["curve"] as? String else {
        throw ConformanceOpError(code: "MalformedInput")
    }
    guard let group = EC_GROUP_new_by_curve_name(try nid(forCurve: curveName))
    else {
        throw ConformanceOpError(code: "UnknownCurve")
    }
    defer { EC_GROUP_free(group) }
    let degree = Int(EC_GROUP_get_degree(group))
    let fieldLen = (degree + 7) / 8
    return try body(group, fieldLen)
}

private func bn(_ bytes: [UInt8]) -> OpaquePointer {
    bytes.withUnsafeBufferPointer { buf in
        BN_bin2bn(buf.baseAddress, Int32(bytes.count), nil)!
    }
}

private func bnBytes(_ v: OpaquePointer, padded length: Int? = nil) -> [UInt8] {
    if let length = length {
        var out = [UInt8](repeating: 0, count: length)
        _ = BN_bn2binpad(v, &out, Int32(length))
        return out
    }
    var out = [UInt8](repeating: 0, count: Int((BN_num_bits(v) + 7) / 8))
    _ = BN_bn2bin(v, &out)
    return out
}

private func decodePoint(
    _ group: OpaquePointer, _ encoded: [UInt8]
) throws -> OpaquePointer {
    let point = EC_POINT_new(group)!
    guard
        encoded.withUnsafeBufferPointer({ buf in
            EC_POINT_oct2point(group, point, buf.baseAddress, encoded.count, nil)
        }) == 1
    else {
        EC_POINT_free(point)
        // oct2point failure == the invalid-point reject the Dart side types
        // as InvalidDataPassed (SCHEMA.md ec_dh rows).
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    return point
}

private func encodePoint(
    _ group: OpaquePointer, _ point: OpaquePointer
) -> [UInt8] {
    let form = POINT_CONVERSION_UNCOMPRESSED
    let len = EC_POINT_point2oct(group, point, form, nil, 0, nil)
    var out = [UInt8](repeating: 0, count: len)
    _ = EC_POINT_point2oct(group, point, form, &out, len, nil)
    return out
}

/// EC_KEY synthesized from a raw private scalar (public half computed): the
/// same pattern the PACE test-seams injection uses.
private func makeECKey(
    _ group: OpaquePointer, privateScalar: OpaquePointer
) throws -> OpaquePointer {
    let key = EC_KEY_new()!
    guard EC_KEY_set_group(key, group) == 1 else {
        EC_KEY_free(key)
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    let pub = EC_POINT_new(group)!
    defer { EC_POINT_free(pub) }
    guard EC_POINT_mul(group, pub, privateScalar, nil, nil, nil) == 1,
        EC_KEY_set_private_key(key, privateScalar) == 1,
        EC_KEY_set_public_key(key, pub) == 1
    else {
        EC_KEY_free(key)
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    return key
}

// --- op registry ------------------------------------------------------------

let cryptoOps: [String: ConformanceOp] = [
    "aesEncrypt": { input in
        ["data": hexString(AESEncrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: try hexBytes(input, "iv")))]
    },
    "aesDecrypt": { input in
        ["data": hexString(AESDecrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: try hexBytes(input, "iv")))]
    },
    "aesECBEncrypt": { input in
        ["data": hexString(AESECBEncrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message")))]
    },
    "tripleDESEncrypt": { input in
        ["data": hexString(tripleDESEncrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: try hexBytes(input, "iv")))]
    },
    "tripleDESDecrypt": { input in
        ["data": hexString(tripleDESDecrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: try hexBytes(input, "iv")))]
    },
    "desEncrypt": { input in
        let ecb = input["ecb"] as? Bool ?? false
        return ["data": hexString(DESEncrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: try hexBytes(input, "iv"),
            options: ecb ? UInt32(kCCOptionECBMode) : 0))]
    },
    "desDecrypt": { input in
        // No iv in the op input: upstream ignores it; pass the
        // zero IV its CBC branch effectively runs with.
        let ecb = input["ecb"] as? Bool ?? false
        return ["data": hexString(DESDecrypt(
            key: try hexBytes(input, "key"),
            message: try hexBytes(input, "message"),
            iv: [UInt8](repeating: 0, count: 8),
            options: ecb ? UInt32(kCCOptionECBMode) : 0))]
    },
    "desMAC": { input in
        ["mac": hexString(desMAC(
            key: try hexBytes(input, "key"), msg: try hexBytes(input, "msg")))]
    },
    "aesMAC": { input in
        ["mac": hexString(aesMAC(
            key: try hexBytes(input, "key"), msg: try hexBytes(input, "msg")))]
    },
    "mac": { input in
        let algo: SecureMessagingSupportedAlgorithms
        switch input["algoName"] as? String {
        case "DES": algo = .DES
        case "AES": algo = .AES
        default: throw ConformanceOpError(code: "MalformedInput")
        }
        return ["mac": hexString(mac(
            algoName: algo,
            key: try hexBytes(input, "key"),
            msg: try hexBytes(input, "msg")))]
    },
    "calcHash": { input in
        guard let algorithm = input["algorithm"] as? String else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        return try mapLibraryError {
            ["hash": hexString(try calcHash(
                data: try hexBytes(input, "data"), hashAlgorithm: algorithm))]
        }
    },
    "deriveKey": { input in
        guard let modeName = input["mode"] as? String else {
            throw ConformanceOpError(code: "MalformedInput")
        }
        let mode: SecureMessagingSessionKeyGenerator.SMSMode
        switch modeName {
        case "ENC": mode = .ENC_MODE
        case "MAC": mode = .MAC_MODE
        case "PACE": mode = .PACE_MODE
        default: throw ConformanceOpError(code: "MalformedInput")
        }
        let nonce = input["nonce"] != nil ? try hexBytes(input, "nonce") : nil
        return try mapLibraryError {
            ["key": hexString(try SecureMessagingSessionKeyGenerator().deriveKey(
                keySeed: try hexBytes(input, "keySeed"),
                cipherAlgName: input["cipherAlgName"] as? String ?? "DESede",
                keyLength: input["keyLength"] as? Int ?? 128,
                nonce: nonce,
                mode: mode,
                paceKeyReference: UInt8(input["paceKeyReference"] as? Int ?? 0)))]
        }
    },
    "bigIntToBytes": { input in
        let v = bn(try hexBytes(input, "value"))
        defer { BN_free(v) }
        return ["data": hexString(bnBytes(v, padded: input["length"] as? Int))]
    },
    "bytesToBigInt": { input in
        let v = bn(try hexBytes(input, "data"))
        defer { BN_free(v) }
        return ["value": minimalHex(bnBytes(v))]
    },
    "ecPublicFromPrivate": { input in
        try withGroup(input) { group, _ in
            let d = bn(try hexBytes(input, "d"))
            defer { BN_free(d) }
            let q = EC_POINT_new(group)!
            defer { EC_POINT_free(q) }
            guard EC_POINT_mul(group, q, d, nil, nil, nil) == 1 else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            return ["point": hexString(encodePoint(group, q))]
        }
    },
    "ecdhSharedSecretX": { input in
        // EVP_PKEY_derive over synthesized EC_KEYs: the exact upstream
        // computeSharedSecret path, whose padded-x output is the property
        // under test.
        try withGroup(input) { group, fieldLen in
            let d = bn(try hexBytes(input, "d"))
            defer { BN_free(d) }
            let ownKey = try makeECKey(group, privateScalar: d)
            defer { EC_KEY_free(ownKey) }
            let peerPoint = try decodePoint(group, try hexBytes(input, "peer"))
            defer { EC_POINT_free(peerPoint) }
            let peerKey = EC_KEY_new()!
            defer { EC_KEY_free(peerKey) }
            guard EC_KEY_set_group(peerKey, group) == 1,
                EC_KEY_set_public_key(peerKey, peerPoint) == 1
            else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            let ownPkey = EVP_PKEY_new()!
            defer { EVP_PKEY_free(ownPkey) }
            let peerPkey = EVP_PKEY_new()!
            defer { EVP_PKEY_free(peerPkey) }
            guard EVP_PKEY_set1_EC_KEY(ownPkey, ownKey) == 1,
                EVP_PKEY_set1_EC_KEY(peerPkey, peerKey) == 1,
                let ctx = EVP_PKEY_CTX_new(ownPkey, nil)
            else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            defer { EVP_PKEY_CTX_free(ctx) }
            var secretLen = 0
            guard EVP_PKEY_derive_init(ctx) == 1,
                EVP_PKEY_derive_set_peer(ctx, peerPkey) == 1,
                EVP_PKEY_derive(ctx, nil, &secretLen) == 1
            else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            var secret = [UInt8](repeating: 0, count: secretLen)
            guard EVP_PKEY_derive(ctx, &secret, &secretLen) == 1 else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            XCTAssertEqual(secretLen, fieldLen, "EVP derive length != field length")
            return ["secret": hexString(Array(secret[0..<secretLen]))]
        }
    },
    "ecPointDecode": { input in
        try withGroup(input) { group, _ in
            let point = try decodePoint(group, try hexBytes(input, "encoded"))
            defer { EC_POINT_free(point) }
            return ["point": hexString(encodePoint(group, point))]
        }
    },
    "ecMulAdd": { input in
        try withGroup(input) { group, _ in
            let s = bn(try hexBytes(input, "s"))
            defer { BN_free(s) }
            let g = try decodePoint(group, try hexBytes(input, "g"))
            defer { EC_POINT_free(g) }
            let h = try decodePoint(group, try hexBytes(input, "h"))
            defer { EC_POINT_free(h) }
            let sg = EC_POINT_new(group)!
            defer { EC_POINT_free(sg) }
            let r = EC_POINT_new(group)!
            defer { EC_POINT_free(r) }
            // Generic s*g + h (the vectors' g is the curve generator, but the
            // op is defined over any g).
            guard EC_POINT_mul(group, sg, nil, g, s, nil) == 1,
                EC_POINT_add(group, r, sg, h, nil) == 1
            else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            return ["point": hexString(encodePoint(group, r))]
        }
    },
    "ecPointMul": { input in
        try withGroup(input) { group, _ in
            let d = bn(try hexBytes(input, "d"))
            defer { BN_free(d) }
            let p = try decodePoint(group, try hexBytes(input, "point"))
            defer { EC_POINT_free(p) }
            let r = EC_POINT_new(group)!
            defer { EC_POINT_free(r) }
            guard EC_POINT_mul(group, r, nil, p, d, nil) == 1 else {
                throw ConformanceOpError(code: "InvalidDataPassed")
            }
            return ["point": hexString(encodePoint(group, r))]
        }
    },
    "dhPublic": { input in
        let p = bn(try hexBytes(input, "p"))
        let g = bn(try hexBytes(input, "g"))
        let x = bn(try hexBytes(input, "x"))
        let y = BN_new()!
        let ctx = BN_CTX_new()!
        defer { BN_free(p); BN_free(g); BN_free(x); BN_free(y); BN_CTX_free(ctx) }
        guard BN_mod_exp(y, g, x, p, ctx) == 1 else {
            throw ConformanceOpError(code: "InvalidDataPassed")
        }
        return ["y": minimalHex(bnBytes(y))]
    },
    "dhSharedSecret": { input in
        let p = bn(try hexBytes(input, "p"))
        let x = bn(try hexBytes(input, "x"))
        let peer = bn(try hexBytes(input, "peerPublic"))
        let s = BN_new()!
        let ctx = BN_CTX_new()!
        defer { BN_free(p); BN_free(x); BN_free(peer); BN_free(s); BN_CTX_free(ctx) }
        guard BN_mod_exp(s, peer, x, p, ctx) == 1 else {
            throw ConformanceOpError(code: "InvalidDataPassed")
        }
        return ["secret": minimalHex(bnBytes(s))]
    },
]
