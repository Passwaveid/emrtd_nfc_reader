// PACE DH Generic Mapping and Integrated Mapping conformance ops (Swift
// side): SCHEMA.md registry.
//
// The Dart port completes DH Generic Mapping (steps 3-4) and implements the
// Integrated Mapping. Upstream does neither: `doStep3KeyExchange` treats
// the mapped parameters as EC unconditionally, so every DH suite dead-ends
// there, and `doPACEStep2IM` is an explicit stub. This file therefore does
// NOT reproduce the completed behavior: the IM ops (pace.imPseudoRandom /
// imMapDh / imMapEcdh) and the DH public-key validation op
// (pace.validateDhPublicKey) have no upstream analogue at all and their
// vector cases stay `runners: ["dart"]`.
//
// What it does provide is the *preserved-failure* half of the two split ops,
// so upstream's zero-relocation quirk stays pinned on this side while the
// Dart rows pin the port's resolution (h at its true integer value, and K
// left-padded to the group length):
//
//   - pace.dhMappedGenerator    ĝ = g^s·h mod p, with h read out of a
//                               DH_size buffer whose write length was ignored
//                               a secret with k leading zero bytes becomes
//                               h·256^k (the swift rows in pace_gm_dh.json)
//   - pace.dhSharedSecretBytes  the same relocation at the step-4 key-seed site
//
// These mirror `doDHMappingAgreement` (PACEHandler.swift) and
// `OpenSSLUtils.computeSharedSecret`'s DH arm respectively: the same OpenSSL
// call sequence, wrapped so a vector can drive it directly. Both pinned
// upstream sites ignore `DH_compute_key`'s return value, which is exactly the
// behavior preserved here; see UPSTREAM.md, Divergences.
//
// Transcript note: the Dart replay runner wires
// `session.ephemeralKeys.imNonce` into the port's IM nonce seam. There is no
// Swift counterpart because upstream has no IM to inject into, so every IM
// transcript is `runners: ["dart"]` and this side keeps reading only
// `mappingKey` / `ephemeralKey`; see TranscriptReplayTests. If an
// upstream PR ever lands an IM implementation, that is when the seam gets a
// Swift arm.
//
// First executed at rented-Mac session S3, with the rest of the PACE ops.

import Foundation
import OpenSSL
import XCTest

@testable import NFCPassportReader

let paceMappingOps: [String: ConformanceOp] = [
    "pace.dhMappedGenerator": dhMappedGeneratorRelocated,
    "pace.dhSharedSecretBytes": dhSharedSecretBytesRelocated,
]

// --- hex plumbing (harness-internal, mirror of CryptoOps) ----------------

private func paceMappingHexBytes(_ input: [String: Any], _ key: String) throws -> [UInt8] {
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

private func paceMappingHexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func paceMappingMinimalHex(_ bytes: [UInt8]) -> String {
    var i = 0
    while i < bytes.count && bytes[i] == 0 { i += 1 }
    return paceMappingHexString(Array(bytes[i...]))
}

private func paceMappingBn(_ bytes: [UInt8]) -> OpaquePointer {
    bytes.withUnsafeBufferPointer { buf in
        BN_bin2bn(buf.baseAddress, Int32(bytes.count), nil)!
    }
}

/// `BN_bn2bin`: minimal big-endian, leading zeros stripped.
private func paceMappingBnBytes(_ v: OpaquePointer) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: Int((BN_num_bits(v) + 7) / 8))
    _ = BN_bn2bin(v, &out)
    return out
}

/// The upstream zero-relocation shape: `DH_compute_key` writes the
/// *stripped* secret into a `DH_size(p)`-byte buffer and returns how many
/// bytes it wrote; upstream ignores that return value and reads the whole
/// buffer, so a secret with k leading zero bytes comes back as
/// stripped-bytes ‖ k **trailing** zeros.
///
/// Expressed as the byte transformation rather than through `DH_compute_key`
/// itself, so an op needs no DH structure per case; the bytes are identical
/// and they are what the vector asserts.
private func paceMappingRelocateZeros(_ secret: OpaquePointer, modulus p: OpaquePointer)
    -> [UInt8]
{
    let target = Int((BN_num_bits(p) + 7) / 8)
    var out = [UInt8](repeating: 0, count: target)
    let minimal = paceMappingBnBytes(secret)
    out.replaceSubrange(0..<minimal.count, with: minimal)
    return out
}

// --- ops --------------------------------------------------------------------

/// `doDHMappingAgreement`'s mapped generator, upstream-shaped: h carries the
/// zero relocation before the multiplication.
private func dhMappedGeneratorRelocated(_ input: [String: Any]) throws -> [String: Any] {
    let p = paceMappingBn(try paceMappingHexBytes(input, "p"))
    let g = paceMappingBn(try paceMappingHexBytes(input, "g"))
    let x = paceMappingBn(try paceMappingHexBytes(input, "x"))
    let peer = paceMappingBn(try paceMappingHexBytes(input, "peerPublic"))
    let nonce = paceMappingBn(try paceMappingHexBytes(input, "nonce"))
    let h = BN_new()!
    let bnG = BN_new()!
    let ghat = BN_new()!
    let ctx = BN_CTX_new()!
    defer {
        BN_free(p)
        BN_free(g)
        BN_free(x)
        BN_free(peer)
        BN_free(nonce)
        BN_free(h)
        BN_free(bnG)
        BN_free(ghat)
        BN_CTX_free(ctx)
    }
    // h = KA(SK_Map,IFD, PK_Map,IC): DH_compute_key's value...
    guard BN_mod_exp(h, peer, x, p, ctx) == 1 else {
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    // ...read back out of the DH_size buffer with the write length ignored.
    let relocated = paceMappingBn(paceMappingRelocateZeros(h, modulus: p))
    defer { BN_free(relocated) }
    guard BN_mod_exp(bnG, g, nonce, p, ctx) == 1,
        BN_mod_mul(ghat, bnG, relocated, p, ctx) == 1
    else {
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    return ["ghat": paceMappingMinimalHex(paceMappingBnBytes(ghat))]
}

/// `OpenSSLUtils.computeSharedSecret`'s DH arm, upstream-shaped: the step-4
/// key seed carries the same relocation.
private func dhSharedSecretBytesRelocated(_ input: [String: Any]) throws -> [String: Any]
{
    let p = paceMappingBn(try paceMappingHexBytes(input, "p"))
    let x = paceMappingBn(try paceMappingHexBytes(input, "x"))
    let peer = paceMappingBn(try paceMappingHexBytes(input, "peerPublic"))
    let s = BN_new()!
    let ctx = BN_CTX_new()!
    defer {
        BN_free(p)
        BN_free(x)
        BN_free(peer)
        BN_free(s)
        BN_CTX_free(ctx)
    }
    guard BN_mod_exp(s, peer, x, p, ctx) == 1 else {
        throw ConformanceOpError(code: "InvalidDataPassed")
    }
    return ["secret": paceMappingHexString(paceMappingRelocateZeros(s, modulus: p))]
}
