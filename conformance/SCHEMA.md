# Conformance vector schema: v1

One language-neutral test set, consumed by two thin runners: Dart
(`test/conformance/runner_test.dart`, gates every push in CI) and Swift (the
`ConformanceTests` XCTest target in `../swift-runner/ConformanceTests/`,
assembled against upstream at the pin and executed in rented-Mac milestone
sessions; see `../swift-runner/README.md`). Rule of work:
no protocol behavior lands without a vector or transcript covering it first.

## Vector file format

One JSON file per suite under `vectors/`, named `<suite>.json`:

```jsonc
{
  "suite": "tlv",                    // matches filename
  "schemaVersion": 1,
  "description": "...",
  "runners": ["dart", "swift"],      // suite-level applicability
  "cases": [
    {
      "name": "asn1Length short form 0x7F",
      "op": "asn1Length",            // dispatch key; registry below
      "runners": ["dart"],           // optional per-case override (e.g. upstream would crash, not throw)
      "input": { "data": "7f" },     // hex: lowercase, no 0x, no separators
      "expect": { "out": { "length": 127, "lengthBytes": 1 } }
      // or     { "error": "CannotDecodeASN1Length" }: codes = upstream case names
    }
  ]
}
```

## Rules

- **Byte values are hex strings**: lowercase, no `0x` prefix, no separators.
  Integers are JSON numbers. TLV tags also travel as hex strings (`"7f49"`),
  read as the raw tag bytes' big-endian value.
- **Error codes are upstream case names** (`NFCPassportReaderError` cases),
  so both runners assert the same identifier. One extra code exists for
  dart-only guard rejections where upstream *crashes* rather than throws:
  `ArgumentError`. Cases using it are always `runners: ["dart"]`.
- **Every op added to the registry names its Dart entry point and its Swift
  entry point**, or `swift: none` with a reason. Skips are visible, never
  silent: a suite or case gated off a runner via `runners` is reported as
  skipped by that runner.
- **A runner encountering an unknown op fails.** Runner updates must accompany
  new vectors.
- `runners` at suite level gates the whole file; a per-case `runners` array
  overrides it for that case (used where upstream would crash rather than
  throw, or for a Dart-only addition; see `../UPSTREAM.md`, Divergences).
- **Runner names are opaque identifiers, and the arrays in this directory
  name only the two reference runners kept in this repository.** Each runner
  selects cases by testing for its own name and ignores names it does not
  know. A runner maintained in another codebase keeps its own map of the
  suites and ops it claims, and skips any case that carries a per-case
  `runners` array (a per-case array marks a case one reference runner cannot
  run (a divergence, a crash-class deviation or a dart-only addition) and an
  outside runner takes no side in it). It does not tag these files, so the
  vectors never encode a consumer's coverage.

## Op registry

Dart entry points live in `lib/src/` (`utils.dart`, `lds/tlv.dart`,
`crypto/*.dart`); Swift entry points are upstream declarations at the pinned
upstream commit (`OpenSSLUtils.asn1EncodeOID` and the KDF class
`SecureMessagingSessionKeyGenerator` are `internal`, visible via
`@testable`; `TlvRecord` ops map to Apple's public `TKBERTLVRecord`), plus
(for the EC/DH primitive layer, which has no single upstream declaration)
small shims in the `ConformanceTests` target calling the same OpenSSL
BN/EC_POINT/DH routines `PACEHandler` uses.

| op | suite | dart entry point | swift entry point | error codes |
|---|---|---|---|---|
| `asn1Length` | tlv | `asn1Length` | `asn1Length` | `CannotDecodeASN1Length` |
| `toAsn1Length` | tlv | `toAsn1Length` | `toAsn1Length` | `InvalidASN1Value` |
| `tlvRecord.encode` | tlv | `TlvRecord(tag, value).data` | `TKBERTLVRecord(tag:value:).data` | |
| `tlvRecord.fromRecords` | tlv | `TlvRecord.fromRecords(tag, records).data` | `TKBERTLVRecord(tag:records:).data` | |
| `tlvRecord.parse` | tlv | `TlvRecord.parse` | `TKBERTLVRecord(from:)` | (`record: null` on malformed); length forms `0x85`+ are null on the port and accepted by `TKBERTLVRecord`: split |
| `tlvRecord.sequenceOfRecords` | tlv | `TlvRecord.sequenceOfRecords` | `TKBERTLVRecord.sequenceOfRecords(from:)` | (`records: null` on malformed) |
| `wrapDO` | tlv | `wrapDO` | `wrapDO(b:arr:)` | |
| `unwrapDO` | tlv | `unwrapDO` | `unwrapDO(tag:wrappedData:)` | `InvalidASN1Value` |
| `oid.encode` | tlv | `asn1EncodeOid` | `OpenSSLUtils.asn1EncodeOID` (`@testable`) | |
| `oid.toBytes` | tlv | `oidToBytes` | `oidToBytes(oid:replaceTag:)` | |
| `oid.decode` | tlv | `asn1DecodeOid` | none: no upstream decoder (a Dart-only addition); pinned via encoder round-trips, cases dart-only | `InvalidASN1Value` |
| `pad` | tlv | `pad` | `pad(_:blockSize:)` | |
| `unpad` | tlv | `unpad` | `unpad(_:)` | `InvalidDataPassed` |
| `hexRepToBin` | tlv | `hexRepToBin` | `hexRepToBin` | |
| `intToBin` | tlv | `intToBin` | `intToBin(_:pad:)` | |
| `binToInt` | tlv | `binToInt` | `binToInt` | `ArgumentError` (dart-only) |
| `binToHexBytes` | tlv | `binToHexBytes` | `binToHex([UInt8]) -> UInt64` | `ArgumentError` (dart-only) |
| `intToBytes` | tlv | `intToBytes` | `intToBytes(val:removePadding:)` | `ArgumentError` (dart-only) |
| `xor` | tlv | `xor` | `xor` | `ArgumentError` (dart-only) |
| `binToHexRep` | tlv | `binToHexRep` | `binToHexRep(_:asArray:)` | |
| `aesEncrypt` | cipher | `aesEncrypt` | `AESEncrypt(key:message:iv:)` | `InvalidDataPassed` (dart-only: upstream returns `[]`) |
| `aesDecrypt` | cipher | `aesDecrypt` | `AESDecrypt(key:message:iv:)` | `InvalidDataPassed` (dart-only) |
| `aesECBEncrypt` | cipher | `aesECBEncrypt` | `AESECBEncrypt(key:message:)` | `InvalidDataPassed` (dart-only) |
| `tripleDESEncrypt` | cipher | `tripleDESEncrypt` | `tripleDESEncrypt(key:message:iv:)` | `InvalidDataPassed` (dart-only) |
| `tripleDESDecrypt` | cipher | `tripleDESDecrypt` | `tripleDESDecrypt(key:message:iv:)` | `InvalidDataPassed` (dart-only) |
| `desEncrypt` | cipher | `desEncrypt` | `DESEncrypt(key:message:iv:options:)` (`ecb` -> `kCCOptionECBMode`) | `InvalidDataPassed` (dart-only) |
| `desDecrypt` | cipher | `desDecrypt` | `DESDecrypt(key:message:iv:options:)` (iv ignored upstream) | `InvalidDataPassed` (dart-only) |
| `desMAC` | cipher | `desMAC` | `desMAC(key:msg:)` | `InvalidDataPassed` (dart-only) |
| `aesMAC` | cipher | `aesMAC` | `aesMAC(key:msg:)` | `InvalidDataPassed` (dart-only) |
| `mac` | cipher | `mac` | `mac(algoName:key:msg:)` | |
| `calcHash` | cipher | `calcHash` | `calcHash(data:hashAlgorithm:)` | `InvalidHashAlgorithmSpecified` |
| `deriveKey` | kdf_bac, kdf_pace, pace_gm_dh, pace_im | `SecureMessagingSessionKeyGenerator.deriveKey` | same (`internal`, `@testable`) | `InvalidDataPassed` |
| `bigIntToBytes` | ec_dh | `bigIntToBytes` | shim: `BN_bn2bin` / `BN_bn2binpad` | `ArgumentError` (dart-only) |
| `bytesToBigInt` | ec_dh | `bytesToBigInt` | shim: `BN_bin2bn` | |
| `ecPublicFromPrivate` | ec_dh | `ecPublicFromPrivate` | shim: `EC_POINT_mul(group, q, d, nil, nil, ctx)` | `InvalidDataPassed` (guard cases dart-only) |
| `ecdhSharedSecretX` | ec_dh | `ecdhSharedSecretX` | shim: `EVP_PKEY_derive` over synthesized `EC_KEY`s | |
| `ecPointDecode` | ec_dh | `ecPointDecode` (validated; re-encoded uncompressed out) | shim: `EC_POINT_oct2point` + `point2oct` | `InvalidDataPassed`: infinity/hybrid/range rejects dart-only (stricter than `oct2point`) |
| `ecMulAdd` | ec_dh | `ecMulAdd` | shim: `EC_POINT_mul(group, r, s, h?, ...)` composition | |
| `ecPointMul` | ec_dh | `ecPointMul` | shim: `EC_POINT_mul(group, r, nil, p, d, ctx)` | |
| `dhPublic` | ec_dh | `dhPublic` | shim: `BN_mod_exp` | |
| `dhSharedSecret` | ec_dh | `dhSharedSecret` | shim: `BN_mod_exp` | |
| `apdu.encode` | apdu | `CommandAPDU(...).encode()` | none: CoreNFC exposes no wire encoding; cases dart-only | `InvalidDataPassed` |
| `apdu.parse` | apdu | `CommandAPDU.parse` | `NFCISO7816APDU(data:)` field extraction; nil -> `UnexpectedError` (the upstream call-site mapping); `le` read through `conformanceLe`, which maps CoreNFC's 0 for a case-4S Le `00` to 256 | `UnexpectedError` |
| `apdu.response` | apdu | `TagReader.send` over a canned transceiver (responses fed in order; commands not asserted: that's the transcript layer's job) | `TagReader.send` over the mock `NFCISO7816Tag` (`ConformanceTests/APDUOps`, runs at S2) | `ResponseError`, `InvalidMRZKey` |
| `apdu.statusMessages` | apdu | `decodeError` (top-level in `proto/tag_reader.dart`) | none: `private` upstream (`@testable` reaches `internal` only); upstream text observable only inside `ResponseError` messages. The two rows the port corrects carry the upstream text in case comments | |
| `apdu.commandBuild` | apdu | TagReader command method over a capturing transceiver -> first emitted command's structured fields (wire bytes pinned by sibling `apdu.encode` cases) | same TagReader methods over the mock tag (S2) | |
| `readLength.fit` | read_length | `fitReadLength(requested:, maxTransceiveLength:, smBlockSize:)` -> `{length}`: the largest READ BINARY length whose response frame (SM overhead included) fits the cap | none: upstream clamps nothing (CoreNFC owned the transport); cases dart-only | (total) |
| `atrInfo.parse` | atr_info | `parseExtendedLengthInfo(data)` -> `{present, maxCommandBytes, maxResponseBytes}` or `{present:false}`: the ISO 7816-4 `7F66` template among EF.ATR/INFO's DOs | none: upstream never reads EF.ATR/INFO; cases dart-only | (total: malformed is `present:false`) |
| `sm.protect` | sm_des, sm_aes | `SecureMessaging(...).protect(cmd, useExtendedMode)` -> protected command's structured fields | same (`protect(apdu:useExtendedMode:)`, `@testable`) | `InvalidDataPassed` |
| `sm.unprotect` | sm_des, sm_aes | `SecureMessaging(...).unprotect(rapdu)` -> `{data, sw}` | same (`unprotect(rapdu:)`) | `InvalidResponseChecksum`, `MissingMandatoryFields`, `D087Malformed`, `InvalidDataPassed` (the bounds-checked length guards are dart-only) |
| `sm.exchange` | sm_des, sm_aes | `protect`/`unprotect` interleaved over one session: pins the SSC trajectory across both directions | same, one `SecureMessaging` instance | (as `sm.unprotect`) |
| `bac.generateInitialKseed` | bac_auth | `BACHandler.generateInitialKseed` | same (`internal`, `@testable`) | |
| `bac.deriveDocumentBasicAccessKeys` | bac_auth | `BACHandler.deriveDocumentBasicAccessKeys` | same (`internal`) | `InvalidDataPassed` |
| `bac.authentication` | bac_auth | `BACHandler.authentication` under the injected RNG | same, `_emrtdRandomSource` test seam | |
| `bac.sessionKeys` | bac_auth | `BACHandler.sessionKeys` (response MAC + RND.IFD echo verified) | same (`public`): upstream accepts tampered input, so the swift-side split cases return keys where dart throws | `InvalidResponseChecksum`, `InvalidDataPassed` |
| `bac.composeMrzKey` | bac_auth | `composeMrzKey` (top-level in `proto/bac.dart`) | none: a Dart-only addition, no upstream equivalent; cases dart-only | `InvalidDataPassed` |
| `paceInfo.oidInfo` | pace_gm_ecdh, pace_gm_dh, pace_im, pace_cam | `PACEInfo.getMappingType/getKeyAgreementAlgorithm/getCipherAlgorithm/getDigestAlgorithm/getKeyLength` | same (`public`, PACEOps) | `InvalidDataPassed` |
| `paceInfo.protocolOIDString` | pace_im, pace_cam | `PACEInfo(...).getProtocolOIDString()` | same (`@testable`, PACEOps) | |
| `paceInfo.parameterSpec` | pace_gm_ecdh, pace_gm_dh | `PACEInfo(...).getParameterSpec()` -> sealed `{kind, curve}`/`{kind, p, q, g}` | none: upstream returns an OpenSSL NID `Int32`, incomparable; cases dart-only | `InvalidDataPassed` |
| `pace.encodePublicKey` | pace_gm_ecdh, pace_cam | `paceEncodePublicKey` (top-level in `proto/pace.dart`) | none for the granular op: validated end-to-end on the Swift side by the `pace_session_*` transcripts (real `PACEHandler` through OpenSSL); cases dart-only | `InvalidASN1Value` |
| `pace.generateAuthenticationToken` | pace_gm_ecdh, pace_cam | `paceGenerateAuthenticationToken` (top-level in `proto/pace.dart`) | none for the granular op: transcript-validated on Swift; cases dart-only | |
| `pace.dhMappedGenerator` | pace_gm_dh | `paceDhMappedGenerator` (top-level in `proto/pace.dart`): ĝ = g^s·h with h at its **true integer value** | shim: the same `BN_mod_exp`/`DH_compute_key` composition `doDHMappingAgreement` performs, return length ignored, so the swift rows carry upstream's zero relocation and the dart rows the resolved value (split cases) | |
| `pace.dhSharedSecretBytes` | pace_gm_dh, pace_im | `paceDhSharedSecretBytes`: the step-4 DH secret **left-padded** to byteLen(p) | shim: `DH_compute_key` into a `DH_size` buffer with the return length ignored; upstream's right-padding, hence the swift/dart split rows | |
| `pace.validateDhPublicKey` | pace_gm_dh | `paceValidateDhPublicKey` -> `{valid}`: `2 <= y <= p-2` and `y^q mod p == 1` | none: upstream feeds DO82/DO84 straight to `DH_compute_key` with no validation at all, so there is nothing to compare; cases dart-only | |
| `pace.imPseudoRandom` | pace_im | `paceImPseudoRandom` -> `{blocks, value}`: the 9303-11 §4.4.3.3.2 Figure 2 CBC construction and its reduction mod p | none: upstream's IM is an unimplemented stub; cases dart-only | `PACEError` (t/s width guards) |
| `pace.imMapDh` | pace_im | `paceImMapDh`: f_g(x) = x^((p-1)/q) mod p with the 9303-11 §4.4.3.3.2 MUST ĝ ≠ 1 | none: same reason; cases dart-only | `PACEError` (ĝ = 1) |
| `pace.imMapEcdh` | pace_im | `paceImMapEcdh`: f_G via the App B.2 affine point encoding, uncompressed point out | none: same reason; cases dart-only | `PACEError` (p ≢ 3 mod 4; R_p out of App B's `0 < t < p`; α + α² = 0) |
| `pace.createPaceKey` | kdf_pace | `paceCreatePaceKey` (top-level in `proto/pace.dart`) -> `{keyReference, keySeed, key}`: `PacePassword.{mrz,can,pin,cuk}` gives f(π) and the DO83 byte, `deriveKey(..., PACE)` gives K_π | shim possible for MRZ only (`PACEHandler.createPaceKey` exists but hardcodes the MRZ seed and never sets a non-MRZ reference); rows dart-only, swift MRZ rows S3-gated | `InvalidDataPassed` (the password charset guard) |
| `pace.camDecryptChipAuthenticationData` | pace_cam | `paceCamDecryptChipAuthenticationData` (top-level in `proto/pace.dart`) -> `{caIc, cause}`: 9303-11 §4.4.3.5.3/.4 decrypt with IV = E(KSenc, -1), method-2 unpad, §4.4.5.6 fixed-length + range check | none: upstream's DO8A handling is a commented-out block, so there is nothing to drive; cases dart-only | (total by contract: every malformed shape is `cause: "malformed"`, never a throw) |
| `pace.camVerifyChipAuthenticationData` | pace_cam | `paceCamVerifyChipAuthenticationData` (top-level in `proto/pace.dart`) -> `{verified}`: 9303-11 §4.4.3.5.2 PK_Map,IC = KA(CA_IC, PK_IC, D_IC) | none: same reason; cases dart-only | (an undecodable point is `verified: false`, never a throw) |
| `cardAccess.securityInfos` | card_access | `CardAccess(data).securityInfos` -> `[{oid, version, parameterId}]` | same (`public`, PACEOps): swift's `SimpleASN1DumpParser` path drives the version-decoding split cases | `InvalidASN1Value` (dart; swift throws the dropped `OpenSSLError`, so that case is dart-only) |
| `cardAccess.paceInfo` | card_access | `CardAccess(data).paceInfo` -> `{oid, version, parameterId}` or `{present:false}` | same (`public`/`@testable`, PACEOps) | |
| `chipAuthInfo.oidInfo` | chip_auth | `ChipAuthenticationInfo.toKeyAgreementAlgorithm/toCipherAlgorithm/toKeyLength` + `getProtocolOIDString()` | same (`internal`, `@testable`, ChipAuthOps) | `InvalidDataPassed` |
| `chipAuthPublicKeyInfo.protocolOIDString` | chip_auth | `ChipAuthenticationPublicKeyInfo(...).getProtocolOIDString()` | same: the Swift op feeds the required `pubKey: OpaquePointer` a canned `d2i_PUBKEY` key, which `getProtocolOIDString` never reads | |
| `spki.publicKeyData` | chip_auth | `parseSubjectPublicKeyInfo` -> `{parsed, kind, publicKey, domain}` for EC/DH, `{parsed, kind:"rsa", modulus, exponent}` for RSA; `{parsed:false}` on the skip contract | shim: `d2i_PUBKEY` + `OpenSSLUtils.getPublicKeyData`, with the domain read off `EC_GROUP`/`DH_get0_pqg`; nil -> `{parsed:false}` | this op's oracle contract stays the EC/DH slice: RSA cases are `runners: ["dart"]` here (upstream's `getPublicKeyData` yields `[]` for an RSA key) and the RSA arm proper is pinned by `dg15.parse`. The other dart-only rejects (hybrid points, unknown named curves, non-zero unused-bits) carry their reason in the case name |
| `chipAuth.deriveSessionKeys` | chip_auth | `chipAuthDeriveSessionKeys` (top-level in `proto/chip_authentication.dart`) -> `{ksEnc, ksMac}` | same composition inline: `toCipherAlgorithm`/`toKeyLength` into `SecureMessagingSessionKeyGenerator.deriveKey`, ENC then MAC (`restartSecureMessaging`'s body minus the SM install) | `InvalidDataPassed` |
| `chipAuth.inferOid` | chip_auth | `chipAuthInferOid` (top-level in `proto/chip_authentication.dart`) -> `{oid}` / `{oid:null}` | same table inline: upstream's `inferOID` is `private` on the handler and needs a DG14 + TagReader to reach | |
| `dg14.securityInfos` | dg14 | `DataGroup14(data).securityInfos` -> typed rows `{type, oid, version\|keyId\|parameterId\|signatureAlgorithmOID}` | same (`@testable`, ChipAuthOps); `type` via `String(describing: type(of: si))` | `InvalidASN1Value` (dart; swift throws the dropped `OpenSSLError`, so that case is dart-only); a BER-malformed entry fails the whole file upstream (`UnableToParseASN1`) and is skipped by the port: split |
| `aaInfo.signatureAlgorithm` | active_auth | `ActiveAuthenticationInfo(...).getSignatureAlgorithmOIDString()` -> `{name}` | same (`public`, ActiveAuthOps) | |
| `aaInfo.protocolOIDString` | active_auth | `ActiveAuthenticationInfo(...).getProtocolOIDString()` -> `{name}` | same (`public`, ActiveAuthOps) | |
| `dg15.parse` | dg15 | `DataGroup15(data).publicKey` -> `{keyType: "ec"\|"rsa"\|"none"}` + per-type fields (EC: uncompressed `publicKey` + the shared `domain` summary; RSA: `modulus`/`exponent` hex) | `DataGroup15(data)` + whichever key field is non-nil, with `RSA_get0_key` / the `EC_GROUP` extractors of `spki.publicKeyData` behind it (ActiveAuthOps) | (never throws on either side) |
| `aa.verify` | active_auth | `verifyActiveAuthentication(dg15:dg14:challenge:signature:)` -> `{passed, scheme, digestAlgorithm}` | `passed` from the real `NFCPassportModel.verifyActiveAuthentication` + `activeAuthenticationPassed` (`@testable`); `scheme`/`digestAlgorithm` have no upstream getter, so ActiveAuthOps mirrors the two selections inline: the DG15 key-field test and, for RSA, the same trailer table / for ECDSA the same `verifySignature` digest chain. The small-modulus case (a negative slice range upstream) and the zero-length-signature case crash upstream and are `runners:["dart"]` |
| `dg.parseDG` | com, dg1 | `DataGroupParser().parseDG(data:)` -> `{type, datagroupType, body}` (`type` = runtime class name) | same (`internal`, `@testable`, LDSOps); `type` via `String(describing: type(of: dg))` | `UnknownTag`; walk errors (`CannotDecodeASN1Length`/`TagNotValid`/`InvalidASN1Value`): the truncated-walk and short-header cases are dart-only (upstream crashes) |
| `dg.hash` | com, dg1 | `DataGroup.hash(hashAlgorythm)` over a `parseDG`-built DG | same (`public`) | `InvalidHashAlgorithmSpecified` (dart); split cases for an unknown hash name: swift pins upstream's silent `""` |
| `com.parse` | com | `COM(data)` -> `{version, unicodeVersion, dataGroupsPresent}` | same (`internal` init) | `InvalidResponse`; truncation cases dart-only |
| `dg1.parse` | dg1 | `DataGroup1(data).elements` | same | `InvalidResponse` (the two-byte-tag splits pin the code; the divergent `actualTag` is unit-test-pinned dart-side); `InvalidDataPassed` (short TD3-shaped bodies, dart-only) |
| `dg2.parse` | dg2 | `DataGroup2(data)` -> CBEFF fields + `imageSha256` (SHA-256 of `imageData`) | same; `calcSHA256Hash(dg2.imageData)` | `InvalidResponse`/`UnknownImageFormat` (the FAC-header split truth table); `InvalidDataPassed` (CBEFF walk hardening) + hostile-XLBox `UnknownImageFormat` dart-only; every ISO/IEC 39794-5 case is dart-only (upstream has no 39794 parser): `NotYetSupported` (no face image the ICAO profile allows), `InvalidDataPassed` (malformed), `UnknownImageFormat` (the shared image rules) |
| `dg2.faceImageFormat` | dg2 | `DataGroup2(data).faceImageFormat.name` | none: upstream's `FaceImageFormat` enum is `private` and dead; cases dart-only, the Swift side pins the identical `imageData` bytes via `dg2.parse` instead | |
| `dg2.encoding` | dg2 | `DataGroup2(data).encoding.name` (`iso19794` or `iso39794`) | none: a Dart-only addition; upstream reads one encoding and names none; cases dart-only | |
| `dg7.parse` | dg7 | `DataGroup7(data)` -> `{imageSha256}` (SHA-256 of `imageData`: the dg2 precedent, bytes never travel) | same (`required init` = internal, `@testable`; fields `public private(set)`, ExtendedLDSOps); `calcSHA256Hash(dg7.imageData)` | `InvalidResponse`, `TagNotValid`; `InvalidASN1Value` (dart-only: upstream slice-crashes) |
| `dg7.imageFormat` | dg7 | `DataGroup7(data).imageFormat?.name` (`null` = unrecognized, never throws) | none: a Dart-only addition; upstream has no image-format surface on DG7 at all. The Swift side pins the identical bytes via `dg7.parse`'s sha (the `dg2.faceImageFormat` precedent); cases dart-only | |
| `dg11.parse` | dg11 | `DataGroup11(data)` -> the twelve upstream fields under upstream's spellings (`fullName`, `personalNumber`, `dateOfBirth`, `placeOfBirth`, `address`, `telephone`, `profession`, `title`, `personalSummary`, `proofOfCitizenship`, `tdNumbers`, `custodyInfo`), `null` when absent | same (`@testable`, ExtendedLDSOps) | `InvalidResponse`, `TagNotValid`; `InvalidASN1Value` (dart-only). The `5F2B` 4-byte-BCD pair is split by the port's fix (dart digits / swift nil) |
| `dg11.otherNames` | dg11 | `DataGroup11(data).otherNames` -> `{otherNames: [...]}`, the raw `A0`/`5F0F` record strings | none: a Dart-only addition; upstream consumes the `A0` value and drops it, so there is nothing to compare. Sibling `dg11.parse` cases over the same blobs pin that the addition changes nothing upstream can see; cases dart-only | |
| `dg12.parse` | dg12 | `DataGroup12(data)` -> `{issuingAuthority, dateOfIssue, endorsementsOrObservations, taxOrExitRequirements, frontImageSha256, rearImageSha256, personalizationTime, personalizationDeviceSerialNr}` | same (`@testable`, ExtendedLDSOps) | as `dg11.parse`. **`otherPersonsDetails` is excluded on both runners**: upstream declares it and never assigns it (dead API), and the port does not port it |
| `dg12.otherPersons` | dg12 | `DataGroup12(data).otherPersons` -> `{otherPersons: [...]}`, the raw `A0`/`5F1A` record strings | none: same disposition as `dg11.otherNames` (upstream's `A0` branch is a literal no-op); cases dart-only | |
| `faceImageInfo.from` | dg2 | `FaceImageInfo.from(dg2)` -> enum member names (`null` off-map, and `faceImageType` on an ISO/IEC 39794-5 DG2); `features` as a name list in declaration order | same (`internal`); upstream's single-value `Features?` emitted as `[]`/`[name]` so shapes stay comparable: split cases for upstream's single-value features; ISO/IEC 39794-5 cases dart-only | |
| `sod.parse` | sod | `SOD(data).pkcs7CertificateData` | same (`internal` init) | construction splits: dart `InvalidASN1Value` / swift `UnableToParseASN1` (the dropped `OpenSSLError`, mapped to its case name by LDSOps) |
| `sod.encapsulatedContent` | sod | `SOD(data).getEncapsulatedContent()` | same | walk-failure splits: dart `InvalidDataPassed` / swift `UnableToExtractSignedDataFromPKCS7` |
| `sod.parseSignatureContent` | sod | `SOD` -> `parseSODSignatureContent(encapsulated bytes)` -> `{algorythm, hashes}` (hash hex uppercase) | `NFCPassportModel().parseSODSignatureContent(OpenSSLUtils.ASN1Parse(...))` via the `seams.patch` `private`->`internal` relaxation | dart `InvalidDataPassed`/`InvalidASN1Value`; swift `UnableToParseSODHashes`, plus splits for substring digest detection and out-of-range dgList ids |
| `sod.ldsVersionInfo` | sod | `parseLdsVersionInfo(content)` over the `LDSSecurityObject` DER (what `sod.encapsulatedContent` yields) -> `{ldsVersion, unicodeVersion}`, rendered as EF.COM renders them (`"1.7"` / `"4.0.0"`) or `null` each: the member is matched by structure (a member SEQUENCE of exactly two `PrintableString`s), not position | none: upstream never reads the `ldsVersionInfo` member (a Dart-only addition); cases dart-only | (never throws) |
| `pa.sodSignature` | passive_auth | `verifySodSignature(SOD(sod))` -> `{valid}` | `OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod:)`: a throw is `{valid:false}` (PassiveAuthOps) | (never throws on either side) |
| `pa.sodSignature.detail` | passive_auth | same call -> `{valid, digestAlgorithm, signatureScheme, cause, annotations}` | none: the verdict vocabulary, the `weak_digest` annotation and the resolved scheme have no upstream analogue; the shared `valid` half is pinned by `pa.sodSignature`. Cases dart-only | |
| `pa.trust` | passive_auth | `verifyPassiveAuth(...).passportCorrectlySigned` -> `{trusted}` | `OpenSSLUtils.verifyTrustAndGetIssuerCertificate(x509:CAFile:)` over a temp PEM written from the case's `trust` DER list: `.success` => `{trusted:true}` | |
| `pa.trust.detail` | passive_auth | same call -> `{trusted, cause, chainLength, cscaFingerprintSha256}` | none: upstream returns only the anchor, has no cause taxonomy and no SHA-256 fingerprint; cases dart-only | |
| `pa.verify` | passive_auth | the three upstream booleans `{passportCorrectlySigned, documentSigningCertificateVerified, passportDataNotTampered}` | `NFCPassportModel` + `addDataGroup` per `dataGroups` + `verifyPassport(masterListURL:useCMSVerification:false)`, then the three model booleans (PassiveAuthOps) | (`verifyPassport` never throws) |
| `pa.verdict` | passive_auth | `verifyPassiveAuth(...)` -> `{outcome, cause, annotations}` | none: the verdict taxonomy is a Dart-only addition with no upstream surface; cases dart-only | |
| `pa.masterList` | passive_auth | `CscaTrustStore.fromSignedMasterList` -> `{certificateCount, signerVerified, skipped, pinned}` | none: upstream ingests plain PEM only, with no signature check, no signer pinning and no `.ml` support at all; cases dart-only | `MasterListParseError`, `MasterListContentTypeError`, `MasterListSignatureError`, `MasterListPinningError` (dart-only) |
| `x509.parse` | passive_auth | `X509Certificate.tryParse` -> `{subject, issuer, serialNumber, notBefore, notAfter, ski, aki, ca, keyCertSign, fingerprintSha256, publicKeyBits, publicKeyCurve}`; the last two from `X509CertificateInfo`: the key width on OpenSSL's `EVP_PKEY_bits` axis (RSA modulus / EC field / DH prime) and the EC curve in the SPKI parser's registry vocabulary (`secp256r1`, `brainpoolp256r1`; `null` for RSA, DH, explicit `ECParameters` and an unusable SPKI) | none: `X509Wrapper` renders dates as `ASN1_TIME_print` text, has no SKI/AKI/basicConstraints accessors, no SHA-256 fingerprint and no key-size accessor, so no field is byte-comparable; cases dart-only | (never throws; an unparseable certificate is `null`) |
| `sod.checkDataGroupHashes` | sod_hash_oracle | `checkDataGroupHashes(sod:, dataGroupsRead:)` -> `{algorythm, hashes, errors, passed}`; the SOD itself is auto-added to the read set (model parity) | `NFCPassportModel` + `addDataGroup` + `ensureReadDataNotBeenTamperedWith(useCMSVerification: false)` via the patch: dummy-signature fixtures always fall into the `getEncapsulatedContent` branch, the exact path the port takes; `errors` from the caught `InvalidDataGroupHash` | as `sod.parseSignatureContent`. Cases carry at most ONE error-producing DG: Swift dictionary iteration order is unspecified, so multi-error text would be nondeterministic there |

Registry notes:

- Runners are extended **only** by adding ops to each runner's registry map
  and rows to this table.
- The Dart op typedef is `FutureOr` (and the Swift `apdu.response`/
  `apdu.commandBuild` ops bridge into async `TagReader` calls): ops may drive
  async pipelines; pure ops stay synchronous.
- The `passive_auth` suite carries its own input conventions, shared by all
  seven `pa.*`/`x509.*` ops: `sod` / `certificate` / `masterList` /
  `pinnedSigner` are hex blobs, `trust` is a **list** of certificate DERs as
  hex (the Swift runner writes them out as a temp PEM file because
  `verifyTrustAndGetIssuerCertificate` takes a `URL`), `dataGroups` is a map
  of DG name -> file hex, and `verificationTime` is an ISO-8601 UTC instant the
  Dart runner injects and the Swift runner ignores. Every certificate on a
  valid path is long-lived (notAfter 2126) so a real-clock Swift run agrees;
  the expired fixtures are expired on any real clock. Its fixtures are
  generated by the deterministic test PKI (`test/support/emrtd_test_pki.dart`)
  and pinned by `test/conformance/passive_auth_vectors_test.dart`; regenerate
  with `REGENERATE_PASSIVE_AUTH_VECTORS=1`.
- The PACE mapping suites' non-published expectations (3DES/AES-192/256
  Integrated Mapping, IM and DH-GM on the groups and curves App G.2/H do not
  cover) come from an **independent python oracle committed at
  `tools/pace_mapping_oracle.py`**, not from the port's own output. `python3
  conformance/tools/pace_mapping_oracle.py verify` recomputes all three
  published chains as a self-check; the `emit-*` subcommands print the
  synthetic rows, whose case names carry the `python-oracle` provenance tag.
  The three PACE mapping session transcripts are authored and re-pinned by
  `test/conformance/pace_mapping_transcripts_test.dart`; regenerate with
  `REGENERATE_PACE_MAPPING_TRANSCRIPTS=1`.
- The ISO/IEC 39794-5 cases in `dg2.json` come from an **independent
  python oracle committed at `tools/dg2_39794_oracle.py`**. asn1tools
  DER-encodes each well-formed case from the ASN.1 modules themselves
  (the ICAO eMRTD application profile's, and ISO's base modules for the
  shapes only the base standard allows); the expected fields are computed
  from the decoded values by a mapping that shares no code with the port.
  The modules are fetched at pinned bytes and never committed. `python3
  -I conformance/tools/dg2_39794_oracle.py verify` decodes ICAO's two
  "silver" DG2 datasets and ISO's sample block as a self-check; `emit`
  prints the rows, whose names carry the `python-oracle` provenance tag.
  Those samples are not redistributable either: `test/lds_test.dart`
  checks the port against them when `EMRTD_39794_SAMPLES` names a
  directory holding them.
- Structured commands travel as `{cla, ins, p1, p2, data, le}`: header bytes
  as hex strings, `data` as a hex string, `le` as a JSON number with
  CoreNFC's `expectedResponseLength` semantics: `-1`/`null` absent,
  1..256 short (256 encodes `00`), 257..65536 extended (65536 encodes
  `0000`). Response APDUs travel as `{data, sw}` with `sw` = SW1‖SW2 hex.
  The Swift codec maps CoreNFC's `expectedResponseLength` 0 (which it
  reports for a parsed case-4 short APDU ending in Le `00`) to 256
  (`conformanceLe`).

## Transcripts: schema v1

Golden APDU transcripts (layer 2) live in `transcripts/`, one JSON file per
fixture. Both replay runners consume them: Dart
(`test/conformance/transcript_runner_test.dart` over the scripted
transceiver) and Swift (`TranscriptReplayTests` over a mock `NFCISO7816Tag`
assembled against upstream at the pin, executed in rented-Mac sessions).

```jsonc
{
  "transcript": "read_com_unprotected", "schemaVersion": 1,
  "runners": ["swift", "dart"],              // omit = both; split behavior ships as sibling files, one per runner
  "session": { "secureMessaging": "none" },  // or "bac" / "pace"
  // "bac": the handshake (GET CHALLENGE + EXTERNAL AUTHENTICATE) runs
  // first, driven by BACHandler with the injected rng (RND.IFD(8) ‖
  // K.IFD(16)); the wrapped drive.op follows over the installed session.
  // Handshake commands are ordinary scripted steps.
  // "pace": + cardAccess (hex EF.CardAccess), mrzKey, and
  //   ephemeralKeys: { mappingKey, ephemeralKey } (hex private scalars)
  //   plus the optional imNonce (hex, the Integrated Mapping's PCD nonce t;
  //   additive, so schemaVersion stays 1, as `ephemeralKeys` itself is).
  //   The password may instead be given in full as
  //   password: { type: "mrz"|"can"|"pin"|"cuk", value: "..." };
  //   `mrzKey` is the MRZ shorthand the MRZ fixtures use, and
  //   exactly one of the two must be present. Also additive: schemaVersion
  //   stays 1. Non-MRZ fixtures are runners:["dart"]: upstream's PACEHandler
  //   can only derive an MRZ key. Absent keys are
  //   sampled from the live RNG, so any deterministic PACE fixture supplies
  //   the ones its mechanism consumes: GM uses mappingKey + ephemeralKey,
  //   IM uses imNonce + ephemeralKey (IM has no mapping keypair at all).
  //   PACEHandler.doPACE runs first (MSE:Set AT + the 4 GA rounds are
  //   scripted steps); the wrapped drive.op follows over the installed PACE
  //   SM. The upstream-only DH-GM/IM partial sessions throw during doPACE:
  //   expect.error, runners:["swift"], since the port completes both
  //   mechanisms.
  "drive": { "op": "selectFileAndRead", "args": { "tag": "011e" } },
  "steps": [
    { "cmd":  { "cla": "00", "ins": "a4", "p1": "02", "p2": "0c", "data": "011e", "le": null },
      "wire": "00a4020c02011e",              // optional; Dart-runner-only assertion
      "cmdFor": { "swift": { ... } },   // optional, per runner name: that runner asserts this instead of cmd
      "resp": { "data": "", "sw": "9000" } }
  ],
  "expect": { "out": "60145f0102..." }       // or { "error": "InvalidMRZKey" }: same contract as vectors
}
```

Replay contract: the runner invokes `drive.op` with `drive.args`, feeds each
step's `resp` through a scripted transceiver, asserts the implementation's
next command matches `cmd` structurally (both runners) and `wire`
byte-exactly (Dart only), then asserts `expect` (deep-equal output or the
thrown error code) and finally that every step was consumed.

`cmdFor` carries a per-runner alternative to `cmd` for one step, the
mechanism for a divergence confined to a single command, today only the
DO84 in MSE:Set AT (`swift`: upstream's form; `cmd`: the port's). A runner
uses the entry under its own name, else `cmd`; an outside runner may accept
either `cmd` or any `cmdFor` variant for that step, since the variants
enumerate the known-good forms and it takes no side. The Dart runner reads no
`cmdFor` today (none is authored for it). Additive: schemaVersion stays 1.

Drive ops (extend both replay runners and this list together):

| op | args | `expect.out` shape |
|---|---|---|
| `selectFileAndRead` | `tag` (hex FID); optional `maxDataLengthToRead` (applied via `overrideDataAmountToRead`) | hex string of the returned bytes |
| `readCardAccess` | optional `maxDataLengthToRead` | hex string |
| `readAtrInfo` | optional `maxDataLengthToRead` | hex string: MF select ladder, SELECT `2F01`, then READ BINARY from offset 0 in fitted chunks until the chip signals the end (short answer, `62 82`, or `6B 00` past the last byte); no header walk, the file is a bare DO sequence. Dart-only fixtures: upstream has no such read |
| `doMutualAuthentication` | `cmdData` (hex) | `{data, sw}` |
| `sendGeneralAuthenticate` | `data` (hex), optional `lengthExpected` (default 256), `isLast` (bool) | `{data, sw}` |
| `selectPassportApplication` | | `{data, sw}`: the first post-PACE protected command, driven over the installed PACE SM |
| `chipAuthentication` | `dg14` (hex EF.DG14 file), `ephemeralKey` (hex private scalar: the Chip Authentication handler's injection seam) | `{data, sw}`: `ChipAuthenticationHandler.doChipAuthentication()` runs over the session the `session` block established, then SELECT eMRTD AID is sent over the **CA** SM, proving the derived keys (as the post-PACE SELECT does). A failed handshake throws first: `expect.error` |
| `activeAuthentication` | `dg15` (hex EF.DG15 file), `dg14` (hex, optional: the ECDSA digest source), `challenge` (hex, fixed so replay needs no RNG seam) | `{passed, signature}`: `TagReader.doInternalAuthentication` over the session the `session` block established, then the pure verifier (Swift: the model's `verifyActiveAuthentication` + `activeAuthenticationPassed`). A chip that refuses the command throws: `expect.error` |
| `none` | | `""`: the session establishment itself is under test (BAC/PACE error fixtures); nothing to drive after the handshake |

The smoke set is hand-authored (no chip needed) and pins upstream's
transport quirks, the port's fixes to them and its field-compatibility
paths; see `transcripts/README.md` for the full set and what is still to
come (captured fixtures).
