// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/SecurityInfo.swift @ 3bf5456 (2.3.2)
//   Ported whole: the PACE and CA constants and branches, plus the Active
//   Authentication OID consts, the six BSI TR-03111 `ecdsa-plain-*` OIDs and
//   the ActiveAuthenticationInfo branch of `getInstance`. Upstream's
//   `d2i_PUBKEY` call in the CA-pubkey branch becomes the Dart SPKI parser
//   (`subject_public_key_info.dart`), nil-contract preserved.

/// SecurityInfo base + every OID constant and every `getInstance` branch the
/// upstream file carries. Consumed by [CardAccess] and [DataGroup14] over a
/// `TlvRecord` walk, replacing upstream's `SimpleASN1DumpParser` text hack.
///
/// Unlike upstream, a malformed entry with fewer than two children is
/// skipped, not a `getChild(1)!` crash, and `version` is parsed as the DER
/// INTEGER value, not a decimal parse of OpenSSL's hex render, in the PACE,
/// CA and AA branches alike. As upstream, an unparseable
/// `ChipAuthenticationPublicKeyInfo` entry is skipped, as upstream's
/// `d2i_PUBKEY` nil does. The first-`PACEInfo`-wins rule lives in
/// [CardAccess], the 3-child rule in `getInstance`.
library;

// Upstream case/const names kept verbatim, so ported call sites diff line by
// line against the Swift.
// ignore_for_file: constant_identifier_names

import '../errors.dart';
import 'active_authentication_info.dart';
import 'chip_authentication_info.dart';
import 'chip_authentication_public_key_info.dart';
import 'data_group14.dart';
import 'pace_info.dart';
import 'subject_public_key_info.dart';
import 'tlv.dart';

/// Upstream `SecurityInfo`. The base stays abstract-by-precondition
/// upstream, realized here as a Dart `abstract` class with the two
/// overridable getters.
abstract class SecurityInfo {
  const SecurityInfo();

  // Active Authentication OID (SecurityInfo.swift:13), verbatim.
  static const String ID_AA_OID = '2.23.136.1.1.5';

  // Active Authentication Signature Algorithm OIDS
  // Specified in BSI TR 03111 Section 5.2.1 (upstream comment;
  // SecurityInfo.swift:17-24), verbatim.
  static const String ECDSA_PLAIN_SIGNATURES = '0.4.0.127.0.7.1.1.4.1';
  static const String ECDSA_PLAIN_SHA1_OID = '$ECDSA_PLAIN_SIGNATURES.1';
  static const String ECDSA_PLAIN_SHA224_OID = '$ECDSA_PLAIN_SIGNATURES.2';
  static const String ECDSA_PLAIN_SHA256_OID = '$ECDSA_PLAIN_SIGNATURES.3';
  static const String ECDSA_PLAIN_SHA384_OID = '$ECDSA_PLAIN_SIGNATURES.4';
  static const String ECDSA_PLAIN_SHA512_OID = '$ECDSA_PLAIN_SIGNATURES.5';
  static const String ECDSA_PLAIN_RIPEMD160_OID = '$ECDSA_PLAIN_SIGNATURES.6';

  // Chip Authentication Public Key OIDS (SecurityInfo.swift:27-28), verbatim.
  static const String ID_PK_DH_OID = '0.4.0.127.0.7.2.2.1.1';
  static const String ID_PK_ECDH_OID = '0.4.0.127.0.7.2.2.1.2';

  // Chip Authentication OIDS (SecurityInfo.swift:31-38), verbatim.
  static const String ID_CA_DH_3DES_CBC_CBC_OID = '0.4.0.127.0.7.2.2.3.1.1';
  static const String ID_CA_ECDH_3DES_CBC_CBC_OID = '0.4.0.127.0.7.2.2.3.2.1';
  static const String ID_CA_DH_AES_CBC_CMAC_128_OID = '0.4.0.127.0.7.2.2.3.1.2';
  static const String ID_CA_DH_AES_CBC_CMAC_192_OID = '0.4.0.127.0.7.2.2.3.1.3';
  static const String ID_CA_DH_AES_CBC_CMAC_256_OID = '0.4.0.127.0.7.2.2.3.1.4';
  static const String ID_CA_ECDH_AES_CBC_CMAC_128_OID =
      '0.4.0.127.0.7.2.2.3.2.2';
  static const String ID_CA_ECDH_AES_CBC_CMAC_192_OID =
      '0.4.0.127.0.7.2.2.3.2.3';
  static const String ID_CA_ECDH_AES_CBC_CMAC_256_OID =
      '0.4.0.127.0.7.2.2.3.2.4';

  // PACE OIDS (SecurityInfo.swift:42-71), values verbatim.
  static const String ID_BSI = '0.4.0.127.0.7';
  static const String ID_PACE = '$ID_BSI.2.2.4';

  static const String ID_PACE_DH_GM = '$ID_PACE.1';
  static const String ID_PACE_DH_GM_3DES_CBC_CBC = '$ID_PACE_DH_GM.1';
  static const String ID_PACE_DH_GM_AES_CBC_CMAC_128 = '$ID_PACE_DH_GM.2';
  static const String ID_PACE_DH_GM_AES_CBC_CMAC_192 = '$ID_PACE_DH_GM.3';
  static const String ID_PACE_DH_GM_AES_CBC_CMAC_256 = '$ID_PACE_DH_GM.4';

  static const String ID_PACE_ECDH_GM = '$ID_PACE.2';
  static const String ID_PACE_ECDH_GM_3DES_CBC_CBC = '$ID_PACE_ECDH_GM.1';
  static const String ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = '$ID_PACE_ECDH_GM.2';
  static const String ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = '$ID_PACE_ECDH_GM.3';
  static const String ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = '$ID_PACE_ECDH_GM.4';

  static const String ID_PACE_DH_IM = '$ID_PACE.3';
  static const String ID_PACE_DH_IM_3DES_CBC_CBC = '$ID_PACE_DH_IM.1';
  static const String ID_PACE_DH_IM_AES_CBC_CMAC_128 = '$ID_PACE_DH_IM.2';
  static const String ID_PACE_DH_IM_AES_CBC_CMAC_192 = '$ID_PACE_DH_IM.3';
  static const String ID_PACE_DH_IM_AES_CBC_CMAC_256 = '$ID_PACE_DH_IM.4';

  static const String ID_PACE_ECDH_IM = '$ID_PACE.4';
  static const String ID_PACE_ECDH_IM_3DES_CBC_CBC = '$ID_PACE_ECDH_IM.1';
  static const String ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = '$ID_PACE_ECDH_IM.2';
  static const String ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = '$ID_PACE_ECDH_IM.3';
  static const String ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = '$ID_PACE_ECDH_IM.4';

  static const String ID_PACE_ECDH_CAM = '$ID_PACE.6';
  static const String ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = '$ID_PACE_ECDH_CAM.2';
  static const String ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = '$ID_PACE_ECDH_CAM.3';
  static const String ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = '$ID_PACE_ECDH_CAM.4';

  /// Upstream `getObjectIdentifier()` (overridden by the info subclasses).
  String getObjectIdentifier();

  /// Upstream `getProtocolOIDString()` (overridden by the info subclasses).
  String getProtocolOIDString();

  /// Upstream `getInstance(object:body:)`: the CA-public-key, CA, PACE and
  /// (last, as upstream orders them) `ActiveAuthenticationInfo` branches.
  ///
  /// [object] is a SecurityInfo SEQUENCE `TlvRecord`; its children are
  /// `[OID, requiredData, optionalData?]` with `optionalData` recognized only
  /// when there are exactly three children. [body] is inert; upstream's
  /// CA-pubkey branch slices the SPKI out of it positionally
  /// (`body[requiredData.pos ..< pos+headerLen+length]`) while the port
  /// re-encodes `requiredData` (byte-identical for DER-minimal input, which
  /// every conformant DG14 is); [body] is kept for signature parity.
  ///
  /// Returns `null` for an OID no branch claims (out-of-scope protocols fall
  /// through the same as upstream's unknown-OID case), for an unparseable
  /// SubjectPublicKeyInfo (upstream: `d2i_PUBKEY` nil -> same skip), and for
  /// a malformed entry (SEQUENCE with fewer than two children), where
  /// upstream crashes on `getChild(1)!` over unauthenticated pre-PACE data.
  static SecurityInfo? getInstance({
    required TlvRecord object,
    required List<int> body,
  }) {
    final children = TlvRecord.sequenceOfRecords(object.value);
    // A <2-child entry is skipped, matching getInstance's nil-return
    // contract, instead of upstream's getChild(1)! trap.
    if (children == null || children.length < 2) {
      return null;
    }
    final String oid;
    try {
      oid = asn1DecodeOid(children[0].data);
    } on InvalidASN1Value {
      return null; // OID field is not a well-formed OID -> skip the entry.
    }
    final requiredData = children[1];
    // As upstream, optionalData is recognized only in an exactly-3-child
    // SEQUENCE. A 4-child SEQUENCE loses its parameterId (parameterId =
    // null).
    final optionalData = children.length == 3 ? children[2] : null;

    if (ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid)) {
      // Upstream hands the SPKI DER to `d2i_PUBKEY` and skips the entry when
      // it returns nil; the port parses it in Dart with the same contract.
      // `requiredData.data` is the re-encoded record.
      final pubKey = parseSubjectPublicKeyInfo(requiredData.data);
      if (pubKey == null) {
        return null;
      }
      final keyId = optionalData == null
          ? null
          : _derIntegerValue(optionalData.value);
      return ChipAuthenticationPublicKeyInfo(
        oid: oid,
        pubKey: pubKey,
        keyId: keyId,
      );
    }

    if (ChipAuthenticationInfo.checkRequiredIdentifier(oid)) {
      // DER INTEGER value, not upstream's `Int(hexRender)`
      // decimal-parse-of-hex. `keyId` is upstream's `Int(value, radix: 16)`,
      // value-correct for non-negative INTEGERs, so the DER read is
      // equivalent there (no split needed).
      final version = _derIntegerValue(requiredData.value);
      final keyId = optionalData == null
          ? null
          : _derIntegerValue(optionalData.value);
      return ChipAuthenticationInfo(oid: oid, version: version, keyId: keyId);
    }

    if (PACEInfo.checkRequiredIdentifier(oid)) {
      // DER INTEGER value, not int.tryParse of a hex render.
      final version = _derIntegerValue(requiredData.value);
      final parameterId = optionalData == null
          ? null
          : _derIntegerValue(optionalData.value);
      return PACEInfo(oid: oid, version: version, parameterId: parameterId);
    }

    if (ActiveAuthenticationInfo.checkRequiredIdentifier(oid)) {
      // DER INTEGER value, as in the PACE and CA branches.
      final version = _derIntegerValue(requiredData.value);
      // Upstream stores `optionalData.value`: the dump parser's rendering of
      // the child, a dotted OID string for a well-formed OBJECT IDENTIFIER.
      // The port decodes it properly; an undecodable third child yields null,
      // the closest observable to upstream's garbage-string -> friendly-name
      // table miss -> nil chain.
      String? signatureAlgorithmOID;
      if (optionalData != null) {
        try {
          signatureAlgorithmOID = asn1DecodeOid(optionalData.data);
        } on InvalidASN1Value {
          signatureAlgorithmOID = null;
        }
      }
      return ActiveAuthenticationInfo(
        oid: oid,
        version: version,
        signatureAlgorithmOID: signatureAlgorithmOID,
      );
    }

    // An OID no branch claims -> skipped, exactly as upstream's getInstance
    // returns nil for it.
    return null;
  }
}

/// Reads a DER INTEGER's content octets as a non-negative integer.
///
/// The only INTEGERs the ported branches read (PACEInfo's `version` and
/// `parameterId`, ChipAuthenticationInfo's `version` and both CA classes'
/// `keyId`) are small and non-negative, so an unsigned big-endian read is
/// exact and matches the spec's `0x02 -> 2`, `0x0A -> 10`, `0x10 -> 16`. For
/// `keyId` this is *equivalent* to upstream's `Int(value, radix: 16)`; for
/// `version` it is deliberately *not*
/// upstream's `Int(hexString)` decimal-parse-of-hex (`0x0A -> nil -> -1`,
/// `0x10 -> 10`); the Swift split cases pin that broken behavior.
int _derIntegerValue(List<int> content) {
  var out = 0;
  for (final b in content) {
    out = (out << 8) | (b & 0xFF);
  }
  return out;
}
