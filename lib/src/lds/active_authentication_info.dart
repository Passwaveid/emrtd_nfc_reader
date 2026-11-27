// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/ActiveAuthenticationInfo.swift
//         @ 3bf5456 (2.3.2), file-for-file.

/// `ActiveAuthenticationInfo`: the DG14 entry that declares Active
/// Authentication support and, optionally, which signature algorithm an
/// ECDSA-AA chip signs with.
///
/// The only consumer is the ECDSA arm of the AA verifier, which reads
/// [getSignatureAlgorithmOIDString] off the **first** such entry in DG14 and
/// feeds the friendly name to the digest chain.
///
/// Two upstream quirks are kept: [version] is parsed and stored but **never**
/// consulted (the [ChipAuthenticationInfo] family trait), and the friendly
/// name `ecdsa-plain-RIPEMD160` has no arm in that digest chain, so a
/// legitimately-signed RIPEMD-160 chip always fails AA.
library;

// Upstream case/const names kept verbatim, so ported call sites diff line by
// line against the Swift.
// ignore_for_file: constant_identifier_names

import 'security_info.dart';

/// Upstream `ActiveAuthenticationInfo`.
class ActiveAuthenticationInfo extends SecurityInfo {
  ActiveAuthenticationInfo({
    required this.oid,
    required this.version,
    this.signatureAlgorithmOID,
  });

  final String oid;

  /// Stored, never consulted, kept for upstream field parity.
  final int version;

  /// The dotted `ecdsa-plain-*` OID DG14's optional third child carried, or
  /// `null` when the entry had none (or it did not decode).
  final String? signatureAlgorithmOID;

  /// Upstream `checkRequiredIdentifier(_:)`.
  static bool checkRequiredIdentifier(String oid) =>
      SecurityInfo.ID_AA_OID == oid;

  @override
  String getObjectIdentifier() => oid;

  @override
  String getProtocolOIDString() => _toProtocolOIDString(oid);

  /// Upstream `getSignatureAlgorithmOIDString()`: the BSI TR-03111 §5.2.1
  /// friendly name, or `null` for an absent/unknown OID.
  String? getSignatureAlgorithmOIDString() =>
      _toSignatureAlgorithmOIDString(signatureAlgorithmOID);

  /// Upstream `toProtocolOIDString(oid:)`: unknown OIDs pass through.
  static String _toProtocolOIDString(String oid) =>
      SecurityInfo.ID_AA_OID == oid ? 'id-AA' : oid;

  /// Upstream `toSignatureAlgorithmOIDString(oid:)`.
  static String? _toSignatureAlgorithmOIDString(String? oid) {
    if (SecurityInfo.ECDSA_PLAIN_SHA1_OID == oid) {
      return 'ecdsa-plain-SHA1';
    }
    if (SecurityInfo.ECDSA_PLAIN_SHA224_OID == oid) {
      return 'ecdsa-plain-SHA224';
    }
    if (SecurityInfo.ECDSA_PLAIN_SHA256_OID == oid) {
      return 'ecdsa-plain-SHA256';
    }
    if (SecurityInfo.ECDSA_PLAIN_SHA384_OID == oid) {
      return 'ecdsa-plain-SHA384';
    }
    if (SecurityInfo.ECDSA_PLAIN_SHA512_OID == oid) {
      return 'ecdsa-plain-SHA512';
    }
    if (SecurityInfo.ECDSA_PLAIN_RIPEMD160_OID == oid) {
      return 'ecdsa-plain-RIPEMD160';
    }
    return null;
  }
}
