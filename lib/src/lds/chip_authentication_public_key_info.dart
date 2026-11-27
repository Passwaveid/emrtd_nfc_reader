// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/ChipAuthenticationPublicKeyInfo.swift
//         @ 3bf5456 (2.3.2)
//   `pubKey : OpaquePointer` (an OpenSSL `EVP_PKEY` from `d2i_PUBKEY`)
//   becomes the parsed [SubjectPublicKey] sum type.

/// `ChipAuthenticationPublicKeyInfo`: the DG14 entry carrying the chip's
/// static CA public key (an X.509 `SubjectPublicKeyInfo`) plus the `keyId`
/// that binds it to a [ChipAuthenticationInfo].
library;

// Upstream case/const names kept verbatim, so ported call sites diff line by
// line against the Swift.
// ignore_for_file: constant_identifier_names

import 'chip_authentication_info.dart';
import 'security_info.dart';
import 'subject_public_key_info.dart';

/// Upstream `ChipAuthenticationPublicKeyInfo`.
class ChipAuthenticationPublicKeyInfo extends SecurityInfo {
  ChipAuthenticationPublicKeyInfo({
    required this.oid,
    required this.pubKey,
    this.keyId,
  });

  /// `id-PK-DH` or `id-PK-ECDH`.
  final String oid;

  /// Upstream's `EVP_PKEY`, parsed. The domain parameters carried
  /// here are the ones the ephemeral keypair is generated on: upstream's
  /// `EVP_PKEY_keygen` off a ctx of this very key.
  final SubjectPublicKey pubKey;

  final int? keyId;

  /// Upstream `checkRequiredIdentifier(_:)`.
  static bool checkRequiredIdentifier(String oid) =>
      SecurityInfo.ID_PK_DH_OID == oid || SecurityInfo.ID_PK_ECDH_OID == oid;

  @override
  String getObjectIdentifier() => oid;

  @override
  String getProtocolOIDString() => _toProtocolOIDString(oid);

  /// Upstream `getKeyId()`. The keyid refers to a specific key if there are
  /// multiple otherwise if not set, only one key is present so set to 0
  /// (upstream comment).
  int getKeyId() => keyId ?? 0;

  /// Upstream `toProtocolOIDString(oid:)`; unknown OIDs pass through.
  static String _toProtocolOIDString(String oid) {
    if (SecurityInfo.ID_PK_DH_OID == oid) {
      return 'id-PK-DH';
    }
    if (SecurityInfo.ID_PK_ECDH_OID == oid) {
      return 'id-PK-ECDH';
    }
    return oid;
  }
}
