// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/ChipAuthenticationInfo.swift
//         @ 3bf5456 (2.3.2)

/// `ChipAuthenticationInfo`: the DG14/EF.CardAccess entry naming the CA
/// protocol suite. Its OID selects the key-agreement algorithm, the
/// cipher, and the key length for the CA session-key derivation; `keyId`
/// binds it to a specific [ChipAuthenticationPublicKeyInfo] when the chip
/// carries several keys.
///
/// An upstream quirk is kept: [version] is parsed and stored but **never
/// consulted**; the v1/v2 flow split is decided by the OID's *cipher*
/// (DESede -> MSE:Set KAT, AES -> MSE:Set AT + GENERAL AUTHENTICATE), not by
/// the CA version.
library;

// Upstream case/const names kept verbatim, so ported call sites diff line by
// line against the Swift.
// ignore_for_file: constant_identifier_names

import '../errors.dart';
import 'chip_authentication_public_key_info.dart';
import 'security_info.dart';

/// Upstream `ChipAuthenticationInfo`.
class ChipAuthenticationInfo extends SecurityInfo {
  ChipAuthenticationInfo({
    required this.oid,
    required this.version,
    this.keyId,
  });

  final String oid;

  /// Stored, never consulted, kept for upstream field parity.
  final int version;

  final int? keyId;

  /// Upstream `checkRequiredIdentifier(_:)`: the eight CA suites.
  static bool checkRequiredIdentifier(String oid) =>
      SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID == oid ||
      SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID == oid ||
      SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID == oid ||
      SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID == oid ||
      SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID == oid ||
      SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid ||
      SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid ||
      SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid;

  @override
  String getObjectIdentifier() => oid;

  @override
  String getProtocolOIDString() => _toProtocolOIDString(oid);

  /// Upstream `getKeyId()`. The keyid refers to a specific key if there are
  /// multiple otherwise if not set, only one key is present so set to 0
  /// (upstream comment).
  int getKeyId() => keyId ?? 0;

  /// Upstream `toKeyAgreementAlgorithm(oid:)`: "DH" or "ECDH". Throws
  /// [InvalidDataPassed] for an OID outside the eight suites.
  static String toKeyAgreementAlgorithm(String oid) {
    if (SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID == oid) {
      return 'DH';
    } else if (SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid) {
      return 'ECDH';
    }
    throw const InvalidDataPassed(
      'Unable to lookup key agreement algorithm - invalid oid',
    );
  }

  /// Upstream `toCipherAlgorithm(oid:)`: "DESede" or "AES". This is what
  /// picks the MSE:Set KAT vs MSE:Set AT + GA flow.
  static String toCipherAlgorithm(String oid) {
    if (SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID == oid ||
        SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID == oid) {
      return 'DESede';
    } else if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid) {
      return 'AES';
    }
    throw const InvalidDataPassed(
      'Unable to lookup cipher algorithm - invalid oid',
    );
  }

  /// Upstream `toKeyLength(oid:)`: 128, 192, or 256 bits.
  static int toKeyLength(String oid) {
    if (SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID == oid ||
        SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID == oid ||
        SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid) {
      return 128;
    } else if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid) {
      return 192;
    } else if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID == oid ||
        SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid) {
      return 256;
    }
    throw const InvalidDataPassed('Unable to get key length - invalid oid');
  }

  /// Upstream `toProtocolOIDString(oid:)`: human-readable protocol name;
  /// unknown OIDs return the OID unchanged.
  static String _toProtocolOIDString(String oid) {
    if (SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID == oid) {
      return 'id-CA-DH-3DES-CBC-CBC';
    }
    if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID == oid) {
      return 'id-CA-DH-AES-CBC-CMAC-128';
    }
    if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID == oid) {
      return 'id-CA-DH-AES-CBC-CMAC-192';
    }
    if (SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID == oid) {
      return 'id-CA-DH-AES-CBC-CMAC-256';
    }
    if (SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID == oid) {
      return 'id-CA-ECDH-3DES-CBC-CBC';
    }
    if (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID == oid) {
      return 'id-CA-ECDH-AES-CBC-CMAC-128';
    }
    if (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID == oid) {
      return 'id-CA-ECDH-AES-CBC-CMAC-192';
    }
    if (SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID == oid) {
      return 'id-CA-ECDH-AES-CBC-CMAC-256';
    }
    return oid;
  }
}
