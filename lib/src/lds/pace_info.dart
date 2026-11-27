// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/PACEInfo.swift @ 3bf5456 (2.3.2)
//   RFC 5114 groups: upstream used OpenSSL built-ins
//   (DH_get_1024_160 / DH_get_2048_224 / DH_get_2048_256, PACEInfo.swift:136);
//   ported here as p/q/g BigInt constants (RFC 5114 §2.1-2.3).

/// `PACEMappingType`, `PACEInfo`, the standardized-domain PARAM_ID table, the
/// RFC 5114 DH group constants, and the PACE value types the handler passes
/// between steps. `createMappingKey` stays on `PACEInfo` (upstream puts key
/// generation on the info class) but delegates all math to
/// `crypto/ec_dh.dart`.
///
/// Unlike upstream, `getParameterSpec` returns a sealed [PACEParameterSpec],
/// not an OpenSSL NID, and the static/instance overload pair collapses to a
/// private static + the public instance method; `createMappingKey` gains an
/// injection seam for the private key. As upstream, the message-string
/// oddities are kept verbatim: the `"p arameterSpec"` typo and the two
/// typo'd protocol OID names.
library;

// Upstream const names kept verbatim, so ported call sites diff line by line
// against the Swift; the private RFC 5114 group constants carry the group
// sizes in their names.
// ignore_for_file: constant_identifier_names, non_constant_identifier_names

import 'package:pointycastle/ecc/api.dart';

import '../crypto/ec_dh.dart';
import '../crypto/rng.dart';
import '../errors.dart';
import 'security_info.dart';

/// Upstream `PACEMappingType`.
enum PACEMappingType {
  GM, // Generic Mapping
  IM, // Integrated Mapping
  CAM; // Chip Authentication Mapping

  /// Upstream `description()`.
  String description() => switch (this) {
    PACEMappingType.GM => 'Generic Mapping',
    PACEMappingType.IM => 'Integrated Mapping',
    PACEMappingType.CAM => 'Chip Authentication Mapping',
  };
}

/// Result of [PACEInfo.getParameterSpec]. Upstream returns an OpenSSL NID
/// (`Int32`), meaningless in Dart; the port resolves the `parameterId` into
/// a curve or a DH group.
sealed class PACEParameterSpec {
  const PACEParameterSpec();
}

/// Standardized elliptic-curve domain (PARAM_ID 8-18) as a pointycastle
/// registry curve.
class ECStandardizedDomain extends PACEParameterSpec {
  const ECStandardizedDomain(this.domain);
  final ECDomainParameters domain;
}

/// Standardized DH group (PARAM_ID 0-2) as RFC 5114 §2.1-2.3 constants.
class DHStandardizedDomain extends PACEParameterSpec {
  const DHStandardizedDomain({
    required this.p,
    required this.q,
    required this.g,
  });
  final BigInt p, q, g;
}

/// A PACE public key crossing GENERAL AUTHENTICATE (mapping or ephemeral),
/// decoded into typed values. EC/DH cases mirror upstream's
/// EVP_PKEY EC/DH split; the name avoids pointycastle's `ECPublicKey`.
sealed class PACEPublicKey {
  const PACEPublicKey();
}

class EcdhPublicKey extends PACEPublicKey {
  const EcdhPublicKey({required this.domain, required this.point});
  final ECDomainParameters domain;
  final ECPoint point;
}

class DhPublicKey extends PACEPublicKey {
  const DhPublicKey({required this.p, required this.y});
  final BigInt p, y;
}

/// A PACE keypair (the step-2 mapping key or the step-3 ephemeral key;
/// upstream reuses one EVP_PKEY type for both).
sealed class PACEMappingKeyPair {
  const PACEMappingKeyPair();

  /// The public half, in the form the token/wire encoders consume.
  PACEPublicKey get publicKey;
}

class EcdhMappingKeyPair extends PACEMappingKeyPair {
  const EcdhMappingKeyPair({
    required this.domain,
    required this.d,
    required this.publicPoint,
  });
  final ECDomainParameters domain;
  final BigInt d;
  final ECPoint publicPoint;

  @override
  PACEPublicKey get publicKey =>
      EcdhPublicKey(domain: domain, point: publicPoint);
}

class DhMappingKeyPair extends PACEMappingKeyPair {
  const DhMappingKeyPair({
    required this.p,
    required this.q,
    required this.g,
    required this.x,
    required this.y,
  });
  final BigInt p, q, g, x, y;

  @override
  PACEPublicKey get publicKey => DhPublicKey(p: p, y: y);
}

/// The mapped ephemeral domain produced by step 2. EC carries the mapped
/// `ECDomainParameters` (generator Ĝ, curve's true n/h: the true cofactor,
/// not upstream's cofactor-0); DH carries `(p, q, ĝ)`.
sealed class PACEEphemeralParams {
  const PACEEphemeralParams();
}

class EcdhEphemeralParams extends PACEEphemeralParams {
  const EcdhEphemeralParams(this.domain);
  final ECDomainParameters domain;
}

class DhEphemeralParams extends PACEEphemeralParams {
  const DhEphemeralParams({required this.p, required this.q, required this.g});
  final BigInt p, q, g;
}

/// Upstream `PACEInfo`.
class PACEInfo extends SecurityInfo {
  PACEInfo({
    required this.oid,
    required this.version,
    required this.parameterId,
  });

  final String oid;
  final int version;
  final int? parameterId;

  // Standardized domain parameters (PACEInfo.swift:33-46, Table 6), verbatim.
  static const int PARAM_ID_GFP_1024_160 = 0;
  static const int PARAM_ID_GFP_2048_224 = 1;
  static const int PARAM_ID_GFP_2048_256 = 2;
  static const int PARAM_ID_ECP_NIST_P192_R1 = 8;
  static const int PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9;
  static const int PARAM_ID_ECP_NIST_P224_R1 = 10;
  static const int PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11;
  static const int PARAM_ID_ECP_NIST_P256_R1 = 12;
  static const int PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13;
  static const int PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14;
  static const int PARAM_ID_ECP_NIST_P384_R1 = 15;
  static const int PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16;
  static const int PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17;
  static const int PARAM_ID_ECP_NIST_P521_R1 = 18;

  static const List<String> allowedIdentifiers = [
    SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC,
    SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128,
    SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192,
    SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256,
    SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC,
    SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128,
    SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192,
    SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256,
    SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC,
    SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
    SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
    SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
    SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC,
    SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
    SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
    SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
    SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
    SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
    SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256,
  ];

  /// Upstream `checkRequiredIdentifier(_:)`.
  static bool checkRequiredIdentifier(String oid) =>
      allowedIdentifiers.contains(oid);

  @override
  String getObjectIdentifier() => oid;

  @override
  String getProtocolOIDString() => _toProtocolOIDString(oid);

  int getVersion() => version;

  int? getParameterId() => parameterId;

  /// Upstream `getParameterSpec()`. Resolves `parameterId` (default -1
  /// when absent, so `getParameterSpec` throws just as upstream does) into a
  /// sealed [PACEParameterSpec].
  PACEParameterSpec getParameterSpec() => _getParameterSpec(parameterId ?? -1);

  /// Upstream `getMappingType()`: GM, IM, or CAM.
  PACEMappingType getMappingType() => toMappingType(oid);

  /// Upstream `getKeyAgreementAlgorithm()`: "DH" or "ECDH".
  String getKeyAgreementAlgorithm() => toKeyAgreementAlgorithm(oid);

  /// Upstream `getCipherAlgorithm()`: "DESede" or "AES".
  String getCipherAlgorithm() => toCipherAlgorithm(oid);

  /// Upstream `getDigestAlgorithm()`: "SHA-1" or "SHA-256".
  String getDigestAlgorithm() => toDigestAlgorithm(oid);

  /// Upstream `getKeyLength()`: 128, 192, or 256.
  int getKeyLength() => toKeyLength(oid);

  /// Upstream `createMappingKey()`. Generates the step-2 mapping keypair;
  /// delegates all math to `ec_dh.dart`. When [privateKey] is
  /// injected (deterministic tests) the public half is recomputed from it;
  /// otherwise the scalar is sampled from [random] (live path: sampling
  /// distribution is unobservable on the wire).
  PACEMappingKeyPair createMappingKey({
    required EmrtdRandom random,
    BigInt? privateKey,
  }) {
    final agreement = getKeyAgreementAlgorithm();
    final spec = getParameterSpec();
    switch (agreement) {
      case 'DH':
        if (spec is! DHStandardizedDomain) {
          throw const InvalidDataPassed('Unable to create DH mapping key');
        }
        final BigInt x;
        final BigInt y;
        if (privateKey != null) {
          x = privateKey;
          y = dhPublic(spec.p, spec.g, x);
        } else {
          final kp = dhGenerateKeyPair(
            p: spec.p,
            g: spec.g,
            q: spec.q,
            rng: random,
          );
          x = kp.x;
          y = kp.y;
        }
        return DhMappingKeyPair(p: spec.p, q: spec.q, g: spec.g, x: x, y: y);
      case 'ECDH':
        if (spec is! ECStandardizedDomain) {
          throw const InvalidDataPassed('Unable to create EC mapping key');
        }
        final domain = spec.domain;
        final BigInt d;
        final ECPoint publicPoint;
        if (privateKey != null) {
          d = privateKey;
          publicPoint = ecPublicFromPrivate(domain, d);
        } else {
          final kp = ecGenerateKeyPair(domain, random);
          d = kp.d;
          publicPoint = kp.q;
        }
        return EcdhMappingKeyPair(
          domain: domain,
          d: d,
          publicPoint: publicPoint,
        );
      default:
        throw const InvalidDataPassed('Unsupported agreement algorithm');
    }
  }

  /// Upstream static `getParameterSpec(stdDomainParam:)`: the private half of
  /// the collapsed overload pair. IDs 0-2 -> RFC 5114 groups; 8-18 ->
  /// pointycastle registry curves; anything else -> [InvalidDataPassed] with
  /// upstream's message, typo (`"p arameterSpec"`) included.
  ///
  /// Footnote (P11 §9.5.1 Table 12): parameterId 10 (NIST P-224) cannot be
  /// used with IM; its p ≡ 1 (mod 4) breaks the App B point encoding.
  /// `PACEHandler.doPACEStep2IM` enforces the footnote, rejecting any ECDH-IM
  /// curve with p ≢ 3 (mod 4) at entry. Resolution here does not: the curve
  /// is perfectly usable with GM.
  static PACEParameterSpec _getParameterSpec(int stdDomainParam) {
    switch (stdDomainParam) {
      case PARAM_ID_GFP_1024_160:
        return DHStandardizedDomain(
          p: _rfc5114_1024_160_p,
          q: _rfc5114_1024_160_q,
          g: _rfc5114_1024_160_g,
        );
      case PARAM_ID_GFP_2048_224:
        return DHStandardizedDomain(
          p: _rfc5114_2048_224_p,
          q: _rfc5114_2048_224_q,
          g: _rfc5114_2048_224_g,
        );
      case PARAM_ID_GFP_2048_256:
        return DHStandardizedDomain(
          p: _rfc5114_2048_256_p,
          q: _rfc5114_2048_256_q,
          g: _rfc5114_2048_256_g,
        );
      case PARAM_ID_ECP_NIST_P192_R1:
        return ECStandardizedDomain(ECDomainParameters('secp192r1'));
      case PARAM_ID_ECP_NIST_P224_R1:
        return ECStandardizedDomain(ECDomainParameters('secp224r1'));
      case PARAM_ID_ECP_NIST_P256_R1:
        return ECStandardizedDomain(ECDomainParameters('secp256r1'));
      case PARAM_ID_ECP_NIST_P384_R1:
        return ECStandardizedDomain(ECDomainParameters('secp384r1'));
      case PARAM_ID_ECP_BRAINPOOL_P192_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp192r1'));
      case PARAM_ID_ECP_BRAINPOOL_P224_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp224r1'));
      case PARAM_ID_ECP_BRAINPOOL_P256_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp256r1'));
      case PARAM_ID_ECP_BRAINPOOL_P320_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp320r1'));
      case PARAM_ID_ECP_BRAINPOOL_P384_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp384r1'));
      case PARAM_ID_ECP_BRAINPOOL_P512_R1:
        return ECStandardizedDomain(ECDomainParameters('brainpoolp512r1'));
      case PARAM_ID_ECP_NIST_P521_R1:
        return ECStandardizedDomain(ECDomainParameters('secp521r1'));
      default:
        throw const InvalidDataPassed(
          'Unable to lookup p arameterSpec - invalid oid',
        );
    }
  }

  /// Upstream `toMappingType(oid:)`.
  static PACEMappingType toMappingType(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256) {
      return PACEMappingType.GM;
    } else if (oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256) {
      return PACEMappingType.IM;
    } else if (oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return PACEMappingType.CAM;
    }
    throw const InvalidDataPassed(
      'Unable to lookup mapping type - invalid oid',
    );
  }

  /// Upstream `toKeyAgreementAlgorithm(oid:)`: "DH" or "ECDH".
  static String toKeyAgreementAlgorithm(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256) {
      return 'DH';
    } else if (oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return 'ECDH';
    }
    throw const InvalidDataPassed(
      'Unable to lookup key agreement algorithm - invalid oid',
    );
  }

  /// Upstream `toCipherAlgorithm(oid:)`: "DESede" or "AES".
  static String toCipherAlgorithm(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC) {
      return 'DESede';
    } else if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return 'AES';
    }
    throw const InvalidDataPassed(
      'Unable to lookup cipher algorithm - invalid oid',
    );
  }

  /// Upstream `toDigestAlgorithm(oid:)`: "SHA-1" or "SHA-256".
  static String toDigestAlgorithm(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) {
      return 'SHA-1';
    } else if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return 'SHA-256';
    }
    throw const InvalidDataPassed(
      'Unable to lookup digest algorithm - invalid oid',
    );
  }

  /// Upstream `toKeyLength(oid:)`: 128, 192, or 256.
  static int toKeyLength(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC ||
        oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) {
      return 128;
    } else if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192) {
      return 192;
    } else if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 ||
        oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return 256;
    }
    throw const InvalidDataPassed('Unable to get key length - invalid oid');
  }

  /// Upstream `toProtocolOIDString(oid:)`: human-readable protocol name.
  ///
  /// Upstream's two typo'd names are preserved verbatim
  /// (`id-PACE_DH-IM-AES-CBC-CMAC-256` with an underscore after `PACE`,
  /// `id-PACE-ECDH-IM_3DES-CBC-CBC` with an underscore after `IM`); the P11
  /// spellings would use hyphens throughout. Unknown OIDs return the OID
  /// unchanged.
  static String _toProtocolOIDString(String oid) {
    if (oid == SecurityInfo.ID_PACE_DH_GM_3DES_CBC_CBC) {
      return 'id-PACE-DH-GM-3DES-CBC-CBC';
    }
    if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128) {
      return 'id-PACE-DH-GM-AES-CBC-CMAC-128';
    }
    if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192) {
      return 'id-PACE-DH-GM-AES-CBC-CMAC-192';
    }
    if (oid == SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256) {
      return 'id-PACE-DH-GM-AES-CBC-CMAC-256';
    }
    if (oid == SecurityInfo.ID_PACE_DH_IM_3DES_CBC_CBC) {
      return 'id-PACE-DH-IM-3DES-CBC-CBC';
    }
    if (oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128) {
      return 'id-PACE-DH-IM-AES-CBC-CMAC-128';
    }
    if (oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192) {
      return 'id-PACE-DH-IM-AES-CBC-CMAC-192';
    }
    if (oid == SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256) {
      return 'id-PACE_DH-IM-AES-CBC-CMAC-256'; // upstream typo verbatim.
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC) {
      return 'id-PACE-ECDH-GM-3DES-CBC-CBC';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) {
      return 'id-PACE-ECDH-GM-AES-CBC-CMAC-128';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192) {
      return 'id-PACE-ECDH-GM-AES-CBC-CMAC-192';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256) {
      return 'id-PACE-ECDH-GM-AES-CBC-CMAC-256';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC) {
      return 'id-PACE-ECDH-IM_3DES-CBC-CBC'; // upstream typo verbatim.
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128) {
      return 'id-PACE-ECDH-IM-AES-CBC-CMAC-128';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192) {
      return 'id-PACE-ECDH-IM-AES-CBC-CMAC-192';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256) {
      return 'id-PACE-ECDH-IM-AES-CBC-CMAC-256';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) {
      return 'id-PACE-ECDH-CAM-AES-CBC-CMAC-128';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192) {
      return 'id-PACE-ECDH-CAM-AES-CBC-CMAC-192';
    }
    if (oid == SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256) {
      return 'id-PACE-ECDH-CAM-AES-CBC-CMAC-256';
    }
    return oid;
  }
}

/// The standardized-domain table (P11 §9.5.1 Table 12) by parameterId,
/// package-internal.
///
/// PACE resolves parameterIds through [PACEInfo.getParameterSpec]; the BSI
/// `standardizedDomainParameters` SubjectPublicKeyInfo form (which App I's
/// PACE-CAM key uses) names its curve the same way, so
/// `subject_public_key_info.dart` resolves it through the same table rather
/// than a second copy. Throws [InvalidDataPassed] for an id the table does
/// not know, exactly as the PACE path does.
///
/// The §9.5.1 Table 12 footnote (parameterId 10 / NIST P-224 is Integrated
/// Mapping-ineligible) does **not** apply to a key encoding: every
/// standardized curve is a legal ECDH key domain.
PACEParameterSpec paceParameterSpecForId(int parameterId) =>
    PACEInfo._getParameterSpec(parameterId);

BigInt _hex(String s) => BigInt.parse(s.replaceAll(' ', ''), radix: 16);

// RFC 5114 §2.1: 1024-bit MODP Group with 160-bit Prime Order Subgroup.
final BigInt _rfc5114_1024_160_p = _hex(
  'B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61'
  '6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF'
  'ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0'
  'A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371',
);
final BigInt _rfc5114_1024_160_g = _hex(
  'A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31'
  '266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4'
  'D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A'
  'D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5',
);
final BigInt _rfc5114_1024_160_q = _hex(
  'F518AA8781A8DF278ABA4E7D64B7CB9D49462353',
);

// RFC 5114 §2.2: 2048-bit MODP Group with 224-bit Prime Order Subgroup.
final BigInt _rfc5114_2048_224_p = _hex(
  'AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75'
  'E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6'
  '6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207'
  'C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836'
  '81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074'
  '15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8'
  'BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29'
  'E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F',
);
final BigInt _rfc5114_2048_224_g = _hex(
  'AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3'
  'A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652'
  'BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A'
  'E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1'
  '19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC'
  'B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381'
  'B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD'
  '7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA',
);
final BigInt _rfc5114_2048_224_q = _hex(
  '801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB',
);

// RFC 5114 §2.3: 2048-bit MODP Group with 256-bit Prime Order Subgroup.
final BigInt _rfc5114_2048_256_p = _hex(
  '87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00'
  'E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C'
  '209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B'
  '6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76'
  'B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E'
  'F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026'
  'C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103'
  'A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597',
);
// Byte-identical to OpenSSL `DH_get_2048_256()`, the exact routine upstream
// PACEInfo.swift:136 calls. Mind the `...21EF2054...` run: RFC 5114 §2.3 has
// `54` there, and a `44` in its place leaves g without order q, a slip only a
// DH-GM handshake on this group (with its subgroup validation) reveals.
final BigInt _rfc5114_2048_256_g = _hex(
  '3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125'
  '10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62'
  '901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B'
  '777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193'
  'B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A'
  'DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915'
  'B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3'
  '2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659',
);
final BigInt _rfc5114_2048_256_q = _hex(
  '8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3',
);
