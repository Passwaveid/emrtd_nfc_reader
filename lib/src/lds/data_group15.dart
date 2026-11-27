// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup15.swift @ 3bf5456
//   (2.3.2). Upstream's two `OpaquePointer` fields (`ecdsaPublicKey`,
//   `rsaPublicKey`) collapse into one [SubjectPublicKey] sum-type field: the
//   Dart SPKI parser dispatches on the algorithm OID where upstream tries
//   `d2i_EC_PUBKEY` first and `d2i_RSA_PUBKEY` on failure, both under `try?`.
//   The `deinit` free has no Dart counterpart.

/// DG15 (EF.DG15): the chip's Active Authentication public key.
///
/// ```asn1
/// EF.DG15 ::= [APPLICATION 15] IMPLICIT SubjectPublicKeyInfo
/// ```
///
/// The body is a bare `SubjectPublicKeyInfo`, handed to the shared
/// [parseSubjectPublicKeyInfo]. Upstream's readers accept EC and RSA only, so
/// a DH SPKI (which that parser does understand) maps to `null` here:
/// exposing it would depart from upstream, and `null` is the parity value.
///
/// As upstream, the parse **never throws** (upstream's `try?` pair), so an
/// unparseable body leaves [publicKey] null, AA silently unsupported, and the
/// raw file bytes intact for the SOD hash oracle, as for every DG that is not
/// fully parsed.
library;

import 'data_group.dart';
import 'data_group_id.dart';
import 'subject_public_key_info.dart';

/// Upstream `DataGroup15`.
class DataGroup15 extends DataGroup {
  DataGroup15(super.data);

  SubjectPublicKey? _publicKey;

  @override
  DataGroupId get datagroupType => DataGroupId.DG15;

  /// The parsed AA public key: [SpkiEcPublicKey] (upstream's
  /// `ecdsaPublicKey`) or [SpkiRsaPublicKey] (upstream's `rsaPublicKey`);
  /// `null` when the body is unparseable or carries a DH key.
  SubjectPublicKey? get publicKey => _publicKey;

  /// Upstream `NFCPassportModel.activeAuthenticationSupported`'s DG15 half
  /// (`ecdsaPublicKey != nil || rsaPublicKey != nil`).
  bool get isActiveAuthenticationSupported => _publicKey != null;

  @override
  void parse(List<int> data) {
    final key = parseSubjectPublicKeyInfo(body);
    _publicKey = key is SpkiDhPublicKey ? null : key;
  }
}
