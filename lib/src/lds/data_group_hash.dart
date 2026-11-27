// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroupHash.swift @ 3bf5456 (2.3.2)
//   (top level upstream, not under DataGroups/)

/// One SOD-vs-computed hash comparison row, produced by
/// `checkDataGroupHashes` in `sod_hash_oracle.dart`.
library;

/// Upstream `DataGroupHash`.
class DataGroupHash {
  const DataGroupHash({
    required this.id,
    required this.sodHash,
    required this.computedHash,
    required this.match,
  });

  /// `DataGroupId.getName()` of the DG the row describes.
  final String id;

  /// Uppercase hex of the hash the SOD carries for the DG.
  final String sodHash;

  /// Uppercase hex of the hash computed over the read file bytes.
  final String computedHash;

  final bool match;
}
