/// Quirk-table seam: optional per-read knobs threaded into [TagReader], the
/// package's answer to issuer-specific chip dialects without scattering
/// issuer conditionals through protocol code.
///
/// Policy: the table of *entries* is app-owned and ships **empty**; the port
/// launches with zero issuer conditionals, preserving the universal-tolerance
/// design of its Dart-only additions. The package only defines the knobs,
/// each of which either already existed or is a one-line dispatch to honor.
/// An entry is added only on confirmed device-matrix/field evidence, and
/// every entry requires a conformance transcript reproducing both the quirk
/// and the non-quirk path, plus a reference to the field report or upstream
/// defect behind it. Standing first candidate: the Danish `3F00 3004`
/// MF-select variant, which breaks UK documents (the two dialects are
/// mutually incompatible, so universal tolerance cannot cover both).
library;

/// How `TagReader.readCardAccess` selects its way to EF.CardAccess.
enum MasterFileSelectVariant {
  /// The default ladder: SELECT MF with `data=3F00`, as upstream does,
  /// falling through to a direct SELECT-by-FID of EF.CardAccess when the
  /// chip refuses the MF select (`6A 86`/`6D 00`/`67 00`/`69 85`).
  iso3F00,

  /// Skip the MF select entirely and go straight to SELECT-by-FID (the
  /// fallback as the primary path).
  directFid,

  /// The Danish dialect: SELECT MF with `data=3F00 3004`. Breaks UK
  /// documents (`67 00`), so it can only ever be a quirk-table entry keyed
  /// on issuing state, never the default.
  fid3F003004,
}

/// Per-read quirk knobs. [ReadQuirks.none] is the universal default
/// and MUST stay behaviorally identical to a `TagReader` without quirks.
class ReadQuirks {
  const ReadQuirks({
    this.selectVariant = MasterFileSelectVariant.iso3F00,
    this.maxReadLength,
    this.timeoutMultiplier = 1.0,
  });

  /// The zero-entry default: standard select ladder, the caller's read-chunk
  /// size, unscaled timeout.
  static const ReadQuirks none = ReadQuirks();

  /// EF.CardAccess select dialect (see [MasterFileSelectVariant]).
  final MasterFileSelectVariant selectVariant;

  /// When non-null, overrides `TagReader.maxDataLengthToRead` at
  /// construction, over the `ReadProfile` chunk too. Stored as given; the
  /// read loop fits it to the transport frame cap (`fitReadLength`). The
  /// Kazakh-class chips that only serve ≤ 0xE7-byte reads are the intended
  /// consumer.
  final int? maxReadLength;

  /// Multiplier for the per-command transceive timeout. The timeout lives
  /// on the transceiver, so `TagReader` carries this value un-consumed;
  /// `PassportReader` applies it to its base `transceiveTimeout` when
  /// polling.
  final double timeoutMultiplier;
}
