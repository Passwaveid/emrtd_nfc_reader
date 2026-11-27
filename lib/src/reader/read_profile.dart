/// The consumer's read-throughput appetite: how large a READ BINARY chunk
/// `PassportReader` starts a session at, and whether it may use
/// extended-length reads on a chip that states its buffer sizes.
///
/// A profile is a policy choice about *this consumer's* tolerance for a
/// retry on the rare chip that caps reads below the chunk; per-issuer facts
/// about *documents* stay in `ReadQuirks`, whose `maxReadLength` wins over
/// any profile.
library;

enum ReadProfile {
  /// Upstream's 0xA0 chunk, and never a larger one: the escape hatch for a
  /// document that is slower with `standard`.
  conservative(readChunk: 0xA0, extendedLength: false),

  /// The default: 0xDF (223), JMRTD's production chunk, under the dmrtd
  /// maintainer's ≤ 224 advice, at or below every chip cap reported from the
  /// field, and the largest value whose secure-messaging response frame
  /// (244 bytes under 3DES and AES alike) fits both the 261-byte ISO-DEP
  /// constant and the 253-byte figure of Broadcom-era Android devices. A
  /// chip that needs 160 costs one failed chunk plus a re-authentication,
  /// after which the session reads at 0xA0 (the recovery ladder).
  standard(readChunk: 0xDF, extendedLength: false),

  /// `standard` plus extended-length reads where the transport declares
  /// support and the chip explicitly states its buffer sizes (9303-10
  /// §3.6.4.2). The gate itself is not wired yet; until it is, this profile
  /// reads exactly as [standard].
  extended(readChunk: 0xDF, extendedLength: true);

  const ReadProfile({required this.readChunk, required this.extendedLength});

  /// The READ BINARY length handed to `TagReader` at construction.
  final int readChunk;

  /// Whether extended-length reads are permitted when the chip and the
  /// transport both qualify.
  final bool extendedLength;
}
