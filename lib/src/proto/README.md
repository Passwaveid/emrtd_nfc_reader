# src/proto

The protocols that run over the transport: BAC, secure messaging (DES and
AES), PACE, Chip Authentication and Active Authentication, with the APDU
types and `TagReader` that carry them. The crypto primitives they use
(ciphers, hashes, key derivation, CMAC and the retail MAC, EC and DH key
agreement, an injectable random source, raw RSA and ECDSA verification) are
in `../crypto/`. All of it is plain Dart.

PACE goes beyond upstream. DH Generic Mapping completes, where upstream
aborts at step 3. Integrated Mapping is implemented for all eight IM OIDs,
where upstream stubs it out. A DH public key received from the chip is
validated before it is used. Chip Authentication Mapping extracts and
decrypts the DO8A data the chip returns (`PaceCamData`), which upstream
ignores. All four PACE passwords (MRZ, CAN, PIN, and PUK as
`PacePassword.cuk`) work through `PacePassword` and
`PACEHandler.doPACEWithPassword`, and `doPACE(mrzKey)` stays as the MRZ
shortcut. Checking the CAM data against DG14's key is
`reader/passport_reader.dart`'s job, since DG14 is read long after PACE
ends.

`TagReader` fits each READ BINARY to the transport's frame size with the
secure-messaging overhead counted (`fitReadLength`, using
`SecureMessagingSession.padLength`), starts at the chunk size its
`readChunk` sets, records what its last read did (`lastRead`), and can read
EF.ATR/INFO before authentication (`readAtrInfo`). Every departure from
upstream is listed in UPSTREAM.md.
