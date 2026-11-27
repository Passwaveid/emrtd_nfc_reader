// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: replaces the CoreNFC `NFCISO7816Tag` session/tag coupling in
//   Sources/NFCPassportReader/TagReader.swift @ 3bf5456 (2.3.2)

/// Transceiver seam: the single abstraction between the protocol layer and
/// whatever moves APDU bytes, `flutter_nfc_kit` in production
/// (`nfc_kit_transceiver.dart`, the only Flutter-importing file in `lib/`), a
/// scripted fake in transcript replay (`test/support/`).
///
/// Session lifecycle (poll, finish, iOS alert messages) is owned by the
/// `NfcSession` seam and its default `flutter_nfc_kit` implementation, both
/// shipped by this package; apps may inject their own.
library;

import 'dart:typed_data';

/// Moves one command APDU to the chip and returns the full response
/// **including trailing SW1/SW2**, `flutter_nfc_kit`'s `transceive`
/// contract, and the contract every implementation must match.
///
/// Error mapping contract: implementations translate their transport's
/// failures into the `EmrtdException` hierarchy (timeout -> `TimeOutError`,
/// tag lost / connection closed -> `ConnectionError`, transceive with no
/// connected tag -> `NoConnectedTag`), never leaking platform exception types
/// to callers.
abstract class NfcTransceiver {
  /// Sends [capdu] and returns data‖SW1‖SW2 (≥ 2 bytes on success).
  Future<Uint8List> transceive(Uint8List capdu);

  /// Largest frame this transport can move in either direction, in bytes.
  /// `TagReader` fits its read-chunk size so no READ BINARY response frame,
  /// secure-messaging overhead included, can exceed it (`fitReadLength`),
  /// and `TagReader.send` refuses to emit a command longer than it (throws
  /// `InvalidDataPassed`).
  int get maxTransceiveLength;

  /// The ISO-DEP historical bytes of the polled tag (the ATS payload,
  /// Type A only), or null when the transport does not know them.
  /// Recorded on the read trace for the chip-capability census; an issuer
  /// may place extended-length information there (9303-10 §3.6.4.1).
  Uint8List? get historicalBytes;

  /// Whether the transport supports extended-length APDUs. When false,
  /// `TagReader.send` refuses to emit one (throws `InvalidDataPassed`) rather
  /// than sending a command the stack will mangle. Spec stance: extended length
  /// MUST NOT be used unless the chip's buffer sizes are known (9303-10 §3.6.4,
  /// 9303-11 §9.3.1.2, TR-03110-3 B.12), capability data this seam is the gate
  /// for.
  bool get isExtendedLengthApduSupported;

  /// What the transport learned about the tag at poll time, or null when it has
  /// no polled tag to report on: a scripted transcript, a simulator. Recorded
  /// on the read trace beside [historicalBytes].
  TagCapabilities? get tagCapabilities;
}

/// The facts a transport's poll response states about the tag it found: the
/// ISO 14443 anti-collision and activation data, carried as the transport
/// reports them, so a census can tell a Type A from a Type B document without
/// inferring it from the absence of historical bytes.
///
/// Every field is optional because no single platform reports all of them.
/// Over `flutter_nfc_kit` 3.6.2:
///
/// | field | Android | iOS |
/// |---|---|---|
/// | [type] | `iso7816` for any ISO-DEP tag | `iso7816` |
/// | [standard] | `ISO 14443-4 (Type A)` / `ISO 14443-4 (Type B)` | `ISO 14443-4 (Type A)` when historical bytes are present, `... (Type B)` when application data is, bare `ISO 14443` otherwise |
/// | [atqa], [sak] | Type A only | never |
/// | [protocolInfo] | Type B only | never |
/// | [applicationData] | Type B only | Type B only |
///
/// [type] and [standard] are the plugin's strings verbatim, including its
/// `unknown`, so a consumer sees exactly what the platform said. Byte fields
/// are raw, as [NfcTransceiver.historicalBytes] is, which stays a separate
/// getter, not a member here.
///
/// **The tag identifier (UID / PUPI) is deliberately not carried, and the
/// type has no field it could go in.** An eMRTD is supposed to randomise it
/// per session and not every document does; a static one would be a
/// persistent document identifier riding along with every read.
class TagCapabilities {
  const TagCapabilities({
    this.type,
    this.standard,
    this.atqa,
    this.sak,
    this.protocolInfo,
    this.applicationData,
  });

  /// The transport's tag-type name (`iso7816`, `unknown`, ...).
  final String? type;

  /// The transport's standard string (`ISO 14443-4 (Type A)`, ...).
  final String? standard;

  /// ISO 14443-3 Type A answer-to-request, two bytes.
  final Uint8List? atqa;

  /// ISO 14443-3 Type A select acknowledge, one byte.
  final Uint8List? sak;

  /// ISO 14443-3 Type B ATQB protocol info, three bytes.
  final Uint8List? protocolInfo;

  /// ISO 14443-3 Type B ATQB application data, four bytes.
  final Uint8List? applicationData;
}
