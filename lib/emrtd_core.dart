/// eMRTD (passport and ID-card chip) reading over NFC for Flutter: BAC, PACE,
/// secure messaging, Chip and Active Authentication, LDS data-group parsing
/// and on-device passive authentication. A Dart port of
/// AndyQ/NFCPassportReader v2.3.2 (MIT); the pin, the per-file port status
/// and every divergence are in UPSTREAM.md.
///
/// Start with [PassportReader]. Its `readPassport` runs one NFC session end
/// to end and returns a [PassportReadResult], or throws a
/// [PassportReadException] carrying the step the read failed at, its typed
/// cause where there is one, and a [PassportReadTrace] of everything it
/// observed. [composeMrzKey] derives the access key from the three MRZ
/// values, and [Dg1Fields] reads the holder's details out of DG1.
///
/// The other exports are the layers the reader is built from, for an app
/// that drives them itself: the NFC session and transceiver interfaces
/// ([NfcSession], [NfcTransceiver]) with their `flutter_nfc_kit`
/// implementation; the APDU types and [TagReader]; [BACHandler],
/// [PACEHandler], [ChipAuthenticationHandler] and
/// [verifyActiveAuthentication]; the data groups, [SOD] and the hash oracle;
/// passive authentication with its [CscaTrustStore]; the error types; and
/// the version constants. Only `src/transport/` touches Flutter or the NFC
/// plugin; the rest is plain Dart.
library;

export 'src/crypto/rng.dart';
export 'src/errors.dart';
export 'src/lds/active_authentication_info.dart';
export 'src/lds/atr_info.dart';
export 'src/lds/card_access.dart';
export 'src/lds/chip_authentication_info.dart';
export 'src/lds/chip_authentication_public_key_info.dart';
export 'src/lds/com.dart';
export 'src/lds/data_group.dart';
export 'src/lds/data_group1.dart';
export 'src/lds/data_group11.dart';
export 'src/lds/data_group12.dart';
export 'src/lds/data_group14.dart';
export 'src/lds/data_group15.dart';
export 'src/lds/data_group2.dart';
export 'src/lds/data_group7.dart';
export 'src/lds/data_group_hash.dart';
export 'src/lds/data_group_id.dart';
export 'src/lds/data_group_parser.dart';
export 'src/lds/dg11_fields.dart';
export 'src/lds/dg12_fields.dart';
export 'src/lds/dg1_fields.dart';
export 'src/lds/face_image_info.dart';
export 'src/lds/not_implemented_dg.dart';
// `paceParameterSpecForId` is the SPKI parser's package-internal route into
// the standardized-domain table, not public API.
export 'src/lds/pace_info.dart' hide paceParameterSpecForId;
export 'src/lds/security_info.dart';
export 'src/lds/sod.dart';
export 'src/lds/sod_hash_oracle.dart';
export 'src/lds/subject_public_key_info.dart';
// The CMS/X.509 model and the verdict API. `verifyCmsSignature`,
// `resolveSignerCertificate` and `verifyPassiveAuthWithHashCheck` stay
// package-internal (the reader's seam and the trust store's plumbing).
export 'src/pki/cms_signed_data.dart';
export 'src/pki/csca_trust_store.dart'
    hide resolveSignerCertificate, verifyCmsSignature;
export 'src/pki/passive_auth.dart' hide verifyPassiveAuthWithHashCheck;
export 'src/pki/x509_certificate.dart';
export 'src/proto/active_authentication.dart';
export 'src/proto/bac.dart';
export 'src/proto/chip_authentication.dart';
export 'src/proto/command_apdu.dart';
export 'src/proto/pace.dart';
export 'src/proto/read_quirks.dart';
export 'src/proto/response_apdu.dart';
export 'src/proto/secure_messaging.dart';
export 'src/proto/tag_reader.dart' hide decodeError;
export 'src/reader/passport_reader.dart';
export 'src/reader/read_profile.dart';
export 'src/transport/nfc_kit_transceiver.dart' hide mapNfcKitPlatformException;
export 'src/transport/nfc_session.dart';
export 'src/transport/transceiver.dart';
export 'src/version.dart';
