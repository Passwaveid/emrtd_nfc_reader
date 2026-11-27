/// Shared chip-file fixtures for the PassportReader session tests, lifted
/// verbatim from the LDS conformance vectors (sod_hash_oracle.json
/// "all DGs match" / "tampered DG1" cases; dg2.json "JPEG happy path") so
/// the in-session oracle sees the same bytes the conformance suite pins.
///
/// DG1 is the ICAO specimen TD3 MRZ (ERIKSSON / ANNA MARIA, UTO L898902C3,
/// doc code 'PP', DOB 740812, expiry 340415); DG2 is a hand-built CBEFF
/// record with a minimal JPEG; the SOD is a synthetic CMS wrapper carrying
/// the real SHA-256 hashes of both files.
///
/// The DG14 side: [buildDg14] composes SecurityInfo entries into a file and
/// [buildSpecimenSod] re-derives the SOD over whatever set of files a
/// session test serves, so a DG14 in the read set always has a matching SOD
/// row. `emrtd_fixtures_test.dart` pins [buildSpecimenSod] against the
/// literal [sodHex] above, so the builder cannot drift from the vector. The
/// DG15 side works the same way ([buildDg15] + the `dg15` argument of
/// [buildSpecimenSod]), with AA key material lifted from the independently
/// authored `conformance/vectors/active_auth.json`. The opt-in extras
/// ([buildDg7]/[buildDg11]/[buildDg12] + [specimenFilesWithExtras]) have
/// element shapes that mirror the `dg7`/`dg11`/`dg12` conformance suites.
library;

// ignore_for_file: implementation_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/ec_dh.dart';
import 'package:emrtd_core/src/crypto/hashes.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:pointycastle/ecc/api.dart';

import 'emrtd_chip_sim.dart';

const String dg1GoodHex =
    '615b5f1f58505055544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c3c'
    '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f373430383132'
    '3246333430343135395a45313834323236423c3c3c3c3c3136';

/// Same file with the final composite check digit flipped 6 -> 7: hashes no
/// longer match the SOD row (the oracle-negative shape).
const String dg1TamperedHex =
    '615b5f1f58505055544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c3c'
    '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f373430383132'
    '3246333430343135395a45313834323236423c3c3c3c3c3137';

const String dg2Hex =
    '755e7f615b0201017f6055a10887020101880200085f2e48464143003031300000000048'
    '00010000003a000001020300000000010000000000000100005a0078010200000000'
    'ffd8ffe000104a46494600010100000100010000aabbccddffd9';

/// The JPEG bytes inside [dg2Hex] (DataGroup2.imageData).
const String dg2FaceJpegHex =
    'ffd8ffe000104a46494600010100000100010000aabbccddffd9';

/// DGI: the dg2.json python-oracle row "39794-5 mandatory fields only,
/// JPEG": an ISO/IEC 39794-5 DG2 around the [dg2FaceJpegHex] image.
const String dg2Iso39794Hex =
    '75537f61500201017f604aa108870201018802002a7f2e3da13b6539a0078001038102'
    '07e3a12e302c800100a127a025a023801affd8ffe000104a464946000101000001000100'
    '00aabbccddffd9a105a003800102';

/// DGI: the dg2.json python-oracle row "39794-5 3D shape representation":
/// a 39794-5 DG2 whose one representation is a 3D shape.
const String dg2Iso39794Shape3dHex =
    '75587f61550201017f604fa108870201018802002a7f2e42a140653ea0078001038102'
    '07e3a1333031800100a12ca02aa12880020102a122a004a002a000a103800100a21580'
    '0380000181038000018203800001830084008500';

const String sodHex =
    '7781b53081b206092a864886f70d010702a081a43081a1020103310f300d0609608648'
    '01650304020105003081800606678108010101a07604743072020101300d0609608648'
    '0165030402010500300e1304303130371306303430303030304e302502010104206ed8'
    'e9b3414d2dca5e97162c769420151f6067dabc4b40542a6d0eea318b6b223025020102'
    '0420208e836344369faa58c58c8c3360e50d2f0e604ad1321399a96be69ae787cd2131'
    '0830060201010401aa';

/// EF.CardAccess advertising exactly the ICAO App G.1 combo:
/// id-PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameterId 13
/// (Brainpool P-256-r1), the card_access.json baseline vector.
const String cardAccessG1Hex = '31143012060a04007f0007020204020202010202010d';

/// `composeMrzKey` over the specimen document (doc L898902C, 8 chars, the
/// `<`-padding case, DOB 1969-08-06, expiry 1994-06-23) yields the ICAO
/// App D MRZ-info with check digits 3/1/6.
const String specimenMrzInfo = 'L898902C<369080619406236';

/// The standard three-file chip for happy-path sessions. [dg2] swaps in
/// another DG2 (the [buildLargeDg2] multi-chunk one) with the SOD re-derived
/// over it.
Map<int, Uint8List> specimenFiles({bool tamperedDg1 = false, Uint8List? dg2}) =>
    {
      0x0101: hx(tamperedDg1 ? dg1TamperedHex : dg1GoodHex),
      0x0102: dg2 ?? hx(dg2Hex),
      0x011D: dg2 == null
          ? hx(sodHex)
          : buildSpecimenSod(tamperedDg1: tamperedDg1, dg2: dg2),
    };

// ---------------------------------------------------------------------------
// Multi-chunk DG2 and EF.ATR/INFO fixtures.
// ---------------------------------------------------------------------------

/// A DG2 with the same CBEFF structure as [dg2Hex] around a JFIF image of
/// [imageBytes] bytes, large enough that the chunk size is visible in the
/// READ BINARY sequence (the 96-byte [dg2Hex] is one chunk at any size).
/// The default 1000-byte image gives a 1078-byte file whose 1074-byte body
/// takes 7 chunks at 0xA0 and 5 at 0xDF. The filler never contains `FF`, so
/// the backwards `FF D9` scan of the parser finds the real end-of-image
/// marker.
Uint8List buildLargeDg2({int imageBytes = 1000}) {
  final jfifHeader = hx('ffd8ffe000104a46494600010100000100010000');
  final fillerLength = imageBytes - jfifHeader.length - 2;
  if (fillerLength < 0) {
    throw ArgumentError.value(imageBytes, 'imageBytes', 'too small for JFIF');
  }
  final image = [
    ...jfifHeader,
    ...List<int>.generate(fillerLength, (i) => 0x10 + (i % 0xE0)),
    0xFF,
    0xD9,
  ];
  // ISO 19794-5 facial record: the 46-byte header of the dg2Hex fixture with
  // the record/data lengths recomputed for this image.
  final facialRecordDataLength = 20 + 12 + image.length;
  final recordLength = 4 + 4 + 4 + 2 + facialRecordDataLength;
  final record = [
    0x46, 0x41, 0x43, 0x00, // 'FAC\0'
    0x30, 0x31, 0x30, 0x00, // version '010'
    ...intToBin4(recordLength),
    0x00, 0x01, // one facial image
    ...intToBin4(facialRecordDataLength),
    0x00, 0x00, // no feature points
    0x01, 0x02, 0x03, // gender, eye colour, hair colour
    0x00, 0x00, 0x00, // feature mask
    0x00, 0x00, // expression
    0x01, 0x00, 0x00, // pose angle
    0x00, 0x00, 0x00, // pose angle uncertainty
    0x01, 0x00, // face image type, image data type (JPEG)
    0x00, 0x5A, 0x00, 0x78, // 90 × 120
    0x01, 0x02, // colour space, source type
    0x00, 0x00, 0x00, 0x00, // device type, quality
    ...image,
  ];
  final biometricInfo = TlvRecord(0x7F60, [
    ...TlvRecord(0xA1, [
      ...TlvRecord(0x87, const [0x01, 0x01]).data,
      ...TlvRecord(0x88, const [0x00, 0x08]).data,
    ]).data,
    ...TlvRecord(0x5F2E, record).data,
  ]).data;
  return TlvRecord(
    0x75,
    TlvRecord(0x7F61, [
      ...TlvRecord(0x02, const [0x01]).data,
      ...biometricInfo,
    ]).data,
  ).data;
}

List<int> intToBin4(int v) => [
  (v >> 24) & 0xFF,
  (v >> 16) & 0xFF,
  (v >> 8) & 0xFF,
  v & 0xFF,
];

/// An EF.ATR/INFO file carrying the ISO 7816-4 `7F66` extended-length
/// information template (two INTEGERs, maximum command APDU then maximum
/// response APDU) behind a card-service DO the way a real file leads with
/// other interindustry objects.
Uint8List buildAtrInfo({
  int maxCommandBytes = 0x0800,
  int maxResponseBytes = 0x0800,
}) => Uint8List.fromList([
  ...TlvRecord(0x43, const [0x00]).data,
  ...TlvRecord(0x7F66, [
    ..._derInt(maxCommandBytes),
    ..._derInt(maxResponseBytes),
  ]).data,
]);

// ---------------------------------------------------------------------------
// DG14 / Chip Authentication fixtures.
// ---------------------------------------------------------------------------

/// The chip's static CA private key (Brainpool P-256), fixed so sessions are
/// reproducible. The matching public key goes into every DG14 built below.
final BigInt caChipPrivateKey = BigInt.parse(
  '2a1cd7b48d19cb4bb1cb60cbb1a5b3aa0b6e4f11c4a4fb7f18d0f0a4a3a4b5c6',
  radix: 16,
);

final ECDomainParameters caChipCurve = ECDomainParameters('brainpoolp256r1');

Uint8List _derInt(int v) {
  var bytes = bigIntToBytes(BigInt.from(v)).toList();
  if (bytes.isEmpty) bytes = [0];
  if ((bytes.first & 0x80) != 0) bytes = [0, ...bytes];
  return TlvRecord(0x02, bytes).data;
}

Uint8List _seq(List<List<int>> children) =>
    TlvRecord(0x30, [for (final c in children) ...c]).data;

/// `SubjectPublicKeyInfo` for the chip's CA key, named-curve encoded.
Uint8List caChipSpki() => _seq([
  _seq([
    asn1EncodeOid('1.2.840.10045.2.1'),
    asn1EncodeOid('1.3.36.3.3.2.8.1.1.7'), // brainpoolP256r1
  ]),
  TlvRecord(0x03, [
    0x00,
    ...ecPointEncode(ecPublicFromPrivate(caChipCurve, caChipPrivateKey)),
  ]).data,
]);

/// A DG14 file: `6E { SET OF SecurityInfo }`. With [caOid] a
/// `ChipAuthenticationInfo` is emitted; with [withPublicKey] an
/// `id-PK-ECDH` `ChipAuthenticationPublicKeyInfo` carrying [caChipSpki].
Uint8List buildDg14({String? caOid, bool withPublicKey = true, int? keyId}) {
  final entries = <int>[
    if (caOid != null)
      ..._seq([
        asn1EncodeOid(caOid),
        _derInt(1),
        if (keyId != null) _derInt(keyId),
      ]),
    if (withPublicKey)
      ..._seq([
        asn1EncodeOid('0.4.0.127.0.7.2.2.1.2'),
        caChipSpki(),
        if (keyId != null) _derInt(keyId),
      ]),
  ];
  return TlvRecord(0x6E, TlvRecord(0x31, entries).data).data;
}

/// The fixture-family SOD, rebuilt over the files a session actually serves
/// (SHA-256 rows, ICAO-shaped CMS wrapper). Passing neither [dg14] nor
/// [dg15] reproduces [sodHex] byte-for-byte.
Uint8List buildSpecimenSod({
  Uint8List? dg2,
  Uint8List? dg7,
  Uint8List? dg11,
  Uint8List? dg12,
  Uint8List? dg14,
  Uint8List? dg15,
  bool tamperedDg1 = false,
}) {
  final hashes = <int, List<int>>{
    1: calcSHA256Hash(hx(tamperedDg1 ? dg1TamperedHex : dg1GoodHex)),
    2: calcSHA256Hash(dg2 ?? hx(dg2Hex)),
    if (dg7 != null) 7: calcSHA256Hash(dg7),
    if (dg11 != null) 11: calcSHA256Hash(dg11),
    if (dg12 != null) 12: calcSHA256Hash(dg12),
    if (dg14 != null) 14: calcSHA256Hash(dg14),
    if (dg15 != null) 15: calcSHA256Hash(dg15),
  };
  final lds = _seq([
    _derInt(1),
    _seq([asn1EncodeOid('2.16.840.1.101.3.4.2.1'), TlvRecord(0x05, []).data]),
    _seq([
      TlvRecord(0x13, utf8.encode('0107')).data,
      TlvRecord(0x13, utf8.encode('040000')).data,
    ]),
    _seq([
      for (final e in hashes.entries)
        _seq([_derInt(e.key), TlvRecord(0x04, e.value).data]),
    ]),
  ]);
  final signedData = _seq([
    _derInt(3),
    TlvRecord(
      0x31,
      _seq([asn1EncodeOid('2.16.840.1.101.3.4.2.1'), TlvRecord(0x05, []).data]),
    ).data,
    _seq([
      asn1EncodeOid('2.23.136.1.1.1'),
      TlvRecord(0xA0, TlvRecord(0x04, lds).data).data,
    ]),
    TlvRecord(
      0x31,
      _seq([
        _derInt(1),
        TlvRecord(0x04, const [0xAA]).data,
      ]),
    ).data,
  ]);
  return TlvRecord(
    0x77,
    _seq([
      asn1EncodeOid('1.2.840.113549.1.7.2'),
      TlvRecord(0xA0, signedData).data,
    ]),
  ).data;
}

/// The three-file chip plus a DG14 at fid `0x010E`, with the SOD re-derived
/// so the hash oracle covers all four files. [sodCoversDg14] lets a test serve
/// one DG14 while the SOD attests a different one, the oracle-negative
/// shape, with the CA handshake left intact.
Map<int, Uint8List> specimenFilesWithDg14(
  Uint8List dg14, {
  Uint8List? sodCoversDg14,
  Uint8List? dg15,
}) => {
  0x0101: hx(dg1GoodHex),
  0x0102: hx(dg2Hex),
  0x010E: dg14,
  if (dg15 != null) 0x010F: dg15,
  0x011D: buildSpecimenSod(dg14: sodCoversDg14 ?? dg14, dg15: dg15),
};

/// Chip-side CA configuration matching [buildDg14]/[caChipSpki].
CaSimConfig caConfig(String oid, {int mseSw = 0x9000}) => CaSimConfig(
  oid: oid,
  chipPrivateKey: caChipPrivateKey,
  curve: caChipCurve,
  mseSw: mseSw,
);

// ---------------------------------------------------------------------------
// DG15 / Active Authentication fixtures.
// ---------------------------------------------------------------------------

/// The chip's AA RSA key: the same 1024-bit key `conformance/vectors/
/// active_auth.json` was authored with (generated independently of this
/// package), so a session test and the vector suite exercise the
/// identical modulus.
final BigInt aaRsaModulus = BigInt.parse(
  '912357a1037b89efe87df82d35300cc7dffb46dc3bfd890cf913180b702804d3'
  '85550371b3013cc58966b36af2b86fc8ed44aedc77e43f0f46e44949142ea059'
  'df30980e085e12d6ecb981faf14245886fbbf7b939439debc788fbb676bb3bbb'
  '0cacc8413e8a8b8efd007d67bc12761b16a374cb0e9de7a06cb6940097501a4f',
  radix: 16,
);
final BigInt aaRsaExponent = BigInt.from(65537);
final BigInt aaRsaPrivateExponent = BigInt.parse(
  '0061be537d7442f69a4310d2da5f3f84dbf6d3dadce6e9d02a94736f76048a6ef'
  '5a48da44c2629672c0164d0dfeda69861d0a8b8ba71639db44421e9d8f5669145'
  'f0a3b8e783964a804b0d5c030b4992b1f6e319ff81ae6f1681c3bb8139d791b0b'
  'fc8f0439f17109871ffb49c3dd61071c5c223a42700ca2826474dfaae85df5',
  radix: 16,
);

/// The chip's AA EC key (prime256v1): likewise the `active_auth.json` key.
final BigInt aaEcPrivateKey = BigInt.parse(
  'b2e5c7c9e12f44d1a3b57e8091c6d4f2a8b0d3e5f70921a4c6e80b1d3f5a7092',
  radix: 16,
);

final ECDomainParameters aaEcCurve = ECDomainParameters('secp256r1');

/// `SubjectPublicKeyInfo` for the AA RSA key (`rsaEncryption`, params NULL).
Uint8List aaRsaSpki() => _seq([
  _seq([asn1EncodeOid('1.2.840.113549.1.1.1'), TlvRecord(0x05, const []).data]),
  TlvRecord(0x03, [
    0x00,
    ..._seq([_derBigInt(aaRsaModulus), _derBigInt(aaRsaExponent)]),
  ]).data,
]);

/// `SubjectPublicKeyInfo` for the AA EC key, named-curve encoded.
Uint8List aaEcSpki() => _seq([
  _seq([
    asn1EncodeOid('1.2.840.10045.2.1'),
    asn1EncodeOid('1.2.840.10045.3.1.7'), // prime256v1
  ]),
  TlvRecord(0x03, [
    0x00,
    ...ecPointEncode(ecPublicFromPrivate(aaEcCurve, aaEcPrivateKey)),
  ]).data,
]);

Uint8List _derBigInt(BigInt v) {
  var bytes = bigIntToBytes(v).toList();
  if (bytes.isEmpty) bytes = [0];
  if ((bytes.first & 0x80) != 0) bytes = [0, ...bytes];
  return TlvRecord(0x02, bytes).data;
}

/// A DG15 file: `6F { SubjectPublicKeyInfo }`.
Uint8List buildDg15({bool rsa = true}) =>
    TlvRecord(0x6F, rsa ? aaRsaSpki() : aaEcSpki()).data;

/// A DG15 whose body is not a parseable SubjectPublicKeyInfo: AA silently
/// unsupported, the file still SOD-hashable.
Uint8List buildUnparseableDg15() =>
    TlvRecord(0x6F, const [0xAA, 0xBB, 0xCC]).data;

/// Chip-side AA configuration matching [buildDg15].
AaSimConfig aaRsaConfig({
  List<int> trailer = const [0xBC],
  String hashAlgorithm = 'SHA1',
  bool corruptSignature = false,
}) => AaSimConfig.rsa(
  modulus: aaRsaModulus,
  privateExponent: aaRsaPrivateExponent,
  trailer: trailer,
  hashAlgorithm: hashAlgorithm,
  corruptSignature: corruptSignature,
);

AaSimConfig aaEcConfig({String hashAlgorithm = 'SHA256'}) => AaSimConfig.ecdsa(
  curve: aaEcCurve,
  privateKey: aaEcPrivateKey,
  hashAlgorithm: hashAlgorithm,
);

/// A DG14 carrying a single `ActiveAuthenticationInfo`, optionally
/// naming an `ecdsa-plain-*` signature algorithm.
Uint8List buildDg14WithAa({String? signatureAlgorithmOid}) => TlvRecord(
  0x6E,
  TlvRecord(
    0x31,
    _seq([
      asn1EncodeOid('2.23.136.1.1.5'),
      _derInt(1),
      if (signatureAlgorithmOid != null) asn1EncodeOid(signatureAlgorithmOid),
    ]),
  ).data,
).data;

/// The specimen chip plus DG15 (and optionally DG14), with the SOD re-derived
/// so the hash oracle covers every file served.
Map<int, Uint8List> specimenFilesWithDg15(
  Uint8List dg15, {
  Uint8List? dg14,
  Uint8List? sodCoversDg15,
}) => {
  0x0101: hx(dg1GoodHex),
  0x0102: hx(dg2Hex),
  if (dg14 != null) 0x010E: dg14,
  0x010F: dg15,
  0x011D: buildSpecimenSod(dg14: dg14, dg15: sodCoversDg15 ?? dg15),
};

/// App G.1-shaped PACE configuration (Brainpool P-256 chip keys reused from
/// the package's handshake tests; the nonce is arbitrary: the sim computes
/// the whole handshake dynamically).
PaceSimConfig paceG1Config() => PaceSimConfig(
  oid: '0.4.0.127.0.7.2.2.4.2.2',
  nonce: hx('3f00c4d39d153f2b2a214a078d899b22'),
  chipMappingPrivateKey: BigInt.parse(
    '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
    radix: 16,
  ),
  chipEphemeralPrivateKey: BigInt.parse(
    '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
    radix: 16,
  ),
);

// ---------------------------------------------------------------------------
// PACE-CAM fixtures.
// ---------------------------------------------------------------------------

/// EF.CardAccess advertising id-PACE-ECDH-CAM-AES-CBC-CMAC-128, version 2,
/// parameterId 13: [cardAccessG1Hex] with the CAM OID arc (`...04 06 02`),
/// the App I.1 suite.
const String cardAccessCamHex = '31143012060a04007f0007020204060202010202010d';

/// The same handshake as [paceG1Config] under a CAM OID, with the chip's
/// static CA key wired in so the final GA response carries a real DO8A.
///
/// [staticPrivateKey] defaults to [caChipPrivateKey]: the key
/// [buildDg14]'s `ChipAuthenticationPublicKeyInfo` publishes, so the verify
/// succeeds (the CAM key *is* the CA key). Pass a different scalar for
/// the tampered-key shape, or [camDataObject] for an undecryptable DO8A.
PaceSimConfig paceCamConfig({
  BigInt? staticPrivateKey,
  Uint8List? camDataObject,
  bool omitCamDataObject = false,
}) => PaceSimConfig(
  oid: '0.4.0.127.0.7.2.2.4.6.2',
  nonce: hx('3f00c4d39d153f2b2a214a078d899b22'),
  chipMappingPrivateKey: BigInt.parse(
    '498ff49756f2dc1587840041839a85982be7761d14715fb091efa7bce9058560',
    radix: 16,
  ),
  chipEphemeralPrivateKey: BigInt.parse(
    '107cf58696ef6155053340fd633392ba81909df7b9706f226f32086c7aff974a',
    radix: 16,
  ),
  camStaticPrivateKey: omitCamDataObject
      ? null
      : (staticPrivateKey ?? caChipPrivateKey),
  camDataObject: camDataObject,
);

// ---------------------------------------------------------------------------
// DG7 / DG11 / DG12 (the opt-in extras) fixtures.
// ---------------------------------------------------------------------------

/// EF.DG7: `67 { 02 01 01, 5F43 <image> }` (P10 §4.7.7 Table 62: no CBEFF).
/// The image defaults to the same JFIF bytes the DG2 fixture carries, so a
/// session test can assert `imageFormat` without a second image fixture.
Uint8List buildDg7({Uint8List? image}) => TlvRecord(0x67, [
  ...TlvRecord(0x02, const [0x01]).data,
  ...TlvRecord(0x5F43, image ?? hx(dg2FaceJpegHex)).data,
]).data;

/// EF.DG11 with the elements a display-oriented consumer actually wants: the
/// full name, the `A0` other-names group (a Dart-only addition), personal
/// number, full date of birth, place of birth and permanent address.
Uint8List buildDg11() {
  final elements = <int>[
    ...TlvRecord(0x5F0E, utf8.encode('ERIKSSON<<ANNA<MARIA')).data,
    ...TlvRecord(0xA0, [
      ...TlvRecord(0x02, const [0x01]).data,
      ...TlvRecord(0x5F0F, utf8.encode('SMITH<<JANE<ELIZABETH')).data,
    ]).data,
    ...TlvRecord(0x5F10, utf8.encode('19203040')).data,
    ...TlvRecord(0x5F2B, utf8.encode('19740812')).data,
    ...TlvRecord(0x5F11, utf8.encode('STOCKHOLM<SWEDEN')).data,
    ...TlvRecord(0x5F42, utf8.encode('123<MAIN<ST<UTOPIA<CITY')).data,
  ];
  return TlvRecord(0x6B, [
    // The tag list is never validated against the elements (as upstream);
    // it is written truthfully here all the same.
    ...TlvRecord(0x5C, const [
      0x5F, 0x0E, 0xA0, 0x5F, 0x10, 0x5F, 0x2B, 0x5F, 0x11, 0x5F, 0x42, //
    ]).data,
    ...elements,
  ]).data;
}

/// EF.DG12 with the issuing authority, a BCD date of issue (the branch
/// upstream already has), the `A0` other-persons group, and a personalization
/// timestamp + device serial.
Uint8List buildDg12() {
  final elements = <int>[
    ...TlvRecord(0x5F19, utf8.encode('UTOPIAN PASSPORT AUTHORITY')).data,
    ...TlvRecord(0x5F26, const [0x20, 0x15, 0x03, 0x15]).data,
    ...TlvRecord(0xA0, [
      ...TlvRecord(0x02, const [0x01]).data,
      ...TlvRecord(0x5F1A, utf8.encode('ERIKSSON<<KARL')).data,
    ]).data,
    ...TlvRecord(0x5F55, utf8.encode('20150315123045')).data,
    ...TlvRecord(0x5F56, utf8.encode('PERSO-DEVICE-0042')).data,
  ];
  return TlvRecord(0x6C, [
    ...TlvRecord(0x5C, const [
      0x5F, 0x19, 0x5F, 0x26, 0xA0, 0x5F, 0x55, 0x5F, 0x56, //
    ]).data,
    ...elements,
  ]).data;
}

/// The specimen chip plus whichever extras a session test serves, with the
/// SOD re-derived over exactly those files so the hash oracle covers them.
/// [sodOmitsDg7] serves a DG7 the SOD does **not** hash, the tamper shape
/// the oracle's strictness on extras catches.
Map<int, Uint8List> specimenFilesWithExtras({
  Uint8List? dg7,
  Uint8List? dg11,
  Uint8List? dg12,
  bool sodOmitsDg7 = false,
}) => {
  0x0101: hx(dg1GoodHex),
  0x0102: hx(dg2Hex),
  if (dg7 != null) 0x0107: dg7,
  if (dg11 != null) 0x010B: dg11,
  if (dg12 != null) 0x010C: dg12,
  0x011D: buildSpecimenSod(
    dg7: sodOmitsDg7 ? null : dg7,
    dg11: dg11,
    dg12: dg12,
  ),
};
