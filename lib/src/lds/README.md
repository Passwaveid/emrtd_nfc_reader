# src/lds

Parsing what the chip stores: EF.CardAccess and its `SecurityInfo` records
(`CardAccess`, `PACEInfo`), EF.ATR/INFO, and the LDS files COM, SOD and the
data groups DG1, DG2, DG7, DG11, DG12, DG14 and DG15, with the SOD hash
oracle, all on the TLV reader in `tlv.dart`. All of it is plain Dart.

`Dg1Fields`, `Dg11Fields` and `Dg12Fields` are typed views over the parsed
data groups for display, with no upstream counterpart. They are untrusted
convenience, never an input to a trust decision. Four files are not
exported from the barrel: `tlv.dart`, `mrz_text.dart` (the name and filler
rules the three typed views share), `dg_text.dart` (upstream's DG12 value
decoders, which DG11's `5F2B` also uses) and `iso39794_face.dart`.

`subject_public_key_info.dart` parses the X.509 `SubjectPublicKeyInfo` that
DG14 and DG15 carry: EC with named or explicit prime-field parameters, X9.42
and PKCS#3 DH, RSA, and the BSI `standardizedDomainParameters` form
(OID 0.4.0.127.0.7.1.2 with an INTEGER `parameterId`), which ICAO 9303
Part 11 App I's PACE-CAM key uses and OpenSSL cannot parse.

`iso39794_face.dart` walks an ISO/IEC 39794-5 face record, the `7F2E`
biometric data block of a DG2 encoded to the ICAO eMRTD application profile,
for `DataGroup2.parseISO39794_5`, and maps what has an ISO/IEC 19794-5
equivalent onto `face_image_info.dart`'s code points.
