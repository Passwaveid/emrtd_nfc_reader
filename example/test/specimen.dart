/// The ICAO 9303 specimen chip files, copied as hex from the package's own
/// `test/support/emrtd_fixtures.dart`.
///
/// They are copied rather than imported because `test/support/` is not
/// reachable from another package: only `lib/` is. The bytes are ICAO's
/// published specimen document, not anyone's passport.
library;

import 'dart:typed_data';

/// DG1 for the Part 11 specimen: ERIKSSON / ANNA MARIA, UTO, document
/// `L898902C3`, born 740812, expires 340415.
const String dg1Hex =
    '615b5f1f58505055544f4552494b53534f4e3c3c414e4e413c4d415249413c3c3c3c'
    '3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c4c38393839303243333655544f373430383132'
    '3246333430343135395a45313834323236423c3c3c3c3c3136';

/// DG2: a hand-built CBEFF record whose image payload is a 26-byte JPEG stub,
/// a valid JFIF header and nothing decodable after it, which is exactly the
/// case the result screen's `errorBuilder` exists for.
const String dg2Hex =
    '755e7f615b0201017f6055a10887020101880200085f2e48464143003031300000000048'
    '00010000003a000001020300000000010000000000000100005a0078010200000000'
    'ffd8ffe000104a46494600010100000100010000aabbccddffd9';

/// A synthetic CMS wrapper carrying the real SHA-256 hashes of both files.
const String sodHex =
    '7781b53081b206092a864886f70d010702a081a43081a1020103310f300d0609608648'
    '01650304020105003081800606678108010101a07604743072020101300d0609608648'
    '0165030402010500300e1304303130371306303430303030304e302502010104206ed8'
    'e9b3414d2dca5e97162c769420151f6067dabc4b40542a6d0eea318b6b223025020102'
    '0420208e836344369faa58c58c8c3360e50d2f0e604ad1321399a96be69ae787cd2131'
    '0830060201010401aa';

/// `composeMrzKey` over the Part 11 Appendix D worked example (document
/// `L898902C`, born 690806, expires 940623). Deliberately *not* the same
/// document as [dg1Hex]; the fixtures come from two different appendices,
/// and the key is only ever an input, never compared against DG1.
const String specimenMrzKey = 'L898902C<369080619406236';

Uint8List hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
