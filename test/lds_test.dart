/// LDS unit tests. What the conformance vectors can't express: the
/// parser-table alignment, error-field values (`InvalidResponse.actualTag`
/// where the port's BER tag rule splits from upstream), object
/// identity/equality surfaces, and the oracle register state machine across
/// multiple pairs.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/hashes.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/com.dart';
import 'package:emrtd_core/src/lds/data_group1.dart';
import 'package:emrtd_core/src/lds/data_group11.dart';
import 'package:emrtd_core/src/lds/data_group12.dart';
import 'package:emrtd_core/src/lds/data_group14.dart';
import 'package:emrtd_core/src/lds/data_group.dart';
import 'package:emrtd_core/src/lds/data_group15.dart';
import 'package:emrtd_core/src/lds/data_group2.dart';
import 'package:emrtd_core/src/lds/data_group7.dart';
import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:emrtd_core/src/lds/data_group_parser.dart';
import 'package:emrtd_core/src/lds/face_image_info.dart';
import 'package:emrtd_core/src/lds/iso39794_face.dart';
import 'package:emrtd_core/src/lds/not_implemented_dg.dart';
import 'package:emrtd_core/src/lds/sod.dart';
import 'package:emrtd_core/src/lds/sod_hash_oracle.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/emrtd_chip_sim.dart' show hx;
import 'support/emrtd_fixtures.dart';
import 'support/emrtd_test_pki.dart';

Uint8List bytes(List<int> b) => Uint8List.fromList(b);

void main() {
  group('DataGroupParser table alignment (18/18)', () {
    test('the three parallel arrays have 18 entries each', () {
      expect(DataGroupParser.dataGroupNames.length, 18);
      expect(DataGroupParser.tags.length, 18);
      expect(DataGroupParser.classes.length, 18);
    });

    test('names row i maps (via DataGroupId) to the tag at row i', () {
      for (var i = 0; i < 18; i++) {
        final name = DataGroupParser.dataGroupNames[i];
        final id = DataGroupId.getIDFromName(name);
        expect(id, isNot(DataGroupId.Unknown), reason: 'row $i: "$name"');
        expect(
          id.id,
          DataGroupParser.tags[i],
          reason:
              'row $i: "$name" vs tag '
              '0x${DataGroupParser.tags[i].toRadixString(16)}',
        );
      }
    });

    test('classes row alignment: ported rows + the parserless remainder', () {
      expect(DataGroupParser.classes[0], equals(COM.new));
      expect(DataGroupParser.classes[1], equals(DataGroup1.new));
      expect(DataGroupParser.classes[2], equals(DataGroup2.new));
      // DG7 (row 7), DG11 (11), DG12 (12), DG14 (14) and DG15 (15) are in
      // the ported set too.
      expect(DataGroupParser.classes[7], equals(DataGroup7.new));
      expect(DataGroupParser.classes[11], equals(DataGroup11.new));
      expect(DataGroupParser.classes[12], equals(DataGroup12.new));
      expect(DataGroupParser.classes[14], equals(DataGroup14.new));
      expect(DataGroupParser.classes[15], equals(DataGroup15.new));
      expect(DataGroupParser.classes[17], equals(SOD.new));
      // What remains on NotImplementedDG is exactly the set upstream has no
      // parser for either: DG3/4/5/6/8/9/10/13/16 (parity holds).
      const ported = {7, 11, 12, 14, 15};
      for (var i = 3; i < 17; i++) {
        if (ported.contains(i)) continue;
        expect(
          DataGroupParser.classes[i],
          equals(NotImplementedDG.new),
          reason:
              'row $i (${DataGroupParser.dataGroupNames[i]}) must '
              'redirect to NotImplementedDG (upstream has no parser for it '
              'either)',
        );
      }
    });
  });

  group('DataGroup base walk', () {
    test('inner 6F 1F reads as single-byte tag 0x6F (actualTag pin)', () {
      // The split conformance case pins the InvalidResponse code on both
      // runners; the divergent actualTag (0x6F here, 0x6F1F upstream) is
      // only observable via the error fields, pinned here.
      try {
        DataGroup1(const [0x61, 0x04, 0x6F, 0x1F, 0x01, 0x41]);
        fail('expected InvalidResponse');
      } on InvalidResponse catch (e) {
        expect(e.actualTag, 0x6F);
        expect(e.expectedTag, 0x5F1F);
        expect(e.dataGroupId, DataGroupId.DG1);
      }
    });

    test('body and data keep trailing bytes beyond the declared length', () {
      final dg = NotImplementedDG(const [0x67, 0x02, 0xAA, 0xBB, 0xCC, 0xDD]);
      expect(dg.body, bytes(const [0xAA, 0xBB, 0xCC, 0xDD]));
      expect(dg.data, bytes(const [0x67, 0x02, 0xAA, 0xBB, 0xCC, 0xDD]));
    });

    test('hash() matches the SHA helpers over data', () {
      final dg = NotImplementedDG(const [0x67, 0x02, 0xAA, 0xBB]);
      expect(dg.hash('SHA1'), calcSHA1Hash(dg.data));
      expect(dg.hash('SHA224'), calcSHA224Hash(dg.data));
      expect(dg.hash('SHA256'), calcSHA256Hash(dg.data));
      expect(dg.hash('SHA384'), calcSHA384Hash(dg.data));
      expect(dg.hash('SHA512'), calcSHA512Hash(dg.data));
    });

    test('unknown and case-mismatched names throw', () {
      final dg = NotImplementedDG(const [0x67, 0x01, 0xAA]);
      expect(
        () => dg.hash('MD5'),
        throwsA(isA<InvalidHashAlgorithmSpecified>()),
      );
      expect(
        () => dg.hash('sha256'),
        throwsA(isA<InvalidHashAlgorithmSpecified>()),
      );
      expect(
        () => dg.hash('SHA-256'),
        throwsA(isA<InvalidHashAlgorithmSpecified>()),
      );
    });

    test('walk truncation surfaces typed errors', () {
      expect(
        () => NotImplementedDG(const []),
        throwsA(isA<CannotDecodeASN1Length>()),
      );
      expect(
        () => NotImplementedDG(const [0x67]),
        throwsA(isA<CannotDecodeASN1Length>()),
      );
      // Two-byte tag opening at the last byte of a DG1 body.
      expect(
        () => DataGroup1(const [0x61, 0x01, 0x5F]),
        throwsA(isA<TagNotValid>()),
      );
      // Declared value length past the end of the buffer.
      expect(
        () => DataGroup1(const [0x61, 0x04, 0x5F, 0x1F, 0x10, 0x41]),
        throwsA(isA<InvalidASN1Value>()),
      );
    });
  });

  group('DataGroup2', () {
    test('strict FAC header check pins expected/actual tags', () {
      final record = [
        0x58, 0x41, 0x43, 0x00, //
        ...List<int>.filled(40, 0x00),
      ];
      final file = _dg2File(record);
      try {
        DataGroup2(file);
        fail('expected InvalidResponse');
      } on InvalidResponse catch (e) {
        expect(e.expectedTag, 0x46);
        expect(e.actualTag, 0x58);
        expect(e.dataGroupId, DataGroupId.DG2);
      }
    });

    test('a 39794-5 envelope that is not TLV is malformed', () {
      final envelope = TlvRecord(
        0xA1,
        TlvRecord(0x65, const [0x01, 0x02, 0x03]).data,
      ).data;
      final file = _dg2File(envelope, bdbTag: 0x7F2E);
      try {
        DataGroup2(file);
        fail('expected InvalidDataPassed');
      } on InvalidDataPassed catch (e) {
        expect(e.reason, 'DG2 ISO/IEC 39794-5 structure malformed');
      }
    });

    test('a 19794-5 record reads as iso19794 under either tag', () {
      final record = hx(dg2Hex).sublist(24); // the 5F2E value
      expect(DataGroup2(hx(dg2Hex)).encoding, FaceRecordEncoding.iso19794);
      expect(
        DataGroup2(_dg2File(record, bdbTag: 0x7F2E)).encoding,
        FaceRecordEncoding.iso19794,
      );
    });

    test('the 39794-5 image gets the 19794-5 image rules', () {
      final image = [...hx(dg2FaceJpegHex), 0x00, 0x00, 0x00];
      final dg2 = DataGroup2(_dg2File(_iso39794(image), bdbTag: 0x7F2E));
      expect(dg2.encoding, FaceRecordEncoding.iso39794);
      expect(dg2.faceImageFormat, FaceImageFormat.jpeg);
      expect(dg2.imageData, hx(dg2FaceJpegHex), reason: 'cut after EOI');
    });

    final samples = Platform.environment['EMRTD_39794_SAMPLES'];
    test(
      'ICAO silver DG2s and the ISO sample (out of tree)',
      () {
        Uint8List read(String name, String sha256) {
          final data = File('$samples/$name').readAsBytesSync();
          expect(calcSHA256Hash(data), hx(sha256), reason: name);
          return data;
        }

        const silverImage =
            '53e1cbbf9194c2aba069ff7db606201e61d6a6d45213fb763cde2a169eb54bb6';
        final mandatory = DataGroup2(
          read(
            'DG2 Silver Dataset (Mandatory Fields Only).dat',
            'ea2e4070b6df3dbf777a872b8a4dc9c573cbb6987d165a3d3ae2c626d620d68f',
          ),
        );
        final all = DataGroup2(
          read(
            'DG2 Silver Dataset (All Fields).dat',
            '0b63e9fe8dde699d3be7eebeed754d722e4e73670039ed5237c293d56bc70034',
          ),
        );
        for (final dg2 in [mandatory, all]) {
          expect(dg2.encoding, FaceRecordEncoding.iso39794);
          expect(dg2.faceImageFormat, FaceImageFormat.jp2);
          expect(dg2.imageData.length, 15000);
          expect(calcSHA256Hash(dg2.imageData), hx(silverImage));
          expect(dg2.nrImages, 1);
          expect(dg2.numberOfFacialImages, 1);
          expect(dg2.imageDataType, 1);
          expect(FaceImageInfo.from(dg2).faceImageType, isNull);
        }
        expect(
          [
            mandatory.imageWidth,
            mandatory.imageHeight,
            mandatory.imageColorSpace,
            mandatory.sourceType,
            mandatory.eyeColor,
            mandatory.hairColor,
            mandatory.featureMask,
            mandatory.expression,
          ],
          [0, 0, 0, 0, 0, 0, 0, 0],
        );
        expect(
          [
            all.imageWidth,
            all.imageHeight,
            all.imageColorSpace,
            all.sourceType,
            all.eyeColor,
            all.hairColor,
            all.featureMask,
            all.expression,
          ],
          [572, 731, 1, 2, 2, 4, 1, 1],
        );

        final sample = read(
          'sample-39794-5-ed-1-v1.der',
          '83c5f22e2d85ad361e81459bbfc14a65b745ed3fd6199c0ec25e515218fb2949',
        );
        final r = parseIso39794FaceRecord(TlvRecord(0xA1, sample).data);
        expect(r.representationCount, 1);
        expect(r.image.length, 893557);
        expect(
          calcSHA256Hash(r.image),
          hx(
            '3bb1d69b85aeeb207a0fe219520fd642f63ca6da4385a7f49a75a0528b400b8a',
          ),
        );
        expect(
          [
            r.imageDataType,
            r.imageWidth,
            r.imageHeight,
            r.imageColorSpace,
            r.sourceType,
            r.eyeColor,
            r.hairColor,
            r.featureMask,
            r.expression,
          ],
          [0, 0, 0, 0, 1, 0, 4, 1, 0],
        );
      },
      skip: samples == null
          ? 'EMRTD_39794_SAMPLES unset: the samples are not redistributable'
          : null,
    );
  });

  group('sniffImageFormat', () {
    test(
      'agrees with DataGroup2.faceImageFormat on the dg2 vector fixtures',
      () {
        // Same three header constants, same dispatch order; the sniff must
        // reach DG2's verdict on every file DG2 itself accepts.
        final suite =
            jsonDecode(File('conformance/vectors/dg2.json').readAsStringSync())
                as Map<String, Object?>;
        final formatCases = (suite['cases']! as List)
            .cast<Map>()
            .map((c) => c.cast<String, Object?>())
            .where((c) => c['op'] == 'dg2.faceImageFormat')
            .toList();
        expect(
          formatCases,
          isNotEmpty,
          reason: 'the dg2 suite must still carry faceImageFormat cases',
        );

        for (final c in formatCases) {
          final hex = (c['input']! as Map)['data']! as String;
          final dg2 = DataGroup2([
            for (var i = 0; i < hex.length; i += 2)
              int.parse(hex.substring(i, i + 2), radix: 16),
          ]);
          expect(
            sniffImageFormat(dg2.imageData),
            dg2.faceImageFormat,
            reason: c['name'] as String?,
          );
        }
      },
    );

    test('returns null instead of throwing where DG2 would reject', () {
      // The deliberate difference: DG7/DG12 images must not fail a parse
      // just because the format is unrecognized.
      expect(sniffImageFormat(const []), isNull);
      expect(sniffImageFormat(const [0xAA, 0xBB, 0xCC]), isNull);
      // Truncated JFIF prefix: 9 of the 10 bytes.
      expect(
        sniffImageFormat(const [
          0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, //
        ]),
        isNull,
      );
      // Exif JPEG: DG2's JFIF-only strictness, inherited.
      expect(sniffImageFormat(const [0xff, 0xd8, 0xff, 0xe1]), isNull);
    });

    test('matches on prefix alone: no end scan, no box walk', () {
      // A JFIF header with no EOI marker at all: DG2's extraction would throw
      // UnknownImageFormat, the sniff still reports jpeg.
      const headerOnly = [
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, //
      ];
      expect(sniffImageFormat(headerOnly), FaceImageFormat.jpeg);
      expect(
        sniffImageFormat(const [
          0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, //
        ]),
        FaceImageFormat.jp2,
      );
      expect(
        sniffImageFormat(const [0xff, 0x4f, 0xff, 0x51]),
        FaceImageFormat.jpeg2000Codestream,
      );
    });
  });

  group('FaceImageInfo', () {
    test('fromMask decodes multi-bit masks to flag sets', () {
      expect(Features.fromMask(0x000000), isEmpty);
      expect(Features.fromMask(0x000002), {Features.glasses});
      expect(Features.fromMask(0x000003), {
        Features.featuresAreSpecified,
        Features.glasses,
      });
      expect(Features.fromMask(0x000300), {
        Features.rightEyePath,
        Features.darkGlasses,
      });
    });

    test('code-point lookups return null off the map', () {
      expect(Expression.from(0x0002), Expression.smileClosed);
      expect(Expression.from(0x0099), isNull);
      expect(EyeColor.from(0xFF), EyeColor.unknown);
      expect(HairColor.from(0x0A), isNull);
    });

    test('equality is field-wise incl. the feature set (Equatable parity)', () {
      FaceImageInfo make({Set<Features> features = const {}}) => FaceImageInfo(
        expression: Expression.neutral,
        eyeColor: EyeColor.blue,
        faceImageType: FaceImageType.fullFrontal,
        features: features,
        hairColor: HairColor.blonde,
        imageColorSpace: ImageColorSpace.rgb24,
        imageDataType: ImageDataType.jpeg,
        sourceType: SourceType.staticPhotoDigitalCam,
      );
      expect(make(), make());
      expect(
        make(features: {Features.glasses}),
        make(features: {Features.glasses}),
      );
      expect(make(), isNot(make(features: {Features.glasses})));
    });

    test('DocTypeEnum.desc mirrors the raw value', () {
      expect(DocTypeEnum.TD1.desc, 'TD1');
      expect(DocTypeEnum.OTHER.desc, 'OTHER');
    });
  });

  group('SOD / oracle', () {
    test('pkcs7CertificateData is the body bytes', () {
      final sod = SOD(_sodFile());
      expect(sod.pkcs7CertificateData, sod.body);
    });

    test('oracle register: poisoned across pairs until the next INTEGER', () {
      // Nonconformant hash-value list exercising the register machine:
      //   [2^64, h1]  -> poisons; entry skipped
      //   [   -, h2]  -> no INTEGER before it: still poisoned, skipped
      //   [   1, h3]  -> records DG1
      final content = TlvRecord.fromRecords(0x30, [
        TlvRecord.fromRecords(0x30, [
          TlvRecord(0x06, const [
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
          ]),
          TlvRecord(0x05, const []),
        ]),
        TlvRecord.fromRecords(0x30, [
          TlvRecord.fromRecords(0x30, [
            TlvRecord(0x02, const [
              0x01,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
            ]),
            TlvRecord(0x04, const [0x11]),
          ]),
          TlvRecord.fromRecords(0x30, [
            TlvRecord(0x04, const [0x22]),
          ]),
          TlvRecord.fromRecords(0x30, [
            TlvRecord(0x02, const [0x01]),
            TlvRecord(0x04, const [0x33]),
          ]),
        ]),
      ]).data;
      final (algo, hashes) = parseSODSignatureContent(content);
      expect(algo, 'SHA256');
      expect(hashes, {DataGroupId.DG1: '33'});
    });

    test('oracle: unparseable content throws InvalidASN1Value', () {
      expect(
        () => parseSODSignatureContent(const [0x30, 0x82, 0x00]),
        throwsA(isA<InvalidASN1Value>()),
      );
    });
  });

  group('ldsVersionInfo', () {
    // The corpus V1 / V0 LDSSecurityObjects (`sod.json`); the V1 one carries
    // ldsVersionInfo *third*, ahead of dataGroupHashValues.
    const v1Content =
        '3072020101300d06096086480165030402010500300e130430313037'
        '1306303430303030304e302502010104206ed8e9b3414d2dca5e97162c769420151f'
        '6067dabc4b40542a6d0eea318b6b2230250201020420208e836344369faa58c58c8c'
        '3360e50d2f0e604ad1321399a96be69ae787cd21';
    const v0Content =
        '3062020100300d06096086480165030402010500304e3025020101'
        '04206ed8e9b3414d2dca5e97162c769420151f6067dabc4b40542a6d0eea318b6b22'
        '30250201020420208e836344369faa58c58c8c3360e50d2f0e604ad1321399a96be6'
        '9ae787cd21';

    final sha256Alg = TlvRecord.fromRecords(0x30, [
      TlvRecord(0x06, const [
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01,
      ]),
      TlvRecord(0x05, const []),
    ]);
    final oneHash = TlvRecord.fromRecords(0x30, [
      TlvRecord.fromRecords(0x30, [
        TlvRecord(0x02, const [0x01]),
        TlvRecord(0x04, List<int>.filled(32, 0x11)),
      ]),
    ]);
    TlvRecord printable(String s) => TlvRecord(0x13, s.codeUnits);

    /// A V1 object with [versionInfo] as its fourth member.
    List<int> object(List<TlvRecord> versionInfo) =>
        TlvRecord.fromRecords(0x30, [
          TlvRecord(0x02, const [0x01]),
          sha256Alg,
          oneHash,
          TlvRecord.fromRecords(0x30, versionInfo),
        ]).data;

    test('corpus V1 object, member third -> 1.7 / 4.0.0', () {
      expect(parseLdsVersionInfo(hx(v1Content)), ('1.7', '4.0.0'));
    });

    test('corpus V0 object -> nulls', () {
      expect(parseLdsVersionInfo(hx(v0Content)), (null, null));
    });

    test('generator V1 object, member fourth (9303-10 order) -> values', () {
      final content = buildLdsSecurityObject(
        dataGroupHashes: {1: List<int>.filled(32, 0x11)},
        ldsVersionInfo: ('0108', '060000'),
      );
      final members = TlvRecord.sequenceOfRecords(
        TlvRecord.parse(content)!.value,
      )!;
      expect(members[0].value, [0x01], reason: 'version flips to v1');
      expect(members.length, 4);
      expect(members[3].tag, 0x30);
      expect(parseLdsVersionInfo(content), ('1.8', '6.0.0'));
    });

    test('a generator V0 object carries no member', () {
      final content = buildLdsSecurityObject(
        dataGroupHashes: {1: List<int>.filled(32, 0x11)},
      );
      expect(
        TlvRecord.sequenceOfRecords(TlvRecord.parse(content)!.value)!,
        hasLength(3),
      );
      expect(parseLdsVersionInfo(content), (null, null));
    });

    test('one or three PrintableString children is not the member', () {
      expect(parseLdsVersionInfo(object([printable('0107')])), (null, null));
      expect(
        parseLdsVersionInfo(
          object([printable('0107'), printable('040000'), printable('01')]),
        ),
        (null, null),
      );
    });

    test('a PrintableString in the algorithm parameters is not a version', () {
      final content = TlvRecord.fromRecords(0x30, [
        TlvRecord(0x02, const [0x00]),
        TlvRecord.fromRecords(0x30, [
          TlvRecord(0x06, const [
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
          ]),
          printable('0107'),
        ]),
        oneHash,
      ]).data;
      expect(parseLdsVersionInfo(content), (null, null));
      // The oracle is untouched by the same bytes.
      expect(parseSODSignatureContent(content).$1, 'SHA256');
    });

    test('non-digit or wrong-length strings -> nulls', () {
      expect(
        parseLdsVersionInfo(object([printable('01a7'), printable('040000')])),
        (null, null),
      );
      expect(
        parseLdsVersionInfo(object([printable('107'), printable('040000')])),
        (null, null),
      );
      expect(
        parseLdsVersionInfo(object([printable('0107'), printable('0400')])),
        (null, null),
      );
      expect(
        parseLdsVersionInfo(
          object([printable('0107'), printable('04000\u00e9')]),
        ),
        (null, null),
      );
    });

    test('never throws', () {
      for (final garbage in [
        const <int>[],
        const [0x30, 0x82, 0x00],
        const [0x30, 0x82, 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF],
        const [0x02, 0x01, 0x00],
        const [0x30, 0x00],
        const [0x30, 0x03, 0x30, 0x81, 0x05],
        List<int>.generate(64, (i) => (i * 37) & 0xFF),
      ]) {
        expect(parseLdsVersionInfo(garbage), (null, null), reason: '$garbage');
      }
    });

    test('checkDataGroupHashes carries the versions through', () {
      final result = checkDataGroupHashes(
        sod: SOD(hx(sodHex)),
        dataGroupsRead: {
          DataGroupId.DG1: DataGroupParser().parseDG(data: hx(dg1GoodHex)),
        },
      );
      expect(result.passed, isTrue);
      expect(result.ldsVersion, '1.7');
      expect(result.unicodeVersion, '4.0.0');
    });

    test('a hand-built result defaults both to null', () {
      const result = SODHashCheckResult(
        sodHashAlgorythm: 'SHA256',
        dataGroupHashes: {},
        errors: '',
      );
      expect(result.ldsVersion, isNull);
      expect(result.unicodeVersion, isNull);
    });
  });

  group('declaredDataGroups', () {
    final parser = DataGroupParser();
    DataGroup dg1() => parser.parseDG(data: hx(dg1GoodHex));
    DataGroup dg2() => parser.parseDG(data: hx(dg2Hex));

    /// A signed SOD attesting exactly [files] (id -> file bytes), in the
    /// map's order.
    SOD sodOver(Map<int, List<int>> files) => SOD(
      buildSignedSod(
        dataGroupFiles: files,
        certificates: const [],
        signerKey: dscRsaKey,
        signerIssuer: testDn(
          country: 'UT',
          organisation: 'Utopia',
          commonName: 'DS',
        ),
        signerSerial: 1,
      ),
    );

    final files = <int, List<int>>{
      1: hx(dg1GoodHex),
      2: hx(dg2Hex),
      3: const [0x63, 0x02, 0x00, 0x00],
      14: const [0x6E, 0x02, 0x00, 0x00],
      15: const [0x6F, 0x02, 0x00, 0x00],
    };

    test('corpus V1 SOD with only DG1 read: declared ⊇ read', () {
      final result = checkDataGroupHashes(
        sod: SOD(hx(sodHex)),
        dataGroupsRead: {DataGroupId.DG1: dg1()},
      );
      expect(result.declaredDataGroups, [DataGroupId.DG1, DataGroupId.DG2]);
      expect(result.dataGroupHashes.keys, [DataGroupId.DG1]);
      expect(result.passed, isTrue);
    });

    test('the SOD\'s whole list, DG-number order, whatever was read', () {
      final result = checkDataGroupHashes(
        sod: sodOver(files),
        dataGroupsRead: {DataGroupId.DG1: dg1(), DataGroupId.DG2: dg2()},
      );
      expect(result.passed, isTrue);
      expect(result.declaredDataGroups, [
        DataGroupId.DG1,
        DataGroupId.DG2,
        DataGroupId.DG3,
        DataGroupId.DG14,
        DataGroupId.DG15,
      ]);
      expect(result.dataGroupHashes.keys, [DataGroupId.DG1, DataGroupId.DG2]);
    });

    test('pairs emitted in reverse DER order are still sorted', () {
      final reversed = Map.fromEntries(files.entries.toList().reversed);
      final sod = sodOver(reversed);
      final (_, parsed) = parseSODSignatureContent(
        sod.getEncapsulatedContent(),
      );
      expect(
        parsed.keys.first,
        DataGroupId.DG15,
        reason: 'the DER really is reversed',
      );
      final result = checkDataGroupHashes(
        sod: sod,
        dataGroupsRead: {DataGroupId.DG1: dg1(), DataGroupId.DG2: dg2()},
      );
      expect(result.declaredDataGroups, [
        DataGroupId.DG1,
        DataGroupId.DG2,
        DataGroupId.DG3,
        DataGroupId.DG14,
        DataGroupId.DG15,
      ]);
    });

    test('a DG read but not declared is absent from the list', () {
      final result = checkDataGroupHashes(
        sod: sodOver({1: hx(dg1GoodHex)}),
        dataGroupsRead: {DataGroupId.DG1: dg1(), DataGroupId.DG2: dg2()},
      );
      expect(result.errors, 'DataGroup DG2 is missing!\n');
      expect(result.declaredDataGroups, [DataGroupId.DG1]);
    });

    test('ids 0 and 17 surface as COM and SOD, unfiltered', () {
      final result = checkDataGroupHashes(
        sod: sodOver({
          17: const [0x77, 0x00],
          1: hx(dg1GoodHex),
          0: const [0x60, 0x00],
        }),
        dataGroupsRead: {DataGroupId.DG1: dg1()},
      );
      expect(result.passed, isTrue);
      expect(result.declaredDataGroups, [
        DataGroupId.COM,
        DataGroupId.DG1,
        DataGroupId.SOD,
      ]);
    });

    test('a hand-built result defaults to an empty list', () {
      const result = SODHashCheckResult(
        sodHashAlgorythm: 'SHA256',
        dataGroupHashes: {},
        errors: '',
      );
      expect(result.declaredDataGroups, isEmpty);
    });
  });
}

/// Minimal DG2 wrapper: 75 { 7F61 { 02 01 01, 7F60 { A1 bht, tag record }}}.
List<int> _dg2File(List<int> record, {int bdbTag = 0x5F2E}) =>
    TlvRecord.fromRecords(0x75, [
      TlvRecord.fromRecords(0x7F61, [
        TlvRecord(0x02, const [0x01]),
        TlvRecord.fromRecords(0x7F60, [
          TlvRecord(0xA1, const [0x87, 0x02, 0x01, 0x01]),
          TlvRecord(bdbTag, record),
        ]),
      ]),
    ]).data;

/// A profile-minimal ISO/IEC 39794-5 `7F2E` value around [image]:
/// A1 { 65 { A0 version, A1 { 30 { 80 id, A1 { A0 { A0 { 80 image,
/// A1 { A0 { 80 jpeg } } } } } } } } }.
List<int> _iso39794(List<int> image) => TlvRecord.fromRecords(0xA1, [
  TlvRecord.fromRecords(0x65, [
    TlvRecord(0xA0, const [0x80, 0x01, 0x03, 0x81, 0x02, 0x07, 0xE3]),
    TlvRecord.fromRecords(0xA1, [
      TlvRecord.fromRecords(0x30, [
        TlvRecord(0x80, const [0x00]),
        TlvRecord.fromRecords(0xA1, [
          TlvRecord.fromRecords(0xA0, [
            TlvRecord.fromRecords(0xA0, [
              TlvRecord(0x80, image),
              TlvRecord(0xA1, const [0xA0, 0x03, 0x80, 0x01, 0x02]),
            ]),
          ]),
        ]),
      ]),
    ]),
  ]),
]).data;

/// Minimal well-formed SOD (dummy signerInfo; no real hashes needed here).
List<int> _sodFile() {
  final lds = TlvRecord.fromRecords(0x30, [
    TlvRecord(0x02, const [0x00]),
    TlvRecord.fromRecords(0x30, [
      TlvRecord(0x06, const [
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01,
      ]),
      TlvRecord(0x05, const []),
    ]),
    TlvRecord.fromRecords(0x30, [
      TlvRecord.fromRecords(0x30, [
        TlvRecord(0x02, const [0x01]),
        TlvRecord(0x04, List<int>.filled(32, 0x11)),
      ]),
    ]),
  ]);
  final signedData = TlvRecord.fromRecords(0x30, [
    TlvRecord(0x02, const [0x03]),
    TlvRecord.fromRecords(0x31, [
      TlvRecord.fromRecords(0x30, [
        TlvRecord(0x06, const [
          0x60,
          0x86,
          0x48,
          0x01,
          0x65,
          0x03,
          0x04,
          0x02,
          0x01,
        ]),
        TlvRecord(0x05, const []),
      ]),
    ]),
    TlvRecord.fromRecords(0x30, [
      TlvRecord(0x06, const [0x67, 0x81, 0x08, 0x01, 0x01, 0x01]),
      TlvRecord.fromRecords(0xA0, [TlvRecord(0x04, lds.data)]),
    ]),
    TlvRecord.fromRecords(0x31, [
      TlvRecord.fromRecords(0x30, [
        TlvRecord(0x02, const [0x01]),
        TlvRecord(0x04, const [0xAA]),
      ]),
    ]),
  ]);
  final contentInfo = TlvRecord.fromRecords(0x30, [
    TlvRecord(0x06, const [
      0x2A,
      0x86,
      0x48,
      0x86,
      0xF7,
      0x0D,
      0x01,
      0x07,
      0x02,
    ]),
    TlvRecord.fromRecords(0xA0, [signedData]),
  ]);
  return TlvRecord.fromRecords(0x77, [contentInfo]).data;
}
