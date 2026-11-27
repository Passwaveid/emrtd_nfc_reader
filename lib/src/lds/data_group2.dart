// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup2.swift @ 3bf5456 (2.3.2)
//   `getImage()` (UIKit) is dropped: image decoding/rendering is app-side;
//   the package hands over bytes + format.

/// DG2 (facial biometric) parsing: CBEFF walk + image extraction.
///
/// Kept as upstream has them: exactly one biometric template is parsed
/// (`nrImages` is read but never looped on, and the BHT `A1` value is
/// skipped unread), and image-format detection is strict: JFIF-only JPEG
/// prefix, exact JP2 signature, backwards last-`FF D9` end scan, JP2 box
/// walk start-through-`jp2c`.
///
/// Unlike upstream: the `FAC\x00` header check is strict, where upstream's
/// `&&`-for-`||` accepts any record with one matching byte; a truncated
/// CBEFF walk throws [InvalidDataPassed] where upstream slice-crashes;
/// hostile JP2 XLBox 64-bit lengths are range-checked and throw
/// [UnknownImageFormat] where upstream traps; the detected format is
/// surfaced as [DataGroup2.faceImageFormat], where upstream computes the
/// branch in a dead `private` enum and exposes nothing; and an ISO/IEC
/// 39794-5 envelope (P10 8th ed Table 2: DO `7F2E` wrapping
/// `A1 { 65 ... }`) is read by [DataGroup2.parseISO39794_5], where upstream
/// has no 39794 support.
///
/// The CBEFF `imageDataType` field and the header-detected [faceImageFormat]
/// are independent and can disagree on nonconformant files; a comparison
/// with another reader must diff on the *detected* format.
library;

import 'dart:typed_data';

import '../errors.dart';
import '../utils.dart';
import 'data_group.dart';
import 'data_group_id.dart';
import 'iso39794_face.dart';
import 'tlv.dart';

/// Upstream's dead `private enum FaceImageFormat`, realized as public API:
/// callers need the detected branch.
///
/// The name is DG2's, but the enum is the package's one image-format
/// vocabulary: [sniffImageFormat] reuses it for the DG7 signature
/// image and the DG12 front/rear images. Keeping the shipped name is an API-
/// stability call over aesthetics.
enum FaceImageFormat { jpeg, jp2, jpeg2000Codestream }

/// The biometric data standard a DG2 face record is encoded in (P10 8th ed
/// §4.5.6 Table 1). Dart-only: upstream reads ISO/IEC 19794-5 only.
enum FaceRecordEncoding { iso19794, iso39794 }

/// The three header prefixes upstream's `extractFaceImageData` dispatches on,
/// at file level so [sniffImageFormat] and [DataGroup2.extractFaceImageData]
/// share one copy. Values verbatim.
const _jpegHeader = [
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, //
];
const _jpeg2000BitmapHeader = [
  0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a, //
];
const _jpeg2000CodestreamBitmapHeader = [0xff, 0x4f, 0xff, 0x51];

/// Prefix-only image-format sniff over the DG2 header constants:
/// the same three tests [DataGroup2.extractFaceImageData] makes, in the same
/// order, **without** the end-scan/box-walk extraction that follows them.
///
/// Returns `null` on no match and **never throws**: DG7/DG12 images are
/// carried verbatim by their parsers (upstream does no format validation at
/// all there), so an unrecognized image must not fail a parse. That is the
/// deliberate difference from DG2's throwing extraction.
///
/// Inherits DG2's strictness: the JPEG test is the 10-byte JFIF-only
/// prefix, so an Exif JPEG (`FF D8 FF E1`) sniffs as `null`, which is also
/// what P10 §4.7.7's "ISO/IEC 10918 (JFIF option)" wording describes.
FaceImageFormat? sniffImageFormat(List<int> image) {
  if (_startsWith(image, _jpegHeader)) {
    return FaceImageFormat.jpeg;
  }
  if (_startsWith(image, _jpeg2000CodestreamBitmapHeader)) {
    return FaceImageFormat.jpeg2000Codestream;
  }
  if (_startsWith(image, _jpeg2000BitmapHeader)) {
    return FaceImageFormat.jp2;
  }
  return null;
}

bool _startsWith(List<int> data, List<int> prefix) {
  if (data.length < prefix.length) {
    return false;
  }
  for (var i = 0; i < prefix.length; i++) {
    if (data[i] != prefix[i]) {
      return false;
    }
  }
  return true;
}

/// Upstream `DataGroup2`.
class DataGroup2 extends DataGroup {
  DataGroup2(super.data);

  int nrImages = 0;
  int versionNumber = 0;
  int lengthOfRecord = 0;
  int numberOfFacialImages = 0;
  int facialRecordDataLength = 0;
  int nrFeaturePoints = 0;
  int gender = 0;
  int eyeColor = 0;
  int hairColor = 0;
  int featureMask = 0;
  int expression = 0;
  int poseAngle = 0;
  int poseAngleUncertainty = 0;
  int faceImageType = 0;

  /// CBEFF-declared image type (0 = JPEG, 1 = JPEG2000), independent of
  /// the header-detected [faceImageFormat]; they can disagree.
  int imageDataType = 0;
  int imageWidth = 0;
  int imageHeight = 0;
  int imageColorSpace = 0;
  int sourceType = 0;
  int deviceType = 0;
  int quality = 0;
  Uint8List imageData = Uint8List(0);

  late FaceImageFormat _faceImageFormat;
  late FaceRecordEncoding _encoding;

  /// The header-detected image format (a Dart-only surface).
  /// Always set once construction succeeds: every parse path either
  /// detects a format or throws.
  FaceImageFormat get faceImageFormat => _faceImageFormat;

  /// Which standard the face record is encoded in. For
  /// [FaceRecordEncoding.iso39794] the 19794-5 fields above carry what
  /// [parseISO39794_5] maps into them, and a field it does not map is 0 even
  /// where 0 is a 19794-5 code point.
  FaceRecordEncoding get encoding => _encoding;

  @override
  DataGroupId get datagroupType => DataGroupId.DG2;

  @override
  void parse(List<int> data) {
    var tag = getNextTag();
    verifyTag(tag, equals: 0x7F61);
    getNextLength();

    // Tag should be 0x02 (upstream comment).
    tag = getNextTag();
    verifyTag(tag, equals: 0x02);
    final nrImagesValue = getNextValue();
    if (nrImagesValue.isEmpty) {
      throw const InvalidDataPassed(
        'DG2 CBEFF structure truncated',
      ); // upstream: [0] crash
    }
    nrImages = nrImagesValue[0]; // read but never looped on, as upstream

    // Next tag is 0x7F60 (upstream comment).
    tag = getNextTag();
    verifyTag(tag, equals: 0x7F60);
    getNextLength();

    // Next tag is 0xA1 (Biometric Header Template) - don't care about this
    // (upstream comment; its REQUIRED 87/88 DOs are skipped unread).
    tag = getNextTag();
    verifyTag(tag, equals: 0xA1);
    getNextValue();

    // Now we get to the good stuff - next tag is either 5F2E or 7F2E
    // (upstream comment).
    tag = getNextTag();
    verifyTagOneOf(tag, oneOf: const [0x5F2E, 0x7F2E]);
    final value = getNextValue();

    parseISO19794_5(value);
  }

  /// Upstream `parseISO19794_5(data:)`: the fixed-offset facial-record
  /// walk, hardened against truncation. An ISO/IEC 39794-5 envelope goes to
  /// [parseISO39794_5] instead.
  // ignore: non_constant_identifier_names
  void parseISO19794_5(List<int> data) {
    var offset = 0;

    // Every fixed-offset read is bounds-checked (upstream: slice crash on
    // truncated records).
    List<int> read(int count) {
      if (offset + count > data.length) {
        throw const InvalidDataPassed('DG2 CBEFF structure truncated');
      }
      final slice = data.sublist(offset, offset + count);
      offset += count;
      return slice;
    }

    // Validate header - 'F', 'A' 'C' 0x00 - 0x46414300 (upstream comment).
    // Upstream's `&&` chain passes any record with ONE matching byte; the
    // port requires all four, a fix.
    if (data.length < 4) {
      throw const InvalidDataPassed('DG2 CBEFF structure truncated');
    }
    if (!(data[0] == 0x46 &&
        data[1] == 0x41 &&
        data[2] == 0x43 &&
        data[3] == 0x00)) {
      if (_isIso39794Envelope(data)) {
        parseISO39794_5(data);
        return;
      }
      throw InvalidResponse(datagroupType, 0x46, data[0]);
    }
    _encoding = FaceRecordEncoding.iso19794;
    offset = 4;

    versionNumber = binToInt(read(4));
    lengthOfRecord = binToInt(read(4));
    numberOfFacialImages = binToInt(read(2));

    facialRecordDataLength = binToInt(read(4));

    nrFeaturePoints = binToInt(read(2));
    gender = binToInt(read(1));
    eyeColor = binToInt(read(1));
    hairColor = binToInt(read(1));
    featureMask = binToInt(read(3));
    expression = binToInt(read(2));
    poseAngle = binToInt(read(3));
    poseAngleUncertainty = binToInt(read(3));

    // Features (not handled). There shouldn't be any but if for some reason
    // there were, then we are going to skip over them
    // The Feature block is 8 bytes (upstream comment; overrun surfaces at
    // the next read's bounds check).
    offset += nrFeaturePoints * 8;

    faceImageType = binToInt(read(1));
    imageDataType = binToInt(read(1));
    imageWidth = binToInt(read(2));
    imageHeight = binToInt(read(2));
    imageColorSpace = binToInt(read(1));
    sourceType = binToInt(read(1));
    deviceType = binToInt(read(2));
    quality = binToInt(read(2));

    // Make sure that the image data at least has a valid header
    // Either JPG or JPEG2000 (upstream comment).
    imageData = extractFaceImageData(data, offset);
  }

  /// The ISO/IEC 39794-5 face record (Dart-only): the fields
  /// `parseIso39794FaceRecord` maps, and the image through the same
  /// [extractFaceImageData] as the 19794-5 record. Every other 19794-5 field
  /// stays 0.
  // ignore: non_constant_identifier_names
  void parseISO39794_5(List<int> data) {
    final record = parseIso39794FaceRecord(data);
    numberOfFacialImages = record.representationCount;
    eyeColor = record.eyeColor;
    hairColor = record.hairColor;
    featureMask = record.featureMask;
    expression = record.expression;
    imageDataType = record.imageDataType;
    imageWidth = record.imageWidth;
    imageHeight = record.imageHeight;
    imageColorSpace = record.imageColorSpace;
    sourceType = record.sourceType;
    imageData = extractFaceImageData(record.image, 0);
    _encoding = FaceRecordEncoding.iso39794;
  }

  /// P10 8th ed Table 2: under a 39794-series `7F2E` the value is an `A1`
  /// DO whose first nested DO is `65` (the ISO/IEC 39794-5
  /// FaceImageDataBlock): the detection that dispatches to
  /// [parseISO39794_5].
  static bool _isIso39794Envelope(List<int> data) {
    final outer = TlvRecord.parse(data);
    if (outer == null || outer.tag != 0xA1) {
      return false;
    }
    final inner = TlvRecord.parse(outer.value);
    return inner != null && inner.tag == 0x65;
  }

  /// Upstream `extractFaceImageData(from:offset:)`: dispatch on header
  /// bytes of the post-walk remainder, in upstream's order. Records the
  /// detected branch in [faceImageFormat].
  Uint8List extractFaceImageData(List<int> data, int offset) {
    final remaining = data.sublist(offset);

    // Check for JPEG Image (upstream comment). As upstream, the 10-byte
    // JFIF-only prefix; an Exif JPEG (FF D8 FF E1) is UnknownImageFormat; do
    // not "improve" this: the strictness is upstream's, kept on purpose.
    if (_startsWith(remaining, _jpegHeader)) {
      final end = findJPEGEnd(remaining);
      if (end == null) {
        throw const UnknownImageFormat();
      }
      _faceImageFormat = FaceImageFormat.jpeg;
      return Uint8List.fromList(remaining.sublist(0, end));
    }

    // Check for jpeg2000CodestreamBitmapHeader (upstream comment).
    if (_startsWith(remaining, _jpeg2000CodestreamBitmapHeader)) {
      final end = findJPEG2000CodestreamEnd(remaining);
      if (end == null) {
        throw const UnknownImageFormat();
      }
      _faceImageFormat = FaceImageFormat.jpeg2000Codestream;
      return Uint8List.fromList(remaining.sublist(0, end));
    }

    // Check for JPEG2000Bitmap (upstream comment).
    if (_startsWith(remaining, _jpeg2000BitmapHeader)) {
      final maxEnd = data.length;
      _faceImageFormat = FaceImageFormat.jp2;
      return extractJP2BoxData(data, offset, maxEnd);
    }

    throw const UnknownImageFormat();
  }

  /// Upstream `extractJP2BoxData(from:offset:maxEnd:)`: box walk from
  /// [offset] until the `jp2c` codestream box is consumed; everything from
  /// the JP2 start through the end of `jp2c` is returned, trailing boxes
  /// dropped, as upstream.
  ///
  /// The XLBox 64-bit length is range-checked against the enclosing buffer
  /// *before* any narrowing or offset arithmetic (Dart ints wrap rather than
  /// trap, so the guard is explicit) -> [UnknownImageFormat], where upstream
  /// traps on the overflow.
  Uint8List extractJP2BoxData(List<int> data, int offset, int maxEnd) {
    var p = offset;

    while (p + 8 <= maxEnd) {
      final boxStart = p;
      final length = binToInt(data.sublist(p, p + 4));
      p += 4;

      final boxType = data.sublist(p, p + 4);
      p += 4;

      final int boxEnd;

      if (length == 0) {
        // Box extends to end of containing data (upstream comment).
        boxEnd = maxEnd;
      } else if (length == 1) {
        // XLBox: 64-bit box length (upstream comment).
        if (p + 8 > maxEnd) {
          throw const UnknownImageFormat();
        }

        final largeLength = _binToInt64(data.sublist(p, p + 8));
        p += 8;

        if (largeLength < BigInt.from(16)) {
          throw const UnknownImageFormat();
        }
        // Bounds first, narrowing after (upstream: Int() trap).
        if (largeLength > BigInt.from(maxEnd - boxStart)) {
          throw const UnknownImageFormat();
        }

        boxEnd = boxStart + largeLength.toInt();
      } else {
        if (length < 8) {
          throw const UnknownImageFormat();
        }

        boxEnd = boxStart + length;
      }

      if (boxEnd > maxEnd) {
        throw const UnknownImageFormat();
      }

      p = boxEnd;

      // jp2c box: this is the codestream box.
      // Once we have consumed it, the JP2 image is complete.
      // (upstream comment)
      if (boxType[0] == 0x6A &&
          boxType[1] == 0x70 &&
          boxType[2] == 0x32 &&
          boxType[3] == 0x63) {
        return Uint8List.fromList(data.sublist(offset, boxEnd));
      }
    }

    throw const UnknownImageFormat();
  }

  /// Upstream `findJPEGEnd(in:)`: scans *backwards* for the last `FF D9`
  /// (trailing chip padding trimmed; data after the true EOI shifts the
  /// cut).
  int? findJPEGEnd(List<int> data) {
    if (data.length < 2) {
      return null;
    }

    // Go backwards to find end of file marker (upstream comment).
    for (var i = data.length - 2; i >= 0; i--) {
      if (data[i] == 0xFF && data[i + 1] == 0xD9) {
        return i + 2;
      }
    }

    return null;
  }

  /// Upstream `findJPEG2000CodestreamEnd(in:)`: the JPEG2000 codestream
  /// EOC marker shares the JPEG EOI bytes.
  int? findJPEG2000CodestreamEnd(List<int> data) {
    return findJPEGEnd(data);
  }

  /// Upstream `binToInt64(_:)`, as [BigInt]: Dart has no unsigned 64-bit
  /// int, and the XLBox bounds check needs the unnarrowed value.
  static BigInt _binToInt64(List<int> slice) {
    var value = BigInt.zero;
    for (final byte in slice) {
      value = (value << 8) | BigInt.from(byte);
    }
    return value;
  }
}
