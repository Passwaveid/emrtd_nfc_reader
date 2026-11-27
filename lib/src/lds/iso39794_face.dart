// The DER walk below is written from the ASN.1 modules of ISO/IEC 39794-1 and
// ISO/IEC 39794-5 (ed. 1, v1) and from the ICAO eMRTD application profile of
// them (ICAO TR "ISO/IEC 39794-5 Application Profile for eMRTDs" v1.00,
// Annex A). Those modules carry the following notice, reproduced as they
// require:
//
// Use of ISO/IEC copyright in this Schema is licensed for the purpose of
// developing, implementing, and using software based on this Schema, subject
// to the following conditions:
//
// * Software developed from this Schema must retain the Copyright Notice,
//   this list of conditions and the disclaimer below ("Disclaimer").
//
// * Neither the name or logo of ISO or of IEC, nor the names of specific
//   contributors, may be used to endorse or promote software derived from
//   this Schema without specific prior written permission.
//
// * The software developer shall attribute the Schema to ISO/IEC and
//   identify the ISO/IEC standard from which it is taken. Such attribution
//   (e.g., "This software makes use of the Schema from ISO/IEC 39794-5
//   within modifications permitted in the relevant ISO/IEC standard.
//   Please reproduce this note if possible."), may be placed in the
//   software itself or any other reasonable location.
//
// The Disclaimer is:
// THE SCHEMA ON WHICH THIS SOFTWARE IS BASED IS PROVIDED BY THE COPYRIGHT
// HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THE CODE COMPONENTS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// This software makes use of the Schema from ISO/IEC 39794-1 and ISO/IEC
// 39794-5 within modifications permitted in the relevant ISO/IEC standard.

/// ISO/IEC 39794-5 face records in DG2. No upstream analogue: upstream
/// reads ISO/IEC 19794-5 only.
///
/// Only the first representation is read, as the ICAO profile constrains DG2
/// (TR §3.2). The walk is strict on the path to the face image and lenient
/// everywhere else: a missing or undecodable element on the image path is
/// [InvalidDataPassed], a record that leaves no face image `DataGroup2` can
/// carry is [NotYetSupported], and a metadata element that is absent or
/// undecodable leaves its 19794-5 field at 0. Elements the walk does not
/// read are skipped, as the profile requires of a reader (TR §3.1). Every
/// level is split with [TlvRecord.sequenceOfRecords], so bytes that are not
/// TLV fail the level they sit in.
library;

import 'dart:typed_data';

import '../errors.dart';
import 'face_image_info.dart';
import 'tlv.dart';

/// The fields of a 39794-5 face record that `DataGroup2` carries, already
/// mapped to its 19794-5 code points. 0 means the record does not state the
/// value in that vocabulary.
final class Iso39794FaceRecord {
  const Iso39794FaceRecord({
    required this.representationCount,
    required this.image,
    required this.imageDataType,
    required this.imageWidth,
    required this.imageHeight,
    required this.imageColorSpace,
    required this.sourceType,
    required this.eyeColor,
    required this.hairColor,
    required this.featureMask,
    required this.expression,
  });

  final int representationCount;

  /// `representationData2D` verbatim: the face image, not yet checked.
  final Uint8List image;

  final int imageDataType;
  final int imageWidth;
  final int imageHeight;
  final int imageColorSpace;
  final int sourceType;
  final int eyeColor;
  final int hairColor;
  final int featureMask;
  final int expression;
}

const _malformed = InvalidDataPassed('DG2 ISO/IEC 39794-5 structure malformed');

NotYetSupported _outsideProfile(String what) =>
    NotYetSupported('ISO/IEC 39794-5 DG2 outside the ICAO profile: $what');

/// Parses the value of the `7F2E` biometric data template, `A1 { 65 ... }`
/// (P10 8th ed Table 2).
Iso39794FaceRecord parseIso39794FaceRecord(List<int> template) {
  final standardized = _require(_children(template), 0xA1);
  final faceImageDataBlock = _require(_children(standardized.value), 0x65);
  final representationBlocks = _require(
    _children(faceImageDataBlock.value),
    0xA1,
  );
  final representations = _children(representationBlocks.value);
  if (representations.isEmpty) {
    throw _outsideProfile('no representation');
  }
  final representation = representations.first;
  if (representation.tag != 0x30) {
    throw _malformed;
  }
  final representationFields = _children(representation.value);
  final block2d = _imageRepresentation2D(_require(representationFields, 0xA1));

  final block2dFields = _children(block2d.value);
  final image = _require(block2dFields, 0x80).value;
  final information = _children(_require(block2dFields, 0xA1).value);
  final imageDataType = _imageDataType(_require(information, 0xA0));
  if (image.isEmpty) {
    throw _outsideProfile('empty image');
  }

  final size = _childrenOrNull(_find(information, 0xA7));
  final device = _childrenOrNull(_find(block2dFields, 0xA2));
  final identity = _childrenOrNull(_find(representationFields, 0xA8));
  return Iso39794FaceRecord(
    representationCount: representations.length,
    image: image,
    imageDataType: imageDataType,
    imageWidth: _uint16(_find(size, 0x80)) ?? 0,
    imageHeight: _uint16(_find(size, 0x81)) ?? 0,
    imageColorSpace: _imageColorSpace[_code(_find(information, 0xA9))] ?? 0,
    sourceType: _sourceType[_code(_find(device, 0xA1))] ?? 0,
    eyeColor: _eyeColor[_code(_find(identity, 0xA1))] ?? 0,
    hairColor: _hairColor[_code(_find(identity, 0xA2))] ?? 0,
    featureMask: _featureMask(_childrenOrNull(_find(identity, 0xA4))),
    expression: _expression(_childrenOrNull(_find(identity, 0xA5))),
  );
}

/// `ImageRepresentation` -> `base` -> `imageRepresentation2DBlock`, each a
/// CHOICE and so explicitly tagged. An alternative the schema defines but
/// the profile excludes is outside the profile; a tag the schema does not
/// define is malformed.
TlvRecord _imageRepresentation2D(TlvRecord imageRepresentation) {
  final alternative = _first(imageRepresentation);
  final base = switch (alternative.tag) {
    0xA0 => _first(alternative),
    0xA1 => throw _outsideProfile('unknown representation'),
    _ => throw _malformed,
  };
  return switch (base.tag) {
    0xA0 => base,
    0xA1 => throw _outsideProfile('3D representation'),
    _ => throw _malformed,
  };
}

/// `ImageDataFormat`: `[0] code`, of which the profile allows jpeg (2),
/// jpeg2000Lossy (3) and jpeg2000Lossless (4), mapped to the 19794-5
/// image data type; `[1] extensionBlock` is a format the profile excludes.
int _imageDataType(TlvRecord imageDataFormat) {
  final alternative = _first(imageDataFormat);
  final code = switch (alternative.tag) {
    0x80 => _uint16(alternative) ?? (throw _malformed),
    0xA1 => throw _outsideProfile('image data format'),
    _ => throw _malformed,
  };
  return switch (code) {
    2 => ImageDataType.jpeg.value,
    3 || 4 => ImageDataType.jpeg2000.value,
    _ => throw _outsideProfile('image data format'),
  };
}

TlvRecord _first(TlvRecord constructed) {
  final children = _children(constructed.value);
  if (children.isEmpty) {
    throw _malformed;
  }
  return children.first;
}

List<TlvRecord> _children(List<int> value) =>
    TlvRecord.sequenceOfRecords(value) ?? (throw _malformed);

TlvRecord _require(List<TlvRecord> records, int tag) =>
    _find(records, tag) ?? (throw _malformed);

TlvRecord? _find(List<TlvRecord>? records, int tag) {
  for (final record in records ?? const <TlvRecord>[]) {
    if (record.tag == tag) {
      return record;
    }
  }
  return null;
}

List<TlvRecord>? _childrenOrNull(TlvRecord? record) =>
    record == null ? null : TlvRecord.sequenceOfRecords(record.value);

/// A non-negative DER INTEGER or ENUMERATED up to 0xFFFF, or null.
int? _uint16(TlvRecord? record) {
  final content = record?.value;
  if (content == null ||
      content.isEmpty ||
      content.length > 3 ||
      content[0] & 0x80 != 0) {
    return null;
  }
  var value = 0;
  for (final byte in content) {
    value = (value << 8) | byte;
  }
  return value <= 0xFFFF ? value : null;
}

/// An extensible enumerated type: `[0] code` (the base standard) or
/// `[1] { [0] fallback ... }` (the only form the ICAO profile allows, TR §4.1).
int? _code(TlvRecord? field) {
  final alternatives = _childrenOrNull(field);
  if (alternatives == null || alternatives.isEmpty) {
    return null;
  }
  final alternative = alternatives.first;
  return switch (alternative.tag) {
    0x80 => _uint16(alternative),
    0xA1 => _uint16(_find(_childrenOrNull(alternative), 0x80)),
    _ => null,
  };
}

bool _isTrue(TlvRecord? record) {
  final content = record?.value;
  return content != null && content.length == 1 && content[0] != 0;
}

/// `PropertiesBlock`: present means the features are specified; each TRUE
/// property with a 19794-5 flag sets it.
int _featureMask(List<TlvRecord>? properties) {
  if (properties == null) {
    return 0;
  }
  var mask = Features.featuresAreSpecified.value;
  for (final MapEntry(key: tag, value: feature) in _propertyFeatures.entries) {
    if (_isTrue(_find(properties, tag))) {
      mask |= feature.value;
    }
  }
  return mask;
}

/// `ExpressionBlock`: a 19794-5 expression only when exactly one flag is
/// TRUE and that flag has a 19794-5 code.
int _expression(List<TlvRecord>? flags) {
  if (flags == null) {
    return 0;
  }
  final trueFlags = [
    for (final tag in const [0x80, 0x81, 0x82, 0x83, 0x84, 0x85])
      if (_isTrue(_find(flags, tag))) tag,
  ];
  return trueFlags.length == 1
      ? _expressionCode[trueFlags.single]?.value ?? 0
      : 0;
}

final _imageColorSpace = <int?, int>{
  0: ImageColorSpace.unspecified.value,
  1: ImageColorSpace.other.value,
  2: ImageColorSpace.rgb24.value,
  3: ImageColorSpace.other.value,
  4: ImageColorSpace.yuv422.value,
  5: ImageColorSpace.gray8.value,
  6: ImageColorSpace.other.value,
};

final _sourceType = <int?, int>{
  0: SourceType.unknown.value,
  1: SourceType.staticPhotoUnknownSource.value,
  2: SourceType.staticPhotoDigitalCam.value,
  3: SourceType.staticPhotoScanner.value,
  4: SourceType.videoFrameUnknownSource.value,
  5: SourceType.videoFrameAnalogCam.value,
  6: SourceType.videoFrameDigitalCam.value,
};

final _eyeColor = <int?, int>{
  0: EyeColor.unknown.value,
  2: EyeColor.black.value,
  3: EyeColor.blue.value,
  4: EyeColor.brown.value,
  5: EyeColor.gray.value,
  6: EyeColor.green.value,
  8: EyeColor.multiColored.value,
  9: EyeColor.pink.value,
};

final _hairColor = <int?, int>{
  0: HairColor.unknown.value,
  2: HairColor.bald.value,
  3: HairColor.black.value,
  4: HairColor.blonde.value,
  5: HairColor.brown.value,
  6: HairColor.gray.value,
  7: HairColor.white.value,
  8: HairColor.red.value,
};

const _propertyFeatures = {
  0x80: Features.glasses,
  0x81: Features.moustache,
  0x82: Features.beard,
  0x83: Features.teethVisible,
  0x85: Features.mouthOpen,
  0x86: Features.leftEyePatch,
  0x87: Features.rightEyePath,
  0x88: Features.darkGlasses,
};

const _expressionCode = {
  0x80: Expression.neutral,
  0x82: Expression.raisedEyebrows,
  0x83: Expression.eyesLookingAway,
  0x84: Expression.squinting,
  0x85: Expression.frowning,
};
