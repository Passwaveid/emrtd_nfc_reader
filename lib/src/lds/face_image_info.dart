// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/Models/FaceImageInfo.swift @ 3bf5456 (2.3.2)
//   Upstream's one-file `Models/` subdirectory is flattened into `lds/`;
//   Swift's nested enums become top-level Dart enums.

/// `FaceImageInfo`: the ISO/IEC 19794-5 facial-record code points as
/// enums, decoded from a parsed [DataGroup2].
///
/// Data structure for storing facial image data. This represents
/// a facial record data block as specified in Section 5.5, 5.6,
/// and 5.7 of ISO/IEC FCD 19794-5 (2004-03-22, AKA Annex D).
/// Integration based on JMRTD's FaceImageInfo (upstream comment).
///
/// Unlike upstream, `featureMask` is read as the bitmask it is, decoded by
/// [Features.fromMask] to the *set* of flags; upstream's exact-single-value
/// enum lookup yields nil for any multi-bit mask. Enum member names are
/// verbatim, including the [Features.rightEyePath] typo.
library;

import 'data_group2.dart';

/// Expression code based on Section 5.5.7 of ISO 19794-5.
enum Expression {
  unspecified(0x0000),
  neutral(0x0001),
  smileClosed(0x0002),
  smileOpen(0x0003),
  raisedEyebrows(0x0004),
  eyesLookingAway(0x0005),
  squinting(0x0006),
  frowning(0x0007);

  const Expression(this.value);

  /// Upstream raw value.
  final int value;

  /// Upstream `from(_:)`: nil for unknown codes.
  static Expression? from(int code) => _lookup(values, (e) => e.value, code);
}

/// Eye color code based on Section 5.5.4 of ISO 19794-5.
enum EyeColor {
  unspecified(0x00),
  black(0x01),
  blue(0x02),
  brown(0x03),
  gray(0x04),
  green(0x05),
  multiColored(0x06),
  pink(0x07),
  unknown(0xFF);

  const EyeColor(this.value);

  final int value;

  static EyeColor? from(int code) => _lookup(values, (e) => e.value, code);
}

/// Face image type code based on Section 5.7.1 of ISO 19794-5.
enum FaceImageType {
  basic(0x00),
  fullFrontal(0x01),
  tokenFrontal(0x02);

  const FaceImageType(this.value);

  final int value;

  static FaceImageType? from(int code) => _lookup(values, (e) => e.value, code);
}

/// Feature flags meaning based on Section 5.5.6 of ISO 19794-5.
///
/// A bitmask, not a code point; see [fromMask].
enum Features {
  featuresAreSpecified(0x000001),
  glasses(0x000002),
  moustache(0x000004),
  beard(0x000008),
  teethVisible(0x000010),
  blink(0x000020),
  mouthOpen(0x000040),
  leftEyePatch(0x000080),
  rightEyePath(0x000100), // upstream typo kept
  darkGlasses(0x000200),
  distortingMedicalCondition(0x000400);

  const Features(this.value);

  final int value;

  /// Decodes the bitmask to the set of set flags, fixing upstream: its
  /// `Features.from(dg2.featureMask)` maps only exact single-flag values (any
  /// multi-bit mask -> nil); split conformance cases pin both behaviors.
  static Set<Features> fromMask(int mask) =>
      values.where((f) => mask & f.value != 0).toSet();
}

/// Hair color code based on Section 5.5.5 of ISO 19794-5.
enum HairColor {
  unspecified(0x00),
  bald(0x01),
  black(0x02),
  blonde(0x03),
  brown(0x04),
  gray(0x05),
  white(0x06),
  red(0x07),
  green(0x08),
  blue(0x09),
  unknown(0xFF);

  const HairColor(this.value);

  final int value;

  static HairColor? from(int code) => _lookup(values, (e) => e.value, code);
}

/// Color space code based on Section 5.7.4 of ISO 19794-5.
enum ImageColorSpace {
  unspecified(0x00),
  rgb24(0x01),
  yuv422(0x02),
  gray8(0x03),
  other(0x04);

  const ImageColorSpace(this.value);

  final int value;

  static ImageColorSpace? from(int code) =>
      _lookup(values, (e) => e.value, code);
}

/// Image data type code based on Section 5.7.2 of ISO 19794-5.
enum ImageDataType {
  jpeg(0x00),
  jpeg2000(0x01);

  const ImageDataType(this.value);

  final int value;

  static ImageDataType? from(int code) => _lookup(values, (e) => e.value, code);
}

/// Source type based on Section 5.7.6 of ISO 19794-5.
enum SourceType {
  unspecified(0x00),
  staticPhotoUnknownSource(0x01),
  staticPhotoDigitalCam(0x02),
  staticPhotoScanner(0x03),
  videoFrameUnknownSource(0x04),
  videoFrameAnalogCam(0x05),
  videoFrameDigitalCam(0x06),
  unknown(0x07);

  const SourceType(this.value);

  final int value;

  static SourceType? from(int code) => _lookup(values, (e) => e.value, code);
}

T? _lookup<T>(List<T> values, int Function(T) valueOf, int code) {
  for (final v in values) {
    if (valueOf(v) == code) {
      return v;
    }
  }
  return null;
}

/// Upstream `FaceImageInfo` (Equatable).
class FaceImageInfo {
  const FaceImageInfo({
    required this.expression,
    required this.eyeColor,
    required this.faceImageType,
    required this.features,
    required this.hairColor,
    required this.imageColorSpace,
    required this.imageDataType,
    required this.sourceType,
  });

  /// Upstream `from(dg2:)`.
  factory FaceImageInfo.from(DataGroup2 dg2) => FaceImageInfo(
    expression: Expression.from(dg2.expression),
    eyeColor: EyeColor.from(dg2.eyeColor),
    // A 39794-5 face image kind has no 19794-5 face image type,
    // and the 0 left in its place would read as `basic`.
    faceImageType: dg2.encoding == FaceRecordEncoding.iso39794
        ? null
        : FaceImageType.from(dg2.faceImageType),
    features: Features.fromMask(dg2.featureMask),
    hairColor: HairColor.from(dg2.hairColor),
    imageColorSpace: ImageColorSpace.from(dg2.imageColorSpace),
    imageDataType: ImageDataType.from(dg2.imageDataType),
    sourceType: SourceType.from(dg2.sourceType),
  );

  final Expression? expression;
  final EyeColor? eyeColor;
  final FaceImageType? faceImageType;

  /// The decoded flag set: upstream's `Features?` single-value field,
  /// corrected to hold every flag the mask sets.
  final Set<Features> features;

  final HairColor? hairColor;
  final ImageColorSpace? imageColorSpace;
  final ImageDataType? imageDataType;
  final SourceType? sourceType;

  @override
  bool operator ==(Object other) =>
      other is FaceImageInfo &&
      expression == other.expression &&
      eyeColor == other.eyeColor &&
      faceImageType == other.faceImageType &&
      features.length == other.features.length &&
      features.containsAll(other.features) &&
      hairColor == other.hairColor &&
      imageColorSpace == other.imageColorSpace &&
      imageDataType == other.imageDataType &&
      sourceType == other.sourceType;

  @override
  int get hashCode => Object.hash(
    expression,
    eyeColor,
    faceImageType,
    Object.hashAllUnordered(features),
    hairColor,
    imageColorSpace,
    imageDataType,
    sourceType,
  );
}
