import 'dart:isolate';
import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:j2k/j2k.dart';

/// Decoded face pixels, ready for `decodeImageFromPixels`.
class FacePixels {
  const FacePixels({
    required this.width,
    required this.height,
    required this.rgba,
  });

  final int width;
  final int height;

  /// Row-major RGBA8888.
  final Uint8List rgba;
}

/// Which decoder, if any, the DG2 image needs.
enum FaceDecodeKind { jpeg, jpeg2000, unknown }

class FaceDecode {
  const FaceDecode._(this.kind, this.bytes);

  const FaceDecode.jpeg(Uint8List bytes) : this._(FaceDecodeKind.jpeg, bytes);
  const FaceDecode.jpeg2000(Uint8List bytes)
    : this._(FaceDecodeKind.jpeg2000, bytes);
  const FaceDecode.unknown() : this._(FaceDecodeKind.unknown, null);

  final FaceDecodeKind kind;

  /// Null only for [FaceDecodeKind.unknown].
  final Uint8List? bytes;
}

/// Routes the DG2 image to a decoder by the format the package detected.
///
/// The package sniffs the header and stops; it never decodes. Calling
/// `Image.memory(result.faceImage)` unguarded therefore renders nothing on a
/// JPEG 2000 chip, which is most of them.
FaceDecode decideFace(Uint8List image, FaceImageFormat? format) =>
    switch (format) {
      FaceImageFormat.jpeg => FaceDecode.jpeg(image),
      FaceImageFormat.jp2 ||
      FaceImageFormat.jpeg2000Codestream => FaceDecode.jpeg2000(image),
      null => const FaceDecode.unknown(),
    };

/// A cap on what a chip can make this app allocate. A DG2 portrait is a few
/// hundred pixels on a side; four megapixels is generous and still refuses a
/// header that claims a gigantic image, before any buffer is allocated.
const Jpeg2000DecodeOptions faceDecodeOptions = Jpeg2000DecodeOptions(
  maxPixels: 4 * 1024 * 1024,
);

/// The decoder call, injectable so tests can drive failures that no fixture
/// can produce.
typedef Jpeg2000Decoder =
    Jpeg2000Image Function(Uint8List bytes, {Jpeg2000DecodeOptions options});

/// Decodes a JPEG 2000 face image, or returns null if the bytes cannot be
/// decoded.
///
/// Null is the whole failure surface for **bad input**: every
/// `Jpeg2000Exception` (truncated, corrupted, not JPEG 2000, an unsupported
/// feature, over the pixel budget) becomes a placeholder in the UI, because
/// there is nothing a user can do about any of them and the distinction does
/// not change the screen. Anything else is a bug in this app or in the codec
/// and is rethrown rather than silently swallowed.
///
/// Runs on whatever isolate calls it; the caller decides. The screen hops to
/// a background isolate because a full-size portrait is hundreds of
/// milliseconds of pure computation and would drop frames on the main one.
FacePixels? decodeJpeg2000Face(
  Uint8List bytes, {
  Jpeg2000DecodeOptions options = faceDecodeOptions,
  Jpeg2000Decoder decode = decodeJpeg2000,
}) {
  final Jpeg2000Image image;
  try {
    image = decode(bytes, options: options);
  } on Jpeg2000Exception {
    return null;
  }
  return FacePixels(
    width: image.width,
    height: image.height,
    rgba: rgbaFromJpeg2000(image),
  );
}

/// Expands any of j2k's channel layouts to RGBA8888.
///
/// Throws [UnsupportedError] on a 16-bit image: the decode above always asks
/// for 8-bit output, so 16 bits here means the caller passed options this
/// function was not written for, and silently truncating would produce a
/// plausible-looking wrong picture.
Uint8List rgbaFromJpeg2000(Jpeg2000Image image) {
  if (image.bitsPerSample != 8) {
    throw UnsupportedError(
      'rgbaFromJpeg2000 needs 8-bit samples, got ${image.bitsPerSample}',
    );
  }
  final pixelCount = image.width * image.height;
  final source = image.pixels;
  final stride = image.components;
  final rgba = Uint8List(pixelCount * 4);

  for (var i = 0; i < pixelCount; i++) {
    final s = i * stride;
    final d = i * 4;
    switch (image.format) {
      case Jpeg2000PixelFormat.gray:
        final v = source[s];
        rgba[d] = v;
        rgba[d + 1] = v;
        rgba[d + 2] = v;
        rgba[d + 3] = 0xFF;
      case Jpeg2000PixelFormat.grayAlpha:
        final v = source[s];
        rgba[d] = v;
        rgba[d + 1] = v;
        rgba[d + 2] = v;
        rgba[d + 3] = source[s + 1];
      case Jpeg2000PixelFormat.rgb:
        rgba[d] = source[s];
        rgba[d + 1] = source[s + 1];
        rgba[d + 2] = source[s + 2];
        rgba[d + 3] = 0xFF;
      case Jpeg2000PixelFormat.rgba:
        rgba[d] = source[s];
        rgba[d + 1] = source[s + 1];
        rgba[d + 2] = source[s + 2];
        rgba[d + 3] = source[s + 3];
      case Jpeg2000PixelFormat.multiComponent:
        // CMYK or multispectral: no colour interpretation is defined, so
        // show the first three channels rather than nothing.
        rgba[d] = source[s];
        rgba[d + 1] = stride > 1 ? source[s + 1] : source[s];
        rgba[d + 2] = stride > 2 ? source[s + 2] : source[s];
        rgba[d + 3] = 0xFF;
    }
  }
  return rgba;
}

/// Runs [decodeJpeg2000Face] on a background isolate.
///
/// Top-level on purpose: a closure written inside a `State` method captures
/// the enclosing instance, and everything reachable from a live widget tree
/// is unsendable. Taking only the bytes keeps the message payload to the
/// bytes.
Future<FacePixels?> decodeJpeg2000FaceInIsolate(Uint8List bytes) =>
    Isolate.run(() => decodeJpeg2000Face(bytes));
