import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/emrtd_core.dart';
import 'package:emrtd_core_example/face_pixels.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:j2k/j2k.dart';

Uint8List fixture(String name) => File('test/fixtures/$name').readAsBytesSync();

Uint8List concat(Uint8List a, List<int> b) => Uint8List.fromList([...a, ...b]);

Jpeg2000Image image(
  Jpeg2000PixelFormat format,
  int width,
  int height,
  int components,
  List<int> pixels, {
  int bitsPerSample = 8,
}) => Jpeg2000Image(
  width: width,
  height: height,
  components: components,
  colorComponents: components,
  hasAlpha:
      format == Jpeg2000PixelFormat.rgba ||
      format == Jpeg2000PixelFormat.grayAlpha,
  alphaIsPremultiplied: false,
  sourceBitsPerComponent: List.filled(components, bitsPerSample),
  bitsPerSample: bitsPerSample,
  pixels: bitsPerSample == 8
      ? Uint8List.fromList(pixels)
      : Uint8List.fromList(pixels),
  format: format,
);

void main() {
  group('rgbaFromJpeg2000', () {
    test('gray expands to R=G=B with opaque alpha', () {
      final rgba = rgbaFromJpeg2000(
        image(Jpeg2000PixelFormat.gray, 2, 2, 1, [10, 20, 30, 40]),
      );
      expect(rgba.length, 16);
      expect(rgba.sublist(0, 4), [10, 10, 10, 0xFF]);
      expect(rgba.sublist(12, 16), [40, 40, 40, 0xFF]);
    });

    test('grayAlpha takes alpha from the second channel', () {
      final rgba = rgbaFromJpeg2000(
        image(Jpeg2000PixelFormat.grayAlpha, 2, 2, 2, [
          10, 1, 20, 2, //
          30, 3, 40, 4,
        ]),
      );
      expect(rgba.sublist(0, 4), [10, 10, 10, 1]);
      expect(rgba.sublist(4, 8), [20, 20, 20, 2]);
    });

    test('rgb gets an opaque alpha', () {
      final rgba = rgbaFromJpeg2000(
        image(Jpeg2000PixelFormat.rgb, 2, 2, 3, [
          1, 2, 3, 4, 5, 6, //
          7, 8, 9, 10, 11, 12,
        ]),
      );
      expect(rgba.sublist(0, 4), [1, 2, 3, 0xFF]);
      expect(rgba.sublist(4, 8), [4, 5, 6, 0xFF]);
    });

    test('rgba passes through unchanged', () {
      final pixels = List.generate(16, (i) => i);
      final rgba = rgbaFromJpeg2000(
        image(Jpeg2000PixelFormat.rgba, 2, 2, 4, pixels),
      );
      expect(rgba, pixels);
    });

    test('multiComponent shows the first three channels', () {
      final rgba = rgbaFromJpeg2000(
        image(Jpeg2000PixelFormat.multiComponent, 1, 1, 5, [9, 8, 7, 6, 5]),
      );
      expect(rgba, [9, 8, 7, 0xFF]);
    });

    test('a zero-sized image yields empty RGBA rather than throwing', () {
      expect(
        rgbaFromJpeg2000(image(Jpeg2000PixelFormat.gray, 0, 0, 1, [])),
        isEmpty,
      );
    });

    test('16-bit samples are refused rather than silently truncated', () {
      expect(
        () => rgbaFromJpeg2000(
          image(Jpeg2000PixelFormat.gray, 1, 1, 1, [0, 0], bitsPerSample: 16),
        ),
        throwsUnsupportedError,
      );
    });
  });

  group('decodeJpeg2000Face', () {
    test('decodes the boxed JP2 fixture', () {
      final face = decodeJpeg2000Face(fixture('synthetic_face.jp2'))!;
      expect(face.width, 96);
      expect(face.height, 128);
      expect(face.rgba.length, 96 * 128 * 4);
    });

    test('decodes the bare codestream fixture', () {
      final face = decodeJpeg2000Face(fixture('synthetic_face.j2k'))!;
      expect(face.width, 96);
      expect(face.height, 128);
    });

    // A chip's DG2 image field is often longer than the codestream inside it.
    test('tolerates 16 trailing zero bytes after a JP2 container', () {
      expect(
        decodeJpeg2000Face(
          concat(fixture('synthetic_face.jp2'), List.filled(16, 0)),
        ),
        isNotNull,
      );
    });

    for (final n in [1, 16, 256]) {
      test('tolerates $n trailing zero bytes after a bare codestream', () {
        expect(
          decodeJpeg2000Face(
            concat(fixture('synthetic_face.j2k'), List.filled(n, 0)),
          ),
          isNotNull,
        );
      });
    }

    test('tolerates 16 trailing 0xFF bytes after a bare codestream', () {
      expect(
        decodeJpeg2000Face(
          concat(fixture('synthetic_face.j2k'), List.filled(16, 0xFF)),
        ),
        isNotNull,
      );
    });

    test('a JP2 container with 1 trailing byte fails to decode', () {
      // Pinned deliberately: 1-7 trailing bytes look like the start of a
      // truncated box header and j2k 0.9.0 refuses the file, while 16 or more
      // are tolerated. If a j2k upgrade fixes this, THIS TEST FAILING is the
      // intended signal; update the pin, do not delete it.
      expect(
        decodeJpeg2000Face(concat(fixture('synthetic_face.jp2'), [0])),
        isNull,
      );
    });

    test('a truncated codestream yields null', () {
      final full = fixture('synthetic_face.j2k');
      expect(decodeJpeg2000Face(full.sublist(0, full.length ~/ 2)), isNull);
    });

    test('empty input yields null', () {
      expect(decodeJpeg2000Face(Uint8List(0)), isNull);
    });

    test('noise yields null', () {
      final noise = Uint8List.fromList(
        List.generate(1024, (i) => (i * 37) % 256),
      );
      expect(decodeJpeg2000Face(noise), isNull);
    });

    test('a JPEG stub yields null', () {
      final jpeg = Uint8List.fromList([
        0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, //
        0x46, 0x49, 0x46, 0x00, 0xff, 0xd9,
      ]);
      expect(decodeJpeg2000Face(jpeg), isNull);
    });

    test('a pixel budget the image exceeds yields null', () {
      expect(
        decodeJpeg2000Face(
          fixture('synthetic_face.jp2'),
          options: const Jpeg2000DecodeOptions(maxPixels: 128),
        ),
        isNull,
      );
    });

    test('a non-Jpeg2000 error from the decoder is rethrown', () {
      // Only failures that are properties of the bytes become a placeholder.
      // A bug must not be swallowed into "photo could not be decoded".
      expect(
        () => decodeJpeg2000Face(
          fixture('synthetic_face.jp2'),
          decode: (bytes, {options = const Jpeg2000DecodeOptions()}) =>
              throw StateError('bug'),
        ),
        throwsStateError,
      );
    });
  });

  group('decideFace', () {
    final bytes = Uint8List.fromList([1, 2, 3]);

    test('jpeg routes to the JPEG branch', () {
      expect(decideFace(bytes, FaceImageFormat.jpeg).kind, FaceDecodeKind.jpeg);
    });

    test('jp2 routes to the JPEG 2000 branch', () {
      expect(
        decideFace(bytes, FaceImageFormat.jp2).kind,
        FaceDecodeKind.jpeg2000,
      );
    });

    test('a bare codestream routes to the JPEG 2000 branch', () {
      expect(
        decideFace(bytes, FaceImageFormat.jpeg2000Codestream).kind,
        FaceDecodeKind.jpeg2000,
      );
    });

    test('an undetected format routes to the placeholder', () {
      expect(decideFace(bytes, null).kind, FaceDecodeKind.unknown);
      expect(decideFace(bytes, null).bytes, isNull);
    });
  });
}
