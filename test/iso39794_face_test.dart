/// `parseIso39794FaceRecord`: the walk over the `7F2E` value, its strict
/// image path, its lenient metadata and the 19794-5 mapping tables. Inputs
/// are built with [TlvRecord]; the schema-encoded shapes are the
/// python-oracle rows in `conformance/vectors/dg2.json`.
library;

import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/iso39794_face.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:flutter_test/flutter_test.dart';

const _jpeg = [
  0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0xff, 0xd9, //
];
const _version = [0xA0, 0x07, 0x80, 0x01, 0x03, 0x81, 0x02, 0x07, 0xE3];

List<int> _tlv(int tag, [List<int> value = const []]) =>
    TlvRecord(tag, value).data;

List<int> _cat(List<List<int>> parts) => [for (final p in parts) ...p];

/// `[n] { [0] code }`: the base standard's form of an extensible enum.
List<int> _codeForm(int tag, int code) => _tlv(tag, _tlv(0x80, [code]));

/// `[n] { [1] { [0] fallback } }`: the only form the ICAO profile allows.
List<int> _fallbackForm(int tag, int code) =>
    _tlv(tag, _tlv(0xA1, _tlv(0x80, [code])));

List<int> _info({int format = 2, List<int> extra = const []}) => _tlv(
  0xA1,
  _cat([
    _tlv(0xA0, _tlv(0x80, [format])),
    extra,
  ]),
);

List<int> _block2d({
  List<int> image = _jpeg,
  List<int>? info,
  List<int> extra = const [],
}) => _tlv(0xA0, _cat([_tlv(0x80, image), info ?? _info(), extra]));

/// `[1] ImageRepresentation { [0] base { [0] 2D } }`.
List<int> _imageRepresentation(List<int> block2d) =>
    _tlv(0xA1, _tlv(0xA0, block2d));

List<int> _representation({
  List<int>? imageRepresentation,
  List<int> extra = const [],
}) => _tlv(
  0x30,
  _cat([
    _tlv(0x80, [0]),
    imageRepresentation ?? _imageRepresentation(_block2d()),
    extra,
  ]),
);

/// The `7F2E` value: `A1 { 65 { A0 version, A1 { representations } } }`.
List<int> _template({
  List<List<int>>? representations,
  List<int> version = _version,
}) => _tlv(
  0xA1,
  _tlv(
    0x65,
    _cat([
      version,
      _tlv(0xA1, _cat(representations ?? [_representation()])),
    ]),
  ),
);

/// A template whose one representation carries [identity] as its `[8]`
/// IdentityMetadataBlock contents.
List<int> _withIdentity(List<int> identity) =>
    _template(representations: [_representation(extra: _tlv(0xA8, identity))]);

/// A template whose 2D block carries [info] extras and [device] contents.
List<int> _withImageInfo({List<int> info = const [], List<int>? device}) =>
    _template(
      representations: [
        _representation(
          imageRepresentation: _imageRepresentation(
            _block2d(
              info: _info(extra: info),
              extra: device == null ? const [] : _tlv(0xA2, device),
            ),
          ),
        ),
      ],
    );

Iso39794FaceRecord _parse(List<int> template) =>
    parseIso39794FaceRecord(template);

void _expectMalformed(List<int> template) => expect(
  () => _parse(template),
  throwsA(
    isA<InvalidDataPassed>().having(
      (e) => e.reason,
      'reason',
      'DG2 ISO/IEC 39794-5 structure malformed',
    ),
  ),
);

void _expectOutsideProfile(List<int> template, String what) => expect(
  () => _parse(template),
  throwsA(
    isA<NotYetSupported>().having(
      (e) => e.reason,
      'reason',
      'ISO/IEC 39794-5 DG2 outside the ICAO profile: $what',
    ),
  ),
);

void main() {
  group('the image path (strict)', () {
    test('a mandatory-fields record: image verbatim, every map 0', () {
      final r = _parse(_template());
      expect(r.representationCount, 1);
      expect(r.image, _jpeg);
      expect(r.imageDataType, 0);
      expect([
        r.imageWidth,
        r.imageHeight,
        r.imageColorSpace,
        r.sourceType,
        r.eyeColor,
        r.hairColor,
        r.featureMask,
        r.expression,
      ], everyElement(0));
    });

    test('image data format 2/3/4 map to image data type 0/1/1', () {
      for (final (code, type) in const [(2, 0), (3, 1), (4, 1)]) {
        final r = _parse(
          _template(
            representations: [
              _representation(
                imageRepresentation: _imageRepresentation(
                  _block2d(info: _info(format: code)),
                ),
              ),
            ],
          ),
        );
        expect(r.imageDataType, type, reason: 'code $code');
      }
    });

    test('any other image data format code is outside the profile', () {
      for (final code in const [0, 1, 5, 6, 7, 0x7F]) {
        _expectOutsideProfile(
          _template(
            representations: [
              _representation(
                imageRepresentation: _imageRepresentation(
                  _block2d(info: _info(format: code)),
                ),
              ),
            ],
          ),
          'image data format',
        );
      }
    });

    test('the image data format extension block is outside the profile', () {
      _expectOutsideProfile(
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _block2d(info: _tlv(0xA1, _tlv(0xA0, _tlv(0xA1)))),
              ),
            ),
          ],
        ),
        'image data format',
      );
    });

    test('an undecodable or absent image data format is malformed', () {
      for (final format in [
        _tlv(0xA0, _tlv(0x80)), // empty ENUMERATED
        _tlv(0xA0, _tlv(0x80, const [0x00, 0x00, 0x00, 0x02])), // 4 bytes
        _tlv(0xA0, _tlv(0x80, const [0xFE])), // negative
        _tlv(0xA0), // empty CHOICE
        _tlv(0xA0, _tlv(0x82, const [0x02])), // unknown alternative
      ]) {
        _expectMalformed(
          _template(
            representations: [
              _representation(
                imageRepresentation: _imageRepresentation(
                  _block2d(info: _tlv(0xA1, format)),
                ),
              ),
            ],
          ),
        );
      }
      _expectMalformed(
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _block2d(info: _tlv(0xA1, _tlv(0xA7))),
              ),
            ),
          ],
        ),
      );
    });

    test(
      'no, 3D or extension representation: outside; undefined: malformed',
      () {
        _expectOutsideProfile(
          _template(representations: const []),
          'no representation',
        );
        _expectOutsideProfile(
          _template(
            representations: [
              _representation(
                imageRepresentation: _tlv(0xA1, _tlv(0xA0, _tlv(0xA1))),
              ),
            ],
          ),
          '3D representation',
        );
        _expectOutsideProfile(
          _template(
            representations: [
              _representation(imageRepresentation: _tlv(0xA1, _tlv(0xA1))),
            ],
          ),
          'unknown representation',
        );
        for (final undefined in [
          _tlv(0xA1, _tlv(0xA2)),
          _tlv(0xA1, _tlv(0xA0, _tlv(0xA2))),
        ]) {
          _expectMalformed(
            _template(
              representations: [
                _representation(imageRepresentation: undefined),
              ],
            ),
          );
        }
      },
    );

    test('an empty image is outside the profile, after the format', () {
      _expectOutsideProfile(
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _block2d(image: const []),
              ),
            ),
          ],
        ),
        'empty image',
      );
      _expectOutsideProfile(
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _block2d(image: const [], info: _info(format: 5)),
              ),
            ),
          ],
        ),
        'image data format',
      );
    });

    test('a missing required element is malformed', () {
      final rep = _representation();
      for (final template in [
        _tlv(0x65), // no A1 around the face image data block
        _tlv(0xA1, _tlv(0x64)), // A1 without 65
        _tlv(0xA1, _tlv(0x65, _version)), // no representation blocks
        _template(representations: [_tlv(0x31, rep.sublist(2))]), // not 30
        _template(
          representations: [
            _tlv(0x30, _tlv(0x80, const [0])),
          ],
        ),
        _template(
          representations: [_representation(imageRepresentation: _tlv(0xA1))],
        ),
        _template(
          representations: [
            _representation(imageRepresentation: _tlv(0xA1, _tlv(0xA0))),
          ],
        ),
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _tlv(0xA0, _info()), // no representationData2D
              ),
            ),
          ],
        ),
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _tlv(0xA0, _tlv(0x80, _jpeg)), // no imageInformation2DBlock
              ),
            ),
          ],
        ),
      ]) {
        _expectMalformed(template);
      }
    });

    test('bytes that are not TLV fail the strict level they sit in', () {
      const junk = [0x30, 0x05, 0x00]; // declares 5 bytes, has 1
      for (final template in [
        junk,
        _tlv(0xA1, junk),
        _tlv(0xA1, _tlv(0x65, junk)),
        _tlv(0xA1, _tlv(0x65, _cat([_version, _tlv(0xA1, junk)]))),
        _template(representations: [_tlv(0x30, junk)]),
        _template(
          representations: [
            _representation(imageRepresentation: _tlv(0xA1, junk)),
          ],
        ),
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(_tlv(0xA0, junk)),
            ),
          ],
        ),
        _template(
          representations: [
            _representation(
              imageRepresentation: _imageRepresentation(
                _block2d(info: _tlv(0xA1, junk)),
              ),
            ),
          ],
        ),
        [..._template(), 0xFF], // a trailing byte after the A1 template
      ]) {
        _expectMalformed(template);
      }
    });

    test('unknown elements are skipped and the version is not read', () {
      const unknown = [0x9F, 0x20, 0x01, 0x00]; // [32] INTEGER 0
      final r = _parse(
        _cat([
          _tlv(
            0xA1,
            _cat([
              _tlv(
                0x65,
                _cat([
                  _tlv(
                    0xA1,
                    _representation(
                      imageRepresentation: _imageRepresentation(
                        _block2d(
                          info: _info(extra: unknown),
                          extra: unknown,
                        ),
                      ),
                      extra: unknown,
                    ),
                  ),
                  unknown,
                ]),
              ),
              unknown,
            ]),
          ),
          const [0x00, 0x00], // a well-formed trailing record
        ]),
      );
      expect(r.image, _jpeg);
      expect(r.imageDataType, 0);
    });

    test('two representations: the count is 2, the first is read', () {
      final second = _representation(
        imageRepresentation: _imageRepresentation(
          _block2d(
            image: const [0xff, 0x4f, 0xff, 0x51],
            info: _info(format: 3),
          ),
        ),
      );
      final r = _parse(_template(representations: [_representation(), second]));
      expect(r.representationCount, 2);
      expect(r.image, _jpeg);
      expect(r.imageDataType, 0);
    });
  });

  group('metadata (lenient, 19794-5 mapping)', () {
    test('image size: boundaries decode, anything else reads as 0', () {
      final cases = <(List<int>, int, int)>[
        (
          _tlv(
            0xA7,
            _cat([
              _tlv(0x80, const [0x5A]),
              _tlv(0x81, const [0x78]),
            ]),
          ),
          90,
          120,
        ),
        (
          _tlv(
            0xA7,
            _cat([
              _tlv(0x80, const [0x7F]),
              _tlv(0x81, const [0x00, 0x80]),
            ]),
          ),
          127,
          128,
        ),
        (
          _tlv(
            0xA7,
            _cat([
              _tlv(0x80, const [0x00, 0xFF, 0xFF]),
              _tlv(0x81, const [0x00]),
            ]),
          ),
          65535,
          0,
        ),
        (
          _tlv(
            0xA7,
            _cat([
              _tlv(0x80, const [0x01, 0x00, 0x00]),
              _tlv(0x81, const [0x80]),
            ]),
          ),
          0,
          0,
        ),
        (
          _tlv(
            0xA7,
            _cat([
              _tlv(0x80),
              _tlv(0x81, const [0, 0, 0, 1]),
            ]),
          ),
          0,
          0,
        ),
        (_tlv(0xA7, _tlv(0x80, const [0x10])), 16, 0),
        (_tlv(0xA7, const [0x30, 0x05]), 0, 0),
        (const [], 0, 0),
      ];
      for (final (size, width, height) in cases) {
        final r = _parse(_withImageInfo(info: size));
        expect((r.imageWidth, r.imageHeight), (width, height), reason: '$size');
      }
    });

    test('colour space: both enum forms, table and out of table', () {
      const table = [0, 4, 1, 4, 2, 3, 4];
      for (var code = 0; code <= 7; code++) {
        final want = code < table.length ? table[code] : 0;
        for (final form in [_codeForm, _fallbackForm]) {
          final r = _parse(_withImageInfo(info: form(0xA9, code)));
          expect(r.imageColorSpace, want, reason: 'code $code');
        }
      }
    });

    test('source type: both enum forms, table, out of table, absent', () {
      const table = [7, 1, 2, 3, 4, 5, 6];
      for (var code = 0; code <= 7; code++) {
        final want = code < table.length ? table[code] : 0;
        for (final form in [_codeForm, _fallbackForm]) {
          final r = _parse(_withImageInfo(device: form(0xA1, code)));
          expect(r.sourceType, want, reason: 'code $code');
        }
      }
      expect(_parse(_withImageInfo(device: const [])).sourceType, 0);
      expect(_parse(_withImageInfo(device: const [0x30, 0x05])).sourceType, 0);
    });

    test('eye colour: both enum forms, table and out of table', () {
      const table = [0xFF, 0, 1, 2, 3, 4, 5, 0, 6, 7];
      for (var code = 0; code <= 10; code++) {
        final want = code < table.length ? table[code] : 0;
        for (final form in [_codeForm, _fallbackForm]) {
          final r = _parse(_withIdentity(form(0xA1, code)));
          expect(r.eyeColor, want, reason: 'code $code');
        }
      }
    });

    test('hair colour: both enum forms, table and out of table', () {
      const table = [0xFF, 0, 1, 2, 3, 4, 5, 6, 7, 0];
      for (var code = 0; code <= 10; code++) {
        final want = code < table.length ? table[code] : 0;
        for (final form in [_codeForm, _fallbackForm]) {
          final r = _parse(_withIdentity(form(0xA2, code)));
          expect(r.hairColor, want, reason: 'code $code');
        }
      }
    });

    test('an enum that cannot be decoded reads as 0', () {
      for (final field in [
        _tlv(0xA9), // empty CHOICE
        _tlv(0xA9, _tlv(0x82, const [0x02])), // unknown alternative
        _tlv(0xA9, _tlv(0xA1, _tlv(0x81, const [0x02]))), // no fallback
        _tlv(0xA9, _tlv(0xA1, const [0x30, 0x05])), // block not TLV
        _tlv(0xA9, const [0x30, 0x05]), // field not TLV
        _tlv(0xA9, _tlv(0x80, const [0xFF])), // negative code
      ]) {
        expect(_parse(_withImageInfo(info: field)).imageColorSpace, 0);
      }
      final extended = _tlv(
        0xA9,
        _tlv(
          0xA1,
          _cat([
            _tlv(0x80, const [0x02]),
            _tlv(0x81, const [0x07]),
          ]),
        ),
      );
      expect(_parse(_withImageInfo(info: extended)).imageColorSpace, 1);
    });

    test('properties: present sets bit 0, each mapped flag its bit', () {
      const bits = {
        0x80: 0x002,
        0x81: 0x004,
        0x82: 0x008,
        0x83: 0x010,
        0x84: 0,
        0x85: 0x040,
        0x86: 0x080,
        0x87: 0x100,
        0x88: 0x200,
        0x89: 0,
        0x8A: 0,
      };
      expect(_parse(_withIdentity(const [])).featureMask, 0);
      expect(_parse(_withIdentity(_tlv(0xA4))).featureMask, 0x001);
      for (final MapEntry(key: tag, value: bit) in bits.entries) {
        final r = _parse(_withIdentity(_tlv(0xA4, _tlv(tag, const [0xFF]))));
        expect(r.featureMask, 0x001 | bit, reason: 'tag $tag');
      }
      final all = _tlv(
        0xA4,
        _cat([
          for (final tag in bits.keys) _tlv(tag, const [0xFF]),
        ]),
      );
      expect(_parse(_withIdentity(all)).featureMask, 0x3DF);
      for (final flag in [
        _tlv(0x80, const [0x00]),
        _tlv(0x80, const [0xFF, 0xFF]),
        _tlv(0x80),
      ]) {
        expect(_parse(_withIdentity(_tlv(0xA4, flag))).featureMask, 0x001);
      }
      expect(
        _parse(_withIdentity(_tlv(0xA4, _tlv(0x80, const [0x01])))).featureMask,
        0x003,
        reason: 'any non-zero BOOLEAN octet is TRUE',
      );
      expect(
        _parse(_withIdentity(_tlv(0xA4, const [0x30, 0x05]))).featureMask,
        0,
      );
    });

    test('expression: one TRUE flag with a 19794-5 code, else 0', () {
      const codes = {0x80: 1, 0x81: 0, 0x82: 4, 0x83: 5, 0x84: 6, 0x85: 7};
      expect(_parse(_withIdentity(const [])).expression, 0);
      expect(_parse(_withIdentity(_tlv(0xA5))).expression, 0);
      for (final MapEntry(key: tag, value: code) in codes.entries) {
        final r = _parse(_withIdentity(_tlv(0xA5, _tlv(tag, const [0xFF]))));
        expect(r.expression, code, reason: 'tag $tag');
      }
      final neutralAmongFalse = _tlv(
        0xA5,
        _cat([
          _tlv(0x80, const [0xFF]),
          for (final tag in const [0x81, 0x82, 0x83, 0x84, 0x85])
            _tlv(tag, const [0x00]),
        ]),
      );
      expect(_parse(_withIdentity(neutralAmongFalse)).expression, 1);
      final two = _tlv(
        0xA5,
        _cat([
          _tlv(0x80, const [0xFF]),
          _tlv(0x84, const [0xFF]),
        ]),
      );
      expect(_parse(_withIdentity(two)).expression, 0);
      final unknownFlag = _tlv(
        0xA5,
        _cat([
          _tlv(0x80, const [0xFF]),
          _tlv(0x86, const [0xFF]),
        ]),
      );
      expect(_parse(_withIdentity(unknownFlag)).expression, 1);
      expect(
        _parse(_withIdentity(_tlv(0xA5, _tlv(0x86, const [0xFF])))).expression,
        0,
      );
      expect(
        _parse(_withIdentity(_tlv(0xA5, const [0x30, 0x05]))).expression,
        0,
      );
    });

    test('an identity block that is not TLV leaves its fields 0', () {
      final r = _parse(_withIdentity(const [0x30, 0x05]));
      expect([
        r.eyeColor,
        r.hairColor,
        r.featureMask,
        r.expression,
      ], everyElement(0));
      expect(r.image, _jpeg);
    });
  });
}
