// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/DataGroups/DataGroup7.swift @ 3bf5456 (2.3.2)
//   `getImage()` (UIKit) is dropped: image decoding/rendering is app-side;
//   the package hands over bytes + format, as for DG2.

/// DG7 (displayed signature or usual mark) parsing.
///
/// P10 §4.7.7 Table 62: `67 { 02 count, 5F43 image × count }`; images stored
/// directly per ISO/IEC 10918 (JFIF option) or ISO/IEC 15444, with **no**
/// CBEFF wrapper (unlike DG2).
///
/// As upstream, exactly one `5F43` is read: the `02` instance count is read
/// and discarded, never validated, and a second instance is left unread
/// without error. Nor is the image format validated: any bytes are accepted
/// where DG2 throws. Unlike upstream, a truncated file throws the base walk's
/// typed errors.
///
/// [imageFormat], a Dart-only addition, surfaces the prefix-sniffed format;
/// upstream has no format surface on DG7 at all.
library;

import 'dart:typed_data';

import 'data_group.dart';
import 'data_group2.dart' show FaceImageFormat, sniffImageFormat;
import 'data_group_id.dart';

/// Upstream `DataGroup7`.
class DataGroup7 extends DataGroup {
  DataGroup7(super.data);

  /// The first `5F43` value, verbatim (any further instances are never
  /// read). Empty only when the file declared a zero-length image.
  Uint8List imageData = Uint8List(0);

  @override
  DataGroupId get datagroupType => DataGroupId.DG7;

  /// The header-detected format of [imageData], or `null` when the prefix
  /// matches none of the three (a Dart-only addition; the sniff never
  /// throws, so an unrecognized signature image is not a parse failure).
  /// The enum name is DG2's; it is the package's one image-format
  /// vocabulary.
  FaceImageFormat? get imageFormat => sniffImageFormat(imageData);

  @override
  void parse(List<int> data) {
    var tag = getNextTag();
    verifyTag(tag, equals: 0x02);
    // The instance count is read and discarded; never compared against the
    // number of 5F43 templates that follow.
    getNextValue();

    tag = getNextTag();
    verifyTag(tag, equals: 0x5F43);

    imageData = getNextValue();
  }
}
