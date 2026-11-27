/// EF.ATR/INFO extended-length information.
///
/// ISO/IEC 7816-4 carries a chip's APDU buffer sizes in the interindustry
/// template `7F66` ("extended length information"): two INTEGER (`02`) data
/// objects, the maximum command-APDU size first and the maximum
/// response-APDU size second. Doc 9303-10 §3.6.4.2 makes those stated sizes
/// the only licence for an extended-length READ BINARY. The layout is the
/// one OpenSC's `sc_parse_ef_atr_content` decodes (`ISO7816_TAG_II_EXTENDED_
/// LENGTH = 0x7F66`, command then response).
///
/// The same walk is offered for the ISO-DEP historical bytes, where an
/// issuer may place the template; those bytes are normally COMPACT-TLV, in
/// which case the walk simply finds nothing.
library;

import 'tlv.dart';

/// The chip's stated APDU buffer sizes, in bytes.
typedef ChipBufferSizes = ({int maxCommandBytes, int maxResponseBytes});

/// Decodes the `7F66` template from [data] (an EF.ATR/INFO file or a
/// historical-bytes payload) or returns null when the template is absent
/// or malformed. Total: never throws.
ChipBufferSizes? parseExtendedLengthInfo(List<int> data) {
  final records = TlvRecord.sequenceOfRecords(data);
  if (records == null) {
    return null;
  }
  for (final record in records) {
    if (record.tag != 0x7F66) {
      continue;
    }
    final integers = TlvRecord.sequenceOfRecords(record.value);
    if (integers == null ||
        integers.length < 2 ||
        integers.take(2).any((r) => r.tag != 0x02 || r.value.isEmpty)) {
      return null;
    }
    return (
      maxCommandBytes: _unsigned(integers[0].value),
      maxResponseBytes: _unsigned(integers[1].value),
    );
  }
  return null;
}

int _unsigned(List<int> bytes) {
  var value = 0;
  for (final b in bytes) {
    value = (value << 8) | b;
  }
  return value;
}
