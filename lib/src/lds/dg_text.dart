/// Shared element-value decoding for the DG11/DG12 walks; **unexported**,
/// like `mrz_text.dart`: these are transliterations of upstream's private
/// `DataGroup12` helpers plus the `A0` group walk, not public API.
///
/// Upstream keeps `parseDateOfIssue`/`decodeASCII`/`decodeBCD` private on
/// `DataGroup12`; the port hoists them here because DG11's `5F2B` takes the
/// *identical* rule (a fix: upstream decodes it as UTF-8 only), and a second
/// copy would be free to drift from the one the conformance vectors pin.
library;

import 'dart:convert';

import 'tlv.dart';

/// Swift `String(bytes:value, encoding:.utf8)`, the failable init: invalid
/// UTF-8 yields nil (the rule `DataGroup1` follows).
String? decodeUtf8OrNull(List<int> value) {
  try {
    return utf8.decode(value);
  } on FormatException {
    return null;
  }
}

/// Upstream `DataGroup12.parseDateOfIssue(value:)`: a 4-byte value is BCD,
/// anything else is UTF-8. Applied verbatim to DG12's `5F26` (parity) and
/// to DG11's `5F2B` (a fix: upstream decodes it as UTF-8 only).
///
/// An upstream quirk is kept: **any** 4-byte value takes the BCD branch, so
/// 4 ASCII digits `"2015"` expand to `"32303135"`, and non-digit nibbles
/// expand verbatim (`0xAB` -> `"AB"`).
String? decodeDateValue(List<int> value) =>
    value.length == 4 ? decodeBcd(value) : decodeUtf8OrNull(value);

/// Upstream `decodeBCD(value:)`: `String(format: "%02X")` per byte, joined.
String decodeBcd(List<int> value) =>
    value.map((b) => b.toRadixString(16).toUpperCase().padLeft(2, '0')).join();

/// The interior of an `A0` content-specific group, which upstream does not
/// parse: `02` count + N × [recordTag] records (ICAO 9303 P10 Tables 71/73).
///
/// **Total**. The addition creates no new failure modes: a value that is not
/// a clean record sequence yields an empty list rather than throwing, so the
/// sibling-field walk is unaffected either way. The `02` count is walked past
/// and never validated against the number of records present (consistent with
/// DG7's stance on its own count), and a record whose value is not
/// valid UTF-8 is dropped (the same nil-on-invalid rule as [decodeUtf8OrNull]).
List<String> decodeContentGroup(List<int> value, int recordTag) {
  final records = TlvRecord.sequenceOfRecords(value);
  if (records == null) {
    return const [];
  }
  final out = <String>[];
  for (final record in records) {
    if (record.tag != recordTag) {
      continue;
    }
    final decoded = decodeUtf8OrNull(record.value);
    if (decoded != null) {
      out.add(decoded);
    }
  }
  return out;
}
