/// Shared ICAO 9303 name/filler text handling: **unexported** internal
/// helpers, kept out of the public API like every uncurated helper.
///
/// `Dg1Fields`, `Dg11Fields` and `Dg12Fields` all apply these, so the three
/// share one implementation of the MRZ filler-stripping and name-splitting
/// rules rather than a copy each; the `Dg1Fields` tests pin their behaviour.
library;

/// `<+$`, trailing-only: leading/embedded fillers are data (the Norwegian TD1
/// optional-data shape).
String stripTrailingFillers(String value) {
  var end = value.length;
  while (end > 0 && value[end - 1] == '<') {
    end--;
  }
  return value.substring(0, end);
}

/// [stripTrailingFillers], null-propagating.
String? stripTrailingFillersOrNull(String? value) =>
    value == null ? null : stripTrailingFillers(value);

/// The leading run of non-filler characters (the guard for note-j extended
/// document numbers).
String leadingNonFillerRun(String value) {
  var end = 0;
  while (end < value.length && value[end] != '<') {
    end++;
  }
  return value.substring(0, end);
}

/// The MRZ name split: strip trailing fillers, split at the **first**
/// `<<`; within each half `<` becomes a space, then trim.
///
/// The right part is `''` (never null) when there is no separator, the
/// Brunei shape. The record type is structurally identical to
/// `MrzNameParts` (declared in `dg11_fields.dart`, which is where the name is
/// public); this file stays free of the public vocabulary.
({String primaryIdentifier, String secondaryIdentifier}) splitMrzName(
  String rawName,
) {
  final stripped = stripTrailingFillers(rawName);
  final separatorAt = stripped.indexOf('<<');
  final left = separatorAt < 0 ? stripped : stripped.substring(0, separatorAt);
  final right = separatorAt < 0 ? '' : stripped.substring(separatorAt + 2);
  return (
    primaryIdentifier: left.replaceAll('<', ' ').trim(),
    secondaryIdentifier: right.replaceAll('<', ' ').trim(),
  );
}
