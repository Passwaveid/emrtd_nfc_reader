// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/NFCPassportModel.swift @ 3bf5456 (2.3.2)
//   The hash-oracle slice only (`parseSODSignatureContent`, lines 487-539,
//   and the comparison half of `ensureReadDataNotBeenTamperedWith`, lines
//   449-481). The rest of NFCPassportModel (CMS verification, certificate
//   handling, the model object itself) is passive auth and out of scope;
//   the fallback branch `sod.getEncapsulatedContent()` at line 444 is
//   exactly the path this port takes always.

/// The SOD hash oracle: `hash(dgN raw) == SOD hash`, self-checking on any
/// chip with no fixtures.
///
/// [parseSODSignatureContent] transliterates upstream's OpenSSL-dump-text
/// scrape onto a depth-annotated `TlvRecord` walk: the selection logic
/// (depth-2 digest OID (last match wins), depth-3 INTEGER into a running
/// `currentDG` register (last wins; unparseable poisons), depth-3 OCTET
/// STRING paired against the register) is reproduced exactly; the `d=N`
/// text matching, `[HEX DUMP]:` scraping, and hex re-parse are not (depth
/// comes from real TLV nesting).
///
/// Kept as upstream has them: `dgList`'s in-bounds oddities 0 -> COM and
/// 17 -> SOD are accepted, though out of spec (P10's `DataGroupNumber`
/// enumerates 1-16 only); the last algorithm wins; the register is retained;
/// SOD and COM are never checked; hex is uppercase. Unlike upstream: ids
/// outside 0-17, including negative INTEGERs, skip the entry and clear the
/// register, where upstream indexes `dgList[id]` unvalidated and crashes on
/// unauthenticated data; failures throw [InvalidDataPassed] with upstream's
/// `UnableToParseSODHashes` messages verbatim (the "algorythm" typo is kept
/// for log parity); and the digest map is a strict five OIDs, where
/// upstream's substring match also accepts e.g. `sha1WithRSAEncryption`, a
/// *signature* OID; split conformance cases pin the divergence.
library;

import 'dart:convert';

import '../errors.dart';
import '../logging.dart';
import '../utils.dart';
import 'data_group.dart';
import 'data_group_hash.dart';
import 'data_group_id.dart';
import 'sod.dart';
import 'tlv.dart';

/// Upstream's `dgList`: 18 entries, so a scraped id 0 -> COM and 17 -> SOD
/// stay reachable in-bounds oddities.
const List<DataGroupId> _dgList = [
  DataGroupId.COM, DataGroupId.DG1, DataGroupId.DG2, DataGroupId.DG3, //
  DataGroupId.DG4, DataGroupId.DG5, DataGroupId.DG6, DataGroupId.DG7,
  DataGroupId.DG8, DataGroupId.DG9, DataGroupId.DG10, DataGroupId.DG11,
  DataGroupId.DG12, DataGroupId.DG13, DataGroupId.DG14, DataGroupId.DG15,
  DataGroupId.DG16, DataGroupId.SOD,
];

/// Exactly the five SHA digest OIDs; the mapped names are precisely the
/// strings `DataGroup.hash` dispatches on (strict where upstream
/// substring-matches OpenSSL long names).
const Map<String, String> _digestOids = {
  '1.3.14.3.2.26': 'SHA1',
  '2.16.840.1.101.3.4.2.4': 'SHA224',
  '2.16.840.1.101.3.4.2.1': 'SHA256',
  '2.16.840.1.101.3.4.2.2': 'SHA384',
  '2.16.840.1.101.3.4.2.3': 'SHA512',
};

final BigInt _int64Min = -(BigInt.one << 63);
final BigInt _int64Max = (BigInt.one << 63) - BigInt.one;

/// Upstream `NFCPassportModel.parseSODSignatureContent` (name kept; bytes
/// in, the encapsulated content from [SOD.getEncapsulatedContent], not
/// dump text).
///
/// Throws [InvalidASN1Value] if the content is not fully parseable TLV
/// (upstream: `OpenSSLUtils.ASN1Parse` threw before the scrape ran), and
/// [InvalidDataPassed] with upstream's two `UnableToParseSODHashes`
/// messages when no algorithm or no hashes survive.
(String, Map<DataGroupId, String>) parseSODSignatureContent(List<int> content) {
  var sodHashAlgo = '';
  // The `currentDG` register: null = unset/cleared; poisoned mirrors
  // upstream's register holding an unparseable hex string (a value outside
  // signed 64-bit, upstream's `Int(_, radix:16)` overflow, not octet
  // count: OpenSSL strips leading zero octets before rendering).
  int? currentDG;
  var currentDGPoisoned = false;
  final sodHashes = <DataGroupId, String>{};

  final roots = TlvRecord.sequenceOfRecords(content);
  if (roots == null) {
    throw const InvalidASN1Value();
  }

  void visit(TlvRecord record, int depth) {
    if (_isConstructed(record.tag)) {
      final kids = TlvRecord.sequenceOfRecords(record.value);
      if (kids == null) {
        throw const InvalidASN1Value(); // eager, as upstream's ASN1Parse
      }
      for (final kid in kids) {
        visit(kid, depth + 1);
      }
      return;
    }
    if (depth == 2 && record.tag == 0x06) {
      // (a) depth-2 OBJECT IDENTIFIER: last known-digest match wins.
      final String oid;
      try {
        oid = asn1DecodeOid(record.data);
      } on InvalidASN1Value {
        return; // undecodable OID: no match, walk continues
      }
      final algo = _digestOids[oid];
      if (algo != null) {
        sodHashAlgo = algo;
      }
    } else if (depth == 3 && record.tag == 0x02) {
      // (b) depth-3 INTEGER sets the register: last wins.
      final value = _derIntegerValue(record.value);
      if (value >= _int64Min && value <= _int64Max) {
        currentDG = value.toInt();
        currentDGPoisoned = false;
      } else {
        currentDG = null;
        currentDGPoisoned = true; // upstream: register keeps the bad text
      }
    } else if (depth == 3 && record.tag == 0x04) {
      // (c) depth-3 OCTET STRING pairs with the register.
      if (currentDGPoisoned) {
        return; // entry skipped, register stays poisoned (upstream parity)
      }
      final id = currentDG;
      if (id == null) {
        return; // register unset: entry skipped, as upstream's "" check
      }
      if (id >= 0 && id < _dgList.length) {
        sodHashes[_dgList[id]] = binToHexRep(record.value); // uppercase hex
      }
      // Out-of-range ids skip the entry; the pairing is consumed and the
      // register cleared either way (upstream crashes here).
      currentDG = null;
    }
  }

  for (final root in roots) {
    visit(root, 0);
  }

  if (sodHashAlgo == '') {
    throw const InvalidDataPassed('Unable to find hash algorythm used');
  }
  if (sodHashes.isEmpty) {
    throw const InvalidDataPassed('Unable to extract hashes');
  }

  passportReaderLog.fine('Parse SOD - Using Algo - $sodHashAlgo');
  passportReaderLog.fine('      - Hashes     - $sodHashes');

  return (sodHashAlgo, sodHashes);
}

/// The `ldsVersionInfo` member of an `LDSSecurityObject` (9303-10 §4.6.2.1;
/// present when the object is V1), rendered as EF.COM renders the same
/// facts: the four-digit `"aabb"` LDS version as `"a.b"` and the six-digit
/// `"aabbcc"` Unicode version as `"a.b.c"` (§4.6.1.1 / §4.6.1.2); `"0107"`
/// -> `"1.7"`, `"040000"` -> `"4.0.0"`, each two-digit slice integer-parsed
/// exactly as `COM.parse` does, so a value from either file has one shape.
///
/// The member is found by structure, not position: the first member of the
/// root SEQUENCE that is itself a SEQUENCE of exactly two `PrintableString`s.
/// The specification places it fourth, after `dataGroupHashValues`; encoders
/// in the field have been seen to place it third. Nothing else in the object
/// has that shape (`hashAlgorithm` holds an OID and a NULL, and every
/// `dataGroupHashValues` entry holds an INTEGER and an OCTET STRING) and a
/// stray `PrintableString` in the algorithm parameters is not mistaken for
/// a version.
///
/// **Never throws.** `(null, null)` for a V0 object, for anything that is
/// not a single constructed root, for an unparseable child list, for a
/// version string that is not exactly four / six parseable digits, and for
/// arbitrary bytes. [content] is the encapsulated content
/// [SOD.getEncapsulatedContent] yields: the same bytes
/// [parseSODSignatureContent] takes, whose failures decide whether a read
/// fails; this walk is kept apart from that one so a census fact can never
/// become a read error.
(String?, String?) parseLdsVersionInfo(List<int> content) {
  final roots = TlvRecord.sequenceOfRecords(content);
  if (roots == null || roots.length != 1 || !_isConstructed(roots[0].tag)) {
    return (null, null);
  }
  final members = TlvRecord.sequenceOfRecords(roots[0].value);
  if (members == null) {
    return (null, null);
  }
  for (final member in members) {
    if (!_isConstructed(member.tag)) {
      continue;
    }
    final kids = TlvRecord.sequenceOfRecords(member.value);
    if (kids == null) {
      return (null, null);
    }
    if (kids.length == 2 && kids[0].tag == 0x13 && kids[1].tag == 0x13) {
      final ldsVersion = _renderVersion(kids[0].value, digits: 4);
      final unicodeVersion = _renderVersion(kids[1].value, digits: 6);
      if (ldsVersion == null || unicodeVersion == null) {
        return (null, null);
      }
      return (ldsVersion, unicodeVersion);
    }
  }
  return (null, null);
}

/// `"aabb"` -> `"a.b"` / `"aabbcc"` -> `"a.b.c"` under `COM.parse`'s rule:
/// exactly [digits] ASCII characters, every two-character slice
/// integer-parseable. Null otherwise.
String? _renderVersion(List<int> bytes, {required int digits}) {
  if (bytes.length != digits) {
    return null;
  }
  final String text;
  try {
    text = ascii.decode(bytes);
  } on FormatException {
    return null;
  }
  final parts = <int>[];
  for (var i = 0; i < digits; i += 2) {
    final part = int.tryParse(text.substring(i, i + 2));
    if (part == null) {
      return null;
    }
    parts.add(part);
  }
  return parts.join('.');
}

/// Result object replacing upstream's model-state mutation + throw: the port
/// has no `PassiveAuthenticationError.InvalidDataGroupHash`, and a caller's
/// hash check wants a decision input, not an exception. Outcome parity is
/// pinned string-for-string via [errors].
class SODHashCheckResult {
  const SODHashCheckResult({
    required this.sodHashAlgorythm,
    required this.dataGroupHashes,
    required this.errors,
    this.declaredDataGroups = const [],
    this.ldsVersion,
    this.unicodeVersion,
  });

  /// The digest algorithm the SOD declares (upstream spelling).
  final String sodHashAlgorythm;

  /// Upstream `dataGroupHashes`: one row per DG that had a SOD hash.
  final Map<DataGroupId, DataGroupHash> dataGroupHashes;

  /// Upstream's accumulated error text, `""` when clean, the same
  /// `"DataGroup \(id) is missing!\n"` / `"\(id) invalid hash:..."` formats.
  final String errors;

  /// Every data group the SOD carries a hash for, in DG-number order
  /// ([DataGroupId.index]) whatever order the DER listed them in, the
  /// document's own statement of which files it holds, independent of
  /// which were read ([dataGroupHashes] covers only those). Reported
  /// verbatim: a nonconformant object that hashes `COM` or `SOD` (ids 0 and
  /// 17, accepted by [parseSODSignatureContent]) shows them here. Empty only
  /// on a hand-built result; [checkDataGroupHashes] never produces an empty
  /// list, since the parse throws on a hashless object.
  final List<DataGroupId> declaredDataGroups;

  /// The SOD's `ldsVersionInfo.ldsVersion` rendered as `"a.b"` (the
  /// EF.COM form), or null when the object is V0 or the member is
  /// unusable; see [parseLdsVersionInfo].
  final String? ldsVersion;

  /// The SOD's `ldsVersionInfo.unicodeVersion` rendered as `"a.b.c"`, or
  /// null under the same conditions as [ldsVersion].
  final String? unicodeVersion;

  /// Reproduces upstream's no-throw condition exactly.
  bool get passed => errors.isEmpty;
}

/// The comparison half of upstream
/// `NFCPassportModel.ensureReadDataNotBeenTamperedWith`:
/// [dataGroupsRead] mirrors the model's `dataGroupsRead` map (whatever was
/// read, keyed by id; include the SOD itself for full parity; SOD and COM
/// are exempt from the missing-DG check).
SODHashCheckResult checkDataGroupHashes({
  required SOD sod,
  required Map<DataGroupId, DataGroup> dataGroupsRead,
}) {
  final signedData = sod.getEncapsulatedContent();

  // Now Verify passport data by comparing compare Hashes in SOD against
  // computed hashes to ensure data not been tampered with (upstream
  // comment).
  final (sodHashAlgorythm, sodHashes) = parseSODSignatureContent(signedData);

  var errors = '';
  final dataGroupHashes = <DataGroupId, DataGroupHash>{};
  for (final MapEntry(key: id, value: dgVal) in dataGroupsRead.entries) {
    final sodHashVal = sodHashes[id];
    if (sodHashVal == null) {
      // SOD and COM don't have hashes so these aren't errors (upstream
      // comment).
      if (id != DataGroupId.SOD && id != DataGroupId.COM) {
        errors += 'DataGroup ${id.getName()} is missing!\n';
      }
      continue;
    }

    final computedHashVal = binToHexRep(dgVal.hash(sodHashAlgorythm));

    var match = true;
    if (computedHashVal != sodHashVal) {
      errors +=
          '${id.getName()} invalid hash:\n'
          '  SOD hash:$sodHashVal\n'
          '   Computed hash:$computedHashVal\n';
      match = false;
    }

    dataGroupHashes[id] = DataGroupHash(
      id: id.getName(),
      sodHash: sodHashVal,
      computedHash: computedHashVal,
      match: match,
    );
  }

  if (errors != '') {
    passportReaderLog.severe('HASH ERRORS - $errors');
  } else {
    passportReaderLog.fine('Passport passed Datagroup Tampering check');
  }

  final (ldsVersion, unicodeVersion) = parseLdsVersionInfo(signedData);

  return SODHashCheckResult(
    sodHashAlgorythm: sodHashAlgorythm,
    dataGroupHashes: dataGroupHashes,
    errors: errors,
    declaredDataGroups: sodHashes.keys.toList()
      ..sort((a, b) => a.index.compareTo(b.index)),
    ldsVersion: ldsVersion,
    unicodeVersion: unicodeVersion,
  );
}

/// DER INTEGER value bytes as a signed (two's-complement) big integer:
/// the mathematical value OpenSSL renders, whose `Int(_, radix:16)` parse
/// upstream's register semantics hang off.
BigInt _derIntegerValue(List<int> bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  if (bytes.isNotEmpty && (bytes[0] & 0x80) != 0) {
    v -= BigInt.one << (8 * bytes.length);
  }
  return v;
}

/// BER constructed bit (0x20) of the first tag byte.
bool _isConstructed(int tag) {
  var t = tag;
  while (t > 0xFF) {
    t >>= 8;
  }
  return t & 0x20 != 0;
}
