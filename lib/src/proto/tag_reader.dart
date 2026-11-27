// Ported to Dart from NFCPassportReader (https://github.com/AndyQ/NFCPassportReader)
// Copyright (c) 2019 Andy Qua, MIT License (see LICENSE).
// Source: Sources/NFCPassportReader/TagReader.swift @ 3bf5456 (2.3.2)
//   minus CoreNFC session code (replaced by the transceiver seam).
//   `sendMSEKAT` and `sendMSESetATIntAuth` serve the Chip Authentication
//   port, and `doInternalAuthentication` the Active Authentication port
//   (minus upstream's `useExtendedMode` parameter, whose default is what the
//   port already does).

/// TagReader. Structure and quirks preserved from upstream. Upstream's
/// status check is fixed, input that crashes or hangs upstream throws typed
/// errors, and READ BINARY offsets beyond 15 bits are refused. The Dart-only
/// field-compatibility additions are the `6C XX` exact-length retry, the
/// `62 82` end-of-file tolerance, the EF.CardAccess select fallback and the
/// transport capability gates. See UPSTREAM.md, Divergences.
///
/// The READ BINARY chunk is fitted to the transport at read time, secure
/// messaging included ([fitReadLength]); the orchestrator chooses the chunk
/// size ([TagReader.new]'s `readChunk`); [TagReader.lastRead] counts READ
/// BINARY traffic; and [TagReader.readAtrInfo] reads EF.ATR/INFO before
/// authentication.
///
/// A command that needs extended length the transport does not declare, or
/// that is longer than the transport's `maxTransceiveLength`, is refused
/// before it is sent, and [TagReader.lastRefusal] names which declared cap
/// refused it.
library;

import 'dart:typed_data';

import '../errors.dart';
import '../lds/data_group_id.dart';
import '../lds/tlv.dart';
import '../logging.dart';
import '../transport/transceiver.dart';
import '../utils.dart';
import 'command_apdu.dart';
import 'read_quirks.dart';
import 'response_apdu.dart';
import 'secure_messaging.dart';

/// Which declared transport cap stopped [TagReader.send] from handing a
/// command to the transport.
enum TransportRefusal {
  /// The command needs extended length and the transport does not declare
  /// support for it.
  extendedLengthUnsupported,

  /// The encoded command is longer than the transport's
  /// `maxTransceiveLength`.
  exceedsTransceiveLength,
}

class TagReader {
  /// [readChunk] is the READ BINARY size the reader starts a session at;
  /// upstream's 0xA0 by default so the transcripts that drive `TagReader`
  /// directly stay valid, while `PassportReader` passes its `ReadProfile`
  /// value. A `ReadQuirks.maxReadLength` wins over it.
  TagReader(
    this._transceiver, {
    this.quirks = ReadQuirks.none,
    int readChunk = 0xA0,
  }) : maxDataLengthToRead = quirks.maxReadLength ?? readChunk;

  final NfcTransceiver _transceiver;

  /// Quirk knobs. [ReadQuirks.none] by default, behaviorally
  /// identical to a quirk-less reader; see `read_quirks.dart` for the
  /// zero-entry policy.
  final ReadQuirks quirks;

  /// BAC and PACE install their session here.
  SecureMessagingSession? secureMessaging;

  /// The READ BINARY size this session asks for, before the transport fit.
  ///
  /// Chips cap the length they will serve: `6C XX`/`67 00`/`6B 00`/`62 82`
  /// on an oversized Le, with caps seen at 231 (`6C E7`), ≤ 0xE7 and 160 in
  /// the field, and a chip that self-reports its cap with `6C XX` is
  /// answered by the exact-Le retry in [send]. Upstream settled on 0xA0
  /// for reliability; 223 is JMRTD's production default and the largest
  /// value whose secure-messaging response frame (244 bytes under either
  /// cipher, see [fitReadLength]) fits every Android ISO-DEP transceive cap
  /// in circulation. The value is stored as requested and fitted to the
  /// transport at read time.
  int maxDataLengthToRead;

  void Function(int percent)? progress;

  /// READ BINARY traffic of the most recent [selectFileAndRead]: the fitted
  /// chunk size in force, the number of READ BINARY commands the read loop
  /// issued (the 4-byte header read included; an exact-Le resend inside
  /// [send] is not counted separately), and the bytes accumulated so far.
  /// Reset when the read starts, so a throw leaves the partial count
  /// visible; null until the SELECT has succeeded.
  ({int chunkSize, int chunks, int bytes})? lastRead;

  /// The cap that refused the most recent [send], or null when that command
  /// was handed to the transport. Reset as every [send] starts, so the
  /// caller's catch sees the refusal that ended it.
  TransportRefusal? lastRefusal;

  void overrideDataAmountToRead(int newAmount) {
    maxDataLengthToRead = newAmount;
  }

  void reduceDataReadingAmount() {
    if (maxDataLengthToRead > 0xA0) {
      maxDataLengthToRead = 0xA0;
    }
  }

  Future<Uint8List> readDataGroup(DataGroupId dataGroup) async {
    final tag = dataGroup.getFileIDTag();
    if (tag == null) {
      throw const UnsupportedDataGroup();
    }
    return selectFileAndRead(tag);
  }

  Future<ResponseAPDU> getChallenge() async {
    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x84,
      p1Parameter: 0,
      p2Parameter: 0,
      data: const [],
      expectedResponseLength: 8,
    );
    return send(cmd);
  }

  /// INTERNAL AUTHENTICATE. The one chip operation Active Authentication
  /// performs: the chip signs [challenge] with its DG15 private
  /// key. Sent under whatever secure-messaging session is current; the
  /// unwrapped response data is the signature.
  ///
  /// Upstream's `useExtendedMode` parameter (Le 65535 instead of 256) is not
  /// ported: the port never had extended mode and upstream's default is
  /// byte-identical.
  Future<ResponseAPDU> doInternalAuthentication({
    required List<int> challenge,
  }) async {
    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x88,
      p1Parameter: 0,
      p2Parameter: 0,
      data: challenge,
      expectedResponseLength: 256,
    );
    return send(cmd);
  }

  Future<ResponseAPDU> doMutualAuthentication(Uint8List cmdData) async {
    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x82,
      p1Parameter: 0,
      p2Parameter: 0,
      data: cmdData,
      expectedResponseLength: 256,
    );
    return send(cmd);
  }

  /// The MSE KAT APDU, see EAC 1.11 spec, Section B.1 (upstream comment).
  /// This command is sent in the "DESede" case of Chip Authentication.
  /// - [keyData]: key data object (tag `0x91`), already wrapped
  /// - [idData]: key id data object (tag `0x84`), already wrapped; empty or
  ///   null when DG14 carried no keyId
  ///
  /// Note the asymmetry with [sendMSESetATIntAuth]: the caller
  /// emits DO84 here whenever `keyId` is non-nil, **including 0**.
  Future<ResponseAPDU> sendMSEKAT({
    required List<int> keyData,
    List<int>? idData,
  }) async {
    final data = <int>[...keyData, ...?idData];
    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x22,
      p1Parameter: 0x41,
      p2Parameter: 0xA6,
      data: data,
      expectedResponseLength: 256,
    );
    return send(cmd);
  }

  /// The MSE Set AT for Chip Authentication (upstream comment). This command
  /// is the first command that is sent in the "AES" case. For Chip
  /// Authentication we prefix `0x80` for OID and `0x84` for keyId.
  ///
  /// NOTE THIS IS CURRENTLY UNTESTED (upstream comment: the port's
  /// `ca_session_after_pace_ecdh_aes128` / `ca_session_dh_aes_chaining`
  /// transcripts pin it).
  ///
  /// Quirk preserved: DO84 is omitted when [keyId] is null **or 0**, unlike
  /// [sendMSEKAT].
  Future<ResponseAPDU> sendMSESetATIntAuth({
    required String oid,
    int? keyId,
  }) async {
    final oidBytes = oidToBytes(oid, replaceTag: true);
    final data = <int>[...oidBytes];
    if (keyId != null && keyId != 0) {
      data.addAll(wrapDO(0x84, intToBytes(keyId, removePadding: true)));
    }

    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x22,
      p1Parameter: 0x41,
      p2Parameter: 0xA4,
      data: data,
      expectedResponseLength: 256,
    );
    return send(cmd);
  }

  /// MSE:Set AT for PACE mutual authentication. No Le: Le on MSE breaks
  /// German documents (upstream v2.0.2 convergence).
  ///
  /// [parameterId] -> DO84, emitted when non-null (a Dart-only addition;
  /// upstream never sends it): 9303-11 §4.4.4.1 makes DO84 REQUIRED when
  /// the chip's domain parameters are ambiguous (multi-PACEInfo eIDs),
  /// absent otherwise.
  Future<ResponseAPDU> sendMSESetATMutualAuth({
    required String oid,
    required int keyType,
    int? parameterId,
  }) async {
    final oidBytes = oidToBytes(oid, replaceTag: true);
    final keyTypeBytes = wrapDO(0x83, [keyType]);

    final data = <int>[...oidBytes, ...keyTypeBytes];
    if (parameterId != null) {
      data.addAll(wrapDO(0x84, intToBytes(parameterId, removePadding: true)));
    }

    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0x22,
      p1Parameter: 0xC1,
      p2Parameter: 0xA4,
      data: data,
      expectedResponseLength: -1,
    );
    return send(cmd);
  }

  /// Sends a General Authenticate command.
  /// - [data]: data to be sent, without the `0x7C` prefix (added here)
  /// - [lengthExpected]: the expected length, defaults to 256
  /// - [isLast]: whether this is the last command in the chain
  ///
  /// Returns the dynamic authentication data without the `0x7C` prefix
  /// (removed here).
  Future<ResponseAPDU> sendGeneralAuthenticate({
    required List<int> data,
    int lengthExpected = 256,
    required bool isLast,
  }) async {
    final commandData = wrapDO(0x7C, data);

    // NOTE: Support of Protocol Response Data is CONDITIONAL:
    // It MUST be provided for version 2 but MUST NOT be provided for version 1.
    // So, we are expecting 0x7C (= tag), 0x00 (= length) here.

    // 0x10 is class command chaining
    final instructionClass = isLast ? 0x00 : 0x10;
    const insBsiGeneralAuthenticate = 0x86;

    final cmd = CommandAPDU(
      instructionClass: instructionClass,
      instructionCode: insBsiGeneralAuthenticate,
      p1Parameter: 0x00,
      p2Parameter: 0x00,
      data: commandData,
      expectedResponseLength: lengthExpected,
    );
    ResponseAPDU response;
    try {
      response = await send(cmd);
      response.data = unwrapDO(0x7c, response.data);
    } on ResponseError catch (e) {
      // If wrong length error, resend with Le 256. Upstream's catch is dead
      // code behind its status check (an SW ending 00 never throws there);
      // here it is live.
      if (e.sw1 == 0x67 && e.sw2 == 0x00) {
        final retryCmd = CommandAPDU(
          instructionClass: instructionClass,
          instructionCode: insBsiGeneralAuthenticate,
          p1Parameter: 0x00,
          p2Parameter: 0x00,
          data: commandData,
          expectedResponseLength: 256,
        );
        response = await send(retryCmd);
        response.data = unwrapDO(0x7c, response.data);
      } else {
        rethrow;
      }
    }
    return response;
  }

  Future<Uint8List> selectFileAndRead(List<int> tag) async {
    lastRead = null;
    var resp = await selectFile(tag);

    final chunk = fitReadLength(
      requested: maxDataLengthToRead,
      maxTransceiveLength: _transceiver.maxTransceiveLength,
      smBlockSize: secureMessaging?.padLength,
    );
    lastRead = (chunkSize: chunk, chunks: 0, bytes: 0);

    // Read first 4 bytes of header to see how big the data structure is.
    // Upstream spells this raw APDU with an extended Le=4; parsed to fields
    // it re-encodes minimal short-form `04`.
    final readHeaderCmd = CommandAPDU.parse(const [
      0x00,
      0xB0,
      0x00,
      0x00,
      0x00,
      0x00,
      0x04,
    ]);
    _countChunkSent();
    resp = await send(readHeaderCmd);

    // Header looks like:  <tag><length of data><nextTag> e.g.60145F01 -
    // the total length is the 2nd value plus the two header 2 bytes
    // We've read 4 bytes so we now need to read the remaining bytes from offset 4
    if (resp.data.length < 4) {
      // Upstream's `try!` + unchecked slicing crashes here.
      throw const InvalidDataPassed('file header truncated/malformed');
    }
    final (int, int) headerLength;
    try {
      headerLength = asn1Length(resp.data.sublist(1, 4));
    } on CannotDecodeASN1Length {
      throw const InvalidDataPassed('file header truncated/malformed');
    }
    final (len, o) = headerLength;
    var remaining = len;
    var amountRead = o + 1;
    final headerLen = amountRead;

    final data = <int>[...resp.data.sublist(0, amountRead)];
    _recordBytes(data.length);

    tagReaderLog.fine('TagReader - Number of data bytes to read - $remaining');

    var readAmount = chunk;
    while (remaining > 0) {
      // As upstream: at exactly 256 the final chunk over-asks and relies on
      // the chip returning less.
      if (chunk != 256 && remaining < chunk) {
        readAmount = remaining;
      }

      progress?.call((amountRead / (remaining + amountRead) * 100).toInt());
      // The even-INS READ BINARY offset is 15-bit (P1 bit 8 set would
      // flip the command into short-EF-ID form); files needing the odd-INS
      // `B1` variant (9303-10 §3.6.6) are not supported. Fail typed at the
      // boundary rather than emit a corrupted command.
      if (amountRead > 0x7FFF) {
        throw const InvalidDataPassed(
          'READ BINARY offset exceeds 32767: file requires the '
          'unsupported odd-INS variant',
        );
      }
      final offset = intToBin(amountRead, pad: 4);

      tagReaderLog.fine(
        'TagReader - data bytes remaining: $remaining, will read : '
        '$readAmount',
      );
      final cmd = CommandAPDU(
        instructionClass: 0x00,
        instructionCode: 0xB0,
        p1Parameter: offset[0],
        p2Parameter: offset[1],
        data: const [],
        expectedResponseLength: readAmount,
      );
      _countChunkSent();
      resp = await send(cmd);

      tagReaderLog.fine(
        'TagReader - got resp - ${binToHexRep(resp.data, asArray: true)}, '
        'sw1 : ${resp.sw1}, sw2 : ${resp.sw2}',
      );
      data.addAll(resp.data);
      _recordBytes(data.length);

      remaining -= resp.data.length;
      amountRead += resp.data.length;

      // End of file reached before Le bytes; keep what the chip gave us
      // (send() returns 62 82 unthrown on READ BINARY only).
      if (resp.sw1 == 0x62 && resp.sw2 == 0x82) {
        if (amountRead == headerLen) {
          // Zero progress beyond the header mirrors the zero-length-read
          // guard below.
          throw ResponseError(decodeError(0x62, 0x82), 0x62, 0x82);
        }
        break;
      }
      // A zero-byte `90 00` read would loop forever upstream.
      if (resp.data.isEmpty) {
        throw const ResponseError('zero-length read', 0x90, 0x00);
      }
      tagReaderLog.fine('TagReader - Amount of data left to read - $remaining');
    }

    return Uint8List.fromList(data);
  }

  void _countChunkSent() {
    final stats = lastRead!;
    lastRead = (
      chunkSize: stats.chunkSize,
      chunks: stats.chunks + 1,
      bytes: stats.bytes,
    );
  }

  void _recordBytes(int bytes) {
    final stats = lastRead!;
    lastRead = (chunkSize: stats.chunkSize, chunks: stats.chunks, bytes: bytes);
  }

  /// EF.ATR/INFO (9303-10 §3.11.1, Table 28): master-file transparent EF
  /// `2F01`, select and read access ALWAYS, so it is readable before any
  /// authentication. Optional on LDS1-only chips: a `6A 82` on the SELECT
  /// is the common outcome. Same master-file select ladder as
  /// [readCardAccess]; the file's extended-length information is decoded by
  /// `parseExtendedLengthInfo`.
  ///
  /// Unlike a data group the file is a bare sequence of interindustry data
  /// objects with no outer TLV, so [selectFileAndRead]'s header-length walk
  /// does not apply: the file is read from offset 0 in fitted chunks until
  /// the chip signals its end (a short or empty response, `62 82`, or
  /// `6B 00` on the read past the last byte).
  Future<Uint8List> readAtrInfo() async {
    await _selectMasterFile();
    await selectFile(const [0x2F, 0x01]);

    final chunk = fitReadLength(
      requested: maxDataLengthToRead,
      maxTransceiveLength: _transceiver.maxTransceiveLength,
      smBlockSize: secureMessaging?.padLength,
    );
    final data = <int>[];
    while (true) {
      if (data.length > 0x7FFF) {
        throw const InvalidDataPassed(
          'READ BINARY offset exceeds 32767: file requires the '
          'unsupported odd-INS variant',
        );
      }
      final offset = intToBin(data.length, pad: 4);
      final cmd = CommandAPDU(
        instructionClass: 0x00,
        instructionCode: 0xB0,
        p1Parameter: offset[0],
        p2Parameter: offset[1],
        data: const [],
        expectedResponseLength: chunk,
      );
      final ResponseAPDU resp;
      try {
        resp = await send(cmd);
      } on ResponseError catch (e) {
        if (data.isNotEmpty && e.sw1 == 0x6B && e.sw2 == 0x00) {
          break;
        }
        rethrow;
      }
      data.addAll(resp.data);
      if (resp.data.length < chunk || (resp.sw1 == 0x62 && resp.sw2 == 0x82)) {
        break;
      }
    }
    return Uint8List.fromList(data);
  }

  Future<Uint8List> readCardAccess() async {
    // Info provided by @smulu (upstream comment, preserved)
    // By default NFCISO7816Tag requirers a list of ISO/IEC 7816 applets
    // (AIDs). Upon discovery of NFC tag the first found applet from this
    // list is automatically selected (and you have no way of changing this).
    // This is a problem for PACE protocol becaues it requires reading
    // parameters from file EF.CardAccess which lies outside of eMRTD applet
    // (AID: A0000002471001) in the master file.

    // Now, the ICAO 9303 standard does specify command for selecting master
    // file by sending SELECT APDU with P1=0x00, P2=0x0C and empty data field
    // (see part 10 page 8). But after some testing I found out this command
    // doesn't work on some passports (European passports) and although
    // receiving success (sw=9000) from passport the master file is not
    // selected.

    // After a bit of researching standard ISO/IEC 7816 I found there is an
    // alternative SELECT command for selecting master file. The command
    // doesn't differ much from the command specified in ICAO 9303 doc with
    // only difference that data field is set to: 0x3F00. See section 6.11.3
    // of ISO/IEC 7816-4. By executing above SELECT command (with data=0x3F00)
    // master file should be selected and you should be able to read
    // EF.CardAccess from passport.

    // First select master file. The quirk seam picks the dialect. The
    // default is upstream's `3F00` form; `directFid` skips straight to
    // SELECT-by-FID (the fallback as primary); `fid3F003004` is the Danish
    // form (quirk-table-only, breaks UK documents).
    await _selectMasterFile();

    // Now read EC.CardAccess
    final data = await selectFileAndRead(const [0x01, 0x1C]);
    return data;
  }

  /// The two SELECTs [readCardAccess] sends, without its read: the master
  /// file in the quirk's dialect (select refusals tolerated), then
  /// EF.CardAccess by file id. Sent with no secure messaging installed, they
  /// end the chip's session (9303-11 §9.8.3) and leave it where the ladder's
  /// PACE ran, which is what an in-session re-PACE needs.
  Future<void> selectCardAccess() async {
    await _selectMasterFile();
    await selectFile(const [0x01, 0x1C]);
  }

  Future<void> _selectMasterFile() async {
    if (quirks.selectVariant != MasterFileSelectVariant.directFid) {
      final cmd = CommandAPDU(
        instructionClass: 0x00,
        instructionCode: 0xA4,
        p1Parameter: 0x00,
        p2Parameter: 0x0C,
        data: quirks.selectVariant == MasterFileSelectVariant.fid3F003004
            ? const [0x3F, 0x00, 0x30, 0x04]
            : const [0x3F, 0x00],
        expectedResponseLength: -1,
      );

      try {
        await send(cmd);
      } on ResponseError catch (e) {
        // Chips that refuse the MF select (Vietnamese, Thai, Algerian,
        // Latvian, UAE, Omani, French documents) still serve EF.CardAccess
        // via direct SELECT-by-FID; proceed to it instead of failing the
        // read. Any other failure propagates.
        const selectRefusals = {0x6A86, 0x6D00, 0x6700, 0x6985};
        if (!selectRefusals.contains((e.sw1 << 8) | e.sw2)) {
          rethrow;
        }
        tagReaderLog.fine(
          'TagReader - MF select refused (sw1: 0x${binToHexRepByte(e.sw1)}, '
          'sw2: 0x${binToHexRepByte(e.sw2)}) - selecting EF.CardAccess by '
          'FID directly',
        );
      }
    } else {
      tagReaderLog.fine(
        'TagReader - directFid quirk: skipping MF select, '
        'selecting EF.CardAccess by FID',
      );
    }
  }

  Future<ResponseAPDU> selectPassportApplication() async {
    // Finally reselect the eMRTD application so the rest of the reading
    // works as normal
    tagReaderLog.fine('Re-selecting eMRTD Application');
    final cmd = CommandAPDU(
      instructionClass: 0x00,
      instructionCode: 0xA4,
      p1Parameter: 0x04,
      p2Parameter: 0x0C,
      data: const [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01],
      expectedResponseLength: -1,
    );
    return send(cmd);
  }

  Future<ResponseAPDU> selectFile(List<int> tag) async {
    final data = [0x00, 0xA4, 0x02, 0x0C, 0x02, ...tag];
    final cmd = CommandAPDU.parse(data);
    return send(cmd);
  }

  Future<ResponseAPDU> send(CommandAPDU cmd, {bool useExtendedMode = false}) {
    lastRefusal = null;
    return _send(
      cmd,
      useExtendedMode: useExtendedMode,
      wrongLengthRetried: false,
    );
  }

  Future<ResponseAPDU> _send(
    CommandAPDU cmd, {
    required bool useExtendedMode,
    required bool wrongLengthRetried,
  }) async {
    tagReaderLog.fine('TagReader - sending $cmd');
    var toSend = cmd;
    final sm = secureMessaging;
    if (sm != null) {
      toSend = sm.protect(cmd, useExtendedMode: useExtendedMode);
      tagReaderLog.fine('TagReader - [SM] $toSend');
    }

    // Never hand an extended-length APDU to a transport that hasn't
    // declared support; the stack would mangle it.
    if (toSend.requiresExtendedLength &&
        !_transceiver.isExtendedLengthApduSupported) {
      lastRefusal = TransportRefusal.extendedLengthUnsupported;
      throw const InvalidDataPassed(
        'extended-length APDU not supported by transport',
      );
    }

    // Nor one longer than the transport's declared cap.
    // Android's NFC service refuses it before it reaches the tag, with an
    // IOException the plugin reports as a lost tag, so without this check an
    // oversized command and a dropped connection look the same.
    final wire = toSend.encode();
    if (wire.length > _transceiver.maxTransceiveLength) {
      lastRefusal = TransportRefusal.exceedsTransceiveLength;
      throw InvalidDataPassed(
        'APDU of ${wire.length} bytes exceeds the transport limit of '
        '${_transceiver.maxTransceiveLength}',
      );
    }

    var response = ResponseAPDU.fromBytes(await _transceiver.transceive(wire));
    final data = <int>[...response.data];
    var sw1 = response.sw1;
    var sw2 = response.sw2;
    tagReaderLog.fine('TagReader - Received response, size ${data.length}b');

    // Some commands may have bigger response than expected. Read the whole
    // response using INS 0xC0 (GET RESPONSE). The chunks are transport
    // fragments; sent raw (outside SM) and concatenated before the single
    // unprotect below (TR-03110-3 App E).
    while (sw1 == 0x61) {
      // sw2 == 0 means the remaining count is not encoded (TR-03110-3
      // E.2); ask for the short-form maximum. Upstream passes Int(0) to
      // CoreNFC with unobservable effect.
      final getResponseCmd = CommandAPDU(
        instructionClass: 0x00,
        instructionCode: 0xC0,
        p1Parameter: 0x00,
        p2Parameter: 0x00,
        data: const [],
        expectedResponseLength: sw2 == 0 ? 256 : sw2,
      );
      final next = ResponseAPDU.fromBytes(
        await _transceiver.transceive(getResponseCmd.encode()),
      );
      // Overwrite sw1 and sw2.
      sw1 = next.sw1;
      sw2 = next.sw2;
      tagReaderLog.fine(
        'Read remaining data. Accumulated: '
        '${data.length + next.data.length}b. Last batch '
        '${next.data.length}b. Still remaining: ${sw2}b',
      );
      data.addAll(next.data);
    }

    var rep = ResponseAPDU(Uint8List.fromList(data), sw1, sw2);

    if (sm != null) {
      rep = sm.unprotect(rep);
      tagReaderLog.fine(
        'TagReader [SM - unprotected] '
        '${binToHexRep(rep.data, asArray: true)}, sw1:0x${_hex2(rep.sw1)} '
        'sw2:0x${_hex2(rep.sw2)}',
      );
    } else {
      tagReaderLog.fine(
        'TagReader [unprotected] ${binToHexRep(rep.data, asArray: true)}, '
        'sw1:0x${_hex2(rep.sw1)} sw2:0x${_hex2(rep.sw2)}',
      );
    }

    // Upstream's `sw1 != 0x90 && sw2 != 0x00` lets any SW ending 00
    // (63 00 failed auth, 67 00 wrong length) pass as success.
    if (rep.sw1 == 0x90 && rep.sw2 == 0x00) {
      return rep;
    }

    // 6C XX = wrong Le, SW2 states the exact length; retry once with
    // Le = XX through the full pipeline (fresh protect under SM). A second
    // 6C falls through to ResponseError. Runs on the effective
    // (post-unprotect) SW.
    if (rep.sw1 == 0x6C && !wrongLengthRetried) {
      return _send(
        cmd.withExpectedResponseLength(rep.sw2 == 0 ? 256 : rep.sw2),
        useExtendedMode: useExtendedMode,
        wrongLengthRetried: true,
      );
    }

    // End of file reached before Le bytes is a valid partial read on READ
    // BINARY. Return it unthrown; the read loop terminates on it. On any
    // other INS it stays an error.
    if (rep.sw1 == 0x62 && rep.sw2 == 0x82 && cmd.instructionCode == 0xB0) {
      return rep;
    }

    tagReaderLog.severe(
      'Error reading tag: sw1 - 0x${binToHexRepByte(rep.sw1)}'
      ', sw2 - 0x${binToHexRepByte(rep.sw2)}',
    );
    // 63 XX on EXTERNAL/MUTUAL AUTHENTICATE (INS 82) is an
    // authentication failure; covers the ISO 63 CX retry-counter range
    // (some chips always answer 63 CF). On GENERAL AUTHENTICATE
    // (INS 86) the password may be CAN/PIN, so the PACE layer owns that
    // mapping; on other INS 63 XX is not auth-related. Both fall through.
    if (rep.sw1 == 0x63 && cmd.instructionCode == 0x82) {
      throw const InvalidMRZKey();
    }
    final errorMsg = decodeError(rep.sw1, rep.sw2);
    tagReaderLog.severe('reason: $errorMsg');
    // Upstream constructs this with the raw pre-unprotect sw1/sw2 while the
    // check and message use the unprotected values, indistinguishable
    // without SM; the port stays self-consistent (rep).
    throw ResponseError(errorMsg, rep.sw1, rep.sw2);
  }

  String _hex2(int v) => v.toRadixString(16).padLeft(2, '0');
}

/// The largest READ BINARY length `N ≤ requested` whose response frame fits
/// [maxTransceiveLength], secure messaging included.
///
/// Without secure messaging ([smBlockSize] null) the frame is `N + 2` (data
/// plus SW1/SW2). Under secure messaging it is
/// `DO87 ‖ DO99 ‖ DO8E ‖ SW` = `1 + L + 1 + pad(N) + 4 + 10 + 2`, where
/// `pad(N)` is ISO 9797-1 method-2 padding to the cipher block ([smBlockSize]
/// = 8 for 3DES, 16 for AES; always at least one byte, a whole block when
/// `N` is block-aligned), `L` the BER length width of the DO87 content
/// (`1 + pad(N)`: one byte below 128, two up to 255, three above), and the
/// MAC truncated to 8 bytes for both ciphers. Never below 1; total.
///
/// At the 261-byte constant and 223 requested this yields 223 under either
/// cipher (244-byte frames); at 253 it yields 223 (AES) / 231 (3DES); at
/// 1024 requested it needs 1061 bytes of frame under AES: the
/// extended-length shape, where `L = 3` falls out of the same formula.
int fitReadLength({
  required int requested,
  required int maxTransceiveLength,
  required int? smBlockSize,
}) {
  int frameLength(int n) {
    if (smBlockSize == null) {
      return n + 2;
    }
    final padded = (n ~/ smBlockSize + 1) * smBlockSize;
    final do87Content = 1 + padded;
    final lengthWidth = do87Content < 0x80
        ? 1
        : do87Content <= 0xFF
        ? 2
        : 3;
    return 1 + lengthWidth + do87Content + 4 + 10 + 2;
  }

  for (var n = requested; n > 1; n--) {
    if (frameLength(n) <= maxTransceiveLength) {
      return n;
    }
  }
  return 1;
}

/// Upstream `decodeError` (private there; top-level here so conformance
/// vectors can pin the table). Message strings byte-identical to upstream
/// for log-diffing, except the two corrected rows: upstream's `0x63/0x0C`
/// dictionary key is proper `63 CX` counter-range handling below, and the
/// stray `]` in the `6B 00` message is dropped.
String decodeError(int sw1, int sw2) {
  const errors = <int, Map<int, String>>{
    0x62: {
      0x00: 'No information given',
      0x81: 'Part of returned data may be corrupted',
      0x82: 'End of file/record reached before reading Le bytes',
      0x83: 'Selected file invalidated',
      0x84: 'FCI not formatted according to ISO7816-4 section 5.1.5',
    },
    0x63: {
      0x81: 'File filled up by the last write',
      0x82: 'Card Key not supported',
      0x83: 'Reader Key not supported',
      0x84: 'Plain transmission not supported',
      0x85: 'Secured Transmission not supported',
      0x86: 'Volatile memory not available',
      0x87: 'Non Volatile memory not available',
      0x88: 'Key number not valid',
      0x89: 'Key length is not correct',
    },
    0x65: {0x00: 'No information given', 0x81: 'Memory failure'},
    0x67: {0x00: 'Wrong length'},
    0x68: {
      0x00: 'No information given',
      0x81: 'Logical channel not supported',
      0x82: 'Secure messaging not supported',
      0x83: 'Last command of the chain expected',
      0x84: 'Command chaining not supported',
    },
    0x69: {
      0x00: 'No information given',
      0x81: 'Command incompatible with file structure',
      0x82: 'Security status not satisfied',
      0x83: 'Authentication method blocked',
      0x84: 'Referenced data invalidated',
      0x85: 'Conditions of use not satisfied',
      0x86: 'Command not allowed (no current EF)',
      0x87: 'Expected SM data objects missing',
      0x88: 'SM data objects incorrect',
    },
    0x6A: {
      0x00: 'No information given',
      0x80: 'Incorrect parameters in the data field',
      0x81: 'Function not supported',
      0x82: 'File not found',
      0x83: 'Record not found',
      0x84: 'Not enough memory space in the file',
      0x85: 'Lc inconsistent with TLV structure',
      0x86: 'Incorrect parameters P1-P2',
      0x87: 'Lc inconsistent with P1-P2',
      0x88: 'Referenced data not found',
    },
    0x6B: {
      // Upstream's message carries a stray trailing `]`, dropped here.
      0x00: 'Wrong parameter(s) P1-P2',
    },
    0x6D: {0x00: 'Instruction code not supported or invalid'},
    0x6E: {0x00: 'Class not supported'},
    0x6F: {0x00: 'No precise diagnosis'},
    0x90: {0x00: 'Success'}, // No further qualification
  };

  // Special cases - where sw2 isn't an error but contains a value
  if (sw1 == 0x61) {
    return 'SW2 indicates the number of response bytes still available - '
        '($sw2 bytes still available)';
  } else if (sw1 == 0x64) {
    return 'State of non-volatile memory unchanged (SW2=00, other values '
        'are RFU)';
  } else if (sw1 == 0x6C) {
    return 'Wrong length Le: SW2 indicates the exact length - '
        '(exact length :$sw2)';
  } else if (sw1 == 0x63 && (sw2 & 0xF0) == 0xC0) {
    // Upstream keys this row on sw2 == 0x0C; the ISO range is 63 CX.
    return 'Counter provided by X (valued from 0 to 15) (exact meaning '
        'depending on the command)';
  }

  final errorMsg = errors[sw1]?[sw2];
  if (errorMsg != null) {
    return errorMsg;
  }

  return 'Unknown error - sw1: 0x${binToHexRepByte(sw1)}, '
      'sw2 - 0x${binToHexRepByte(sw2)} ';
}
