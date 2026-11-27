/// Conformance runner (Dart side).
///
/// Enumerates `conformance/vectors/*.json`, validates `schemaVersion`,
/// dispatches each case through the op registry, and asserts deep equality on
/// `expect.out` or the thrown error code on `expect.error`. One `test()` per
/// case, so failures are readable. New ops go ONLY into the registry (and
/// the op table in conformance/SCHEMA.md).
///
/// Product ops throw the package error hierarchy ([EmrtdException]), whose
/// codes are upstream case names; dart-only guard rejections surface as
/// [ArgumentError], matched by the vector code `ArgumentError` (SCHEMA.md).
///
/// Runs under `flutter test` from the package root (CI does exactly that).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/ciphers.dart' as ciphers;
import 'package:emrtd_core/src/crypto/ec_dh.dart' as ec_dh;
import 'package:emrtd_core/src/crypto/hashes.dart' as hashes;
import 'package:emrtd_core/src/crypto/kdf.dart';
import 'package:emrtd_core/src/crypto/mac.dart' as macs;
import 'package:emrtd_core/src/crypto/rng.dart';
import 'package:emrtd_core/src/errors.dart';
import 'package:emrtd_core/src/lds/active_authentication_info.dart';
import 'package:emrtd_core/src/lds/atr_info.dart';
import 'package:emrtd_core/src/lds/card_access.dart';
import 'package:emrtd_core/src/lds/chip_authentication_info.dart';
import 'package:emrtd_core/src/lds/chip_authentication_public_key_info.dart';
import 'package:emrtd_core/src/lds/com.dart';
import 'package:emrtd_core/src/lds/data_group.dart';
import 'package:emrtd_core/src/lds/data_group1.dart';
import 'package:emrtd_core/src/lds/data_group11.dart';
import 'package:emrtd_core/src/lds/data_group12.dart';
import 'package:emrtd_core/src/lds/data_group14.dart';
import 'package:emrtd_core/src/lds/data_group15.dart';
import 'package:emrtd_core/src/lds/data_group2.dart';
import 'package:emrtd_core/src/lds/data_group7.dart';
import 'package:emrtd_core/src/lds/data_group_id.dart';
import 'package:emrtd_core/src/lds/data_group_parser.dart';
import 'package:emrtd_core/src/lds/face_image_info.dart';
import 'package:emrtd_core/src/lds/not_implemented_dg.dart';
import 'package:emrtd_core/src/lds/pace_info.dart';
import 'package:emrtd_core/src/lds/security_info.dart';
import 'package:emrtd_core/src/lds/sod.dart';
import 'package:emrtd_core/src/lds/sod_hash_oracle.dart';
import 'package:emrtd_core/src/lds/subject_public_key_info.dart';
import 'package:emrtd_core/src/lds/tlv.dart';
import 'package:emrtd_core/src/pki/csca_trust_store.dart';
import 'package:emrtd_core/src/pki/passive_auth.dart';
import 'package:emrtd_core/src/pki/x509_certificate.dart';
import 'package:emrtd_core/src/proto/active_authentication.dart';
import 'package:emrtd_core/src/proto/bac.dart';
import 'package:emrtd_core/src/proto/chip_authentication.dart';
import 'package:emrtd_core/src/proto/pace.dart' as pace;
import 'package:emrtd_core/src/proto/command_apdu.dart';
import 'package:emrtd_core/src/proto/response_apdu.dart';
import 'package:emrtd_core/src/proto/secure_messaging.dart';
import 'package:emrtd_core/src/proto/tag_reader.dart';
import 'package:emrtd_core/src/transport/transceiver.dart';
import 'package:emrtd_core/src/utils.dart' as utils;
import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart';
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;

/// Ops are `FutureOr`: the `apdu.response`/`apdu.commandBuild` ops drive the
/// async `TagReader.send` pipeline. Pure ops stay synchronous.
typedef ConformanceOp =
    FutureOr<Map<String, Object?>> Function(Map<String, Object?> input);

/// Op registry: dispatch key is the case's `op` field. Every entry has a row
/// in conformance/SCHEMA.md. An op missing here fails the case (never skips):
/// runner updates must accompany new vectors.
final Map<String, ConformanceOp> _ops = {
  'asn1Length': _opAsn1Length,
  'toAsn1Length': _opToAsn1Length,
  'tlvRecord.encode': _opTlvEncode,
  'tlvRecord.fromRecords': _opTlvFromRecords,
  'tlvRecord.parse': _opTlvParse,
  'tlvRecord.sequenceOfRecords': _opTlvSequence,
  'wrapDO': _opWrapDO,
  'unwrapDO': _opUnwrapDO,
  'oid.encode': _opOidEncode,
  'oid.toBytes': _opOidToBytes,
  'oid.decode': _opOidDecode,
  'pad': _opPad,
  'unpad': _opUnpad,
  'hexRepToBin': _opHexRepToBin,
  'intToBin': _opIntToBin,
  'binToInt': _opBinToInt,
  'binToHexBytes': _opBinToHexBytes,
  'intToBytes': _opIntToBytes,
  'xor': _opXor,
  'binToHexRep': _opBinToHexRep,
  // Crypto ops.
  'aesEncrypt': _opAesEncrypt,
  'aesDecrypt': _opAesDecrypt,
  'aesECBEncrypt': _opAesECBEncrypt,
  'tripleDESEncrypt': _opTripleDESEncrypt,
  'tripleDESDecrypt': _opTripleDESDecrypt,
  'desEncrypt': _opDesEncrypt,
  'desDecrypt': _opDesDecrypt,
  'desMAC': _opDesMAC,
  'aesMAC': _opAesMAC,
  'mac': _opMac,
  'calcHash': _opCalcHash,
  'deriveKey': _opDeriveKey,
  'bigIntToBytes': _opBigIntToBytes,
  'bytesToBigInt': _opBytesToBigInt,
  'ecPublicFromPrivate': _opEcPublicFromPrivate,
  'ecdhSharedSecretX': _opEcdhSharedSecretX,
  'ecPointDecode': _opEcPointDecode,
  'ecMulAdd': _opEcMulAdd,
  'ecPointMul': _opEcPointMul,
  'dhPublic': _opDhPublic,
  'dhSharedSecret': _opDhSharedSecret,
  // Transport/APDU ops.
  'apdu.encode': _opApduEncode,
  'apdu.parse': _opApduParse,
  'apdu.response': _opApduResponse,
  'apdu.statusMessages': _opApduStatusMessages,
  'apdu.commandBuild': _opApduCommandBuild,
  'readLength.fit': _opReadLengthFit,
  'atrInfo.parse': _opAtrInfoParse,
  // BAC / secure-messaging ops.
  'sm.protect': _opSmProtect,
  'sm.unprotect': _opSmUnprotect,
  'sm.exchange': _opSmExchange,
  'bac.generateInitialKseed': _opBacGenerateInitialKseed,
  'bac.deriveDocumentBasicAccessKeys': _opBacDeriveDocumentBasicAccessKeys,
  'bac.authentication': _opBacAuthentication,
  'bac.sessionKeys': _opBacSessionKeys,
  'bac.composeMrzKey': _opBacComposeMrzKey,
  // PACE / CardAccess ops.
  'pace.createPaceKey': _opPaceCreatePaceKey,
  'pace.camDecryptChipAuthenticationData': _opPaceCamDecrypt,
  'pace.camVerifyChipAuthenticationData': _opPaceCamVerify,
  'pace.encodePublicKey': _opPaceEncodePublicKey,
  'pace.generateAuthenticationToken': _opPaceGenerateAuthenticationToken,
  'pace.dhMappedGenerator': _opPaceDhMappedGenerator,
  // DH Generic Mapping and Integrated Mapping ops.
  'pace.dhSharedSecretBytes': _opPaceDhSharedSecretBytes,
  'pace.validateDhPublicKey': _opPaceValidateDhPublicKey,
  'pace.imPseudoRandom': _opPaceImPseudoRandom,
  'pace.imMapDh': _opPaceImMapDh,
  'pace.imMapEcdh': _opPaceImMapEcdh,
  'paceInfo.protocolOIDString': _opPaceInfoProtocolOIDString,
  'paceInfo.oidInfo': _opPaceInfoOidInfo,
  'paceInfo.parameterSpec': _opPaceInfoParameterSpec,
  'cardAccess.securityInfos': _opCardAccessSecurityInfos,
  'cardAccess.paceInfo': _opCardAccessPaceInfo,
  // Chip Authentication / DG14 ops.
  'chipAuthInfo.oidInfo': _opChipAuthInfoOidInfo,
  'chipAuthPublicKeyInfo.protocolOIDString': _opChipAuthPublicKeyInfoOidString,
  'spki.publicKeyData': _opSpkiPublicKeyData,
  'chipAuth.deriveSessionKeys': _opChipAuthDeriveSessionKeys,
  'chipAuth.inferOid': _opChipAuthInferOid,
  'dg14.securityInfos': _opDg14SecurityInfos,
  // Active Authentication / DG15 ops.
  'aaInfo.signatureAlgorithm': _opAaInfoSignatureAlgorithm,
  'aaInfo.protocolOIDString': _opAaInfoProtocolOIDString,
  'dg15.parse': _opDg15Parse,
  'aa.verify': _opAaVerify,
  // LDS / SOD-oracle ops.
  'dg.parseDG': _opDgParseDG,
  'dg.hash': _opDgHash,
  'com.parse': _opComParse,
  'dg1.parse': _opDg1Parse,
  'dg2.parse': _opDg2Parse,
  'dg2.faceImageFormat': _opDg2FaceImageFormat,
  'dg2.encoding': _opDg2Encoding,
  // Extended data-group ops.
  'dg7.parse': _opDg7Parse,
  'dg7.imageFormat': _opDg7ImageFormat,
  'dg11.parse': _opDg11Parse,
  'dg11.otherNames': _opDg11OtherNames,
  'dg12.parse': _opDg12Parse,
  'dg12.otherPersons': _opDg12OtherPersons,
  'faceImageInfo.from': _opFaceImageInfoFrom,
  'sod.parse': _opSodParse,
  'sod.encapsulatedContent': _opSodEncapsulatedContent,
  'sod.parseSignatureContent': _opSodParseSignatureContent,
  'sod.ldsVersionInfo': _opSodLdsVersionInfo,
  'sod.checkDataGroupHashes': _opSodCheckDataGroupHashes,
  // Passive-authentication ops.
  'pa.sodSignature': _opPaSodSignature,
  'pa.sodSignature.detail': _opPaSodSignatureDetail,
  'pa.trust': _opPaTrust,
  'pa.trust.detail': _opPaTrustDetail,
  'pa.verify': _opPaVerify,
  'pa.verdict': _opPaVerdict,
  'pa.masterList': _opPaMasterList,
  'x509.parse': _opX509Parse,
};

// --- harness hex/tag codec (strict; NOT the product helpers under test) ----

List<int> _bytes(Object? hex) {
  final s = hex! as String;
  if (s.length.isOdd) {
    fail('vector hex value has odd length: "$s"');
  }
  return [
    for (var i = 0; i < s.length; i += 2)
      int.parse(s.substring(i, i + 2), radix: 16),
  ];
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Tags travel as hex strings in vectors (SCHEMA.md); the API takes the raw
/// tag bytes' big-endian value as an int.
int _tag(Object? hex) => int.parse(hex! as String, radix: 16);

String _tagHex(int tag) {
  var s = tag.toRadixString(16);
  if (s.length.isOdd) {
    s = '0$s';
  }
  return s;
}

Map<String, Object?> _recordMap(TlvRecord r) => {
  'tag': _tagHex(r.tag),
  'value': _hex(r.value),
};

// --- tlv suite ops ---------------------------------------------------------

Map<String, Object?> _opAsn1Length(Map<String, Object?> input) {
  final (length, lengthBytes) = asn1Length(_bytes(input['data']));
  return {'length': length, 'lengthBytes': lengthBytes};
}

Map<String, Object?> _opToAsn1Length(Map<String, Object?> input) => {
  'data': _hex(toAsn1Length(input['length']! as int)),
};

Map<String, Object?> _opTlvEncode(Map<String, Object?> input) => {
  'data': _hex(TlvRecord(_tag(input['tag']), _bytes(input['value'])).data),
};

Map<String, Object?> _opTlvFromRecords(Map<String, Object?> input) {
  final children = (input['records']! as List)
      .map((r) => (r as Map).cast<String, Object?>())
      .map((r) => TlvRecord(_tag(r['tag']), _bytes(r['value'])))
      .toList();
  return {
    'data': _hex(TlvRecord.fromRecords(_tag(input['tag']), children).data),
  };
}

Map<String, Object?> _opTlvParse(Map<String, Object?> input) {
  final rec = TlvRecord.parse(_bytes(input['data']));
  return {'record': rec == null ? null : _recordMap(rec)};
}

Map<String, Object?> _opTlvSequence(Map<String, Object?> input) {
  final recs = TlvRecord.sequenceOfRecords(_bytes(input['data']));
  return {'records': recs?.map(_recordMap).toList()};
}

Map<String, Object?> _opWrapDO(Map<String, Object?> input) => {
  'data': _hex(wrapDO(_tag(input['tag']), _bytes(input['value']))),
};

Map<String, Object?> _opUnwrapDO(Map<String, Object?> input) => {
  'value': _hex(unwrapDO(_tag(input['tag']), _bytes(input['data']))),
};

Map<String, Object?> _opOidEncode(Map<String, Object?> input) => {
  'data': _hex(asn1EncodeOid(input['oid']! as String)),
};

Map<String, Object?> _opOidToBytes(Map<String, Object?> input) => {
  'data': _hex(
    oidToBytes(
      input['oid']! as String,
      replaceTag: input['replaceTag']! as bool,
    ),
  ),
};

Map<String, Object?> _opOidDecode(Map<String, Object?> input) => {
  'oid': asn1DecodeOid(_bytes(input['data'])),
};

Map<String, Object?> _opPad(Map<String, Object?> input) => {
  'data': _hex(
    utils.pad(_bytes(input['data']), blockSize: input['blockSize']! as int),
  ),
};

Map<String, Object?> _opUnpad(Map<String, Object?> input) => {
  'data': _hex(utils.unpad(_bytes(input['data']))),
};

Map<String, Object?> _opHexRepToBin(Map<String, Object?> input) => {
  'data': _hex(utils.hexRepToBin(input['hex']! as String)),
};

Map<String, Object?> _opIntToBin(Map<String, Object?> input) => {
  'data': _hex(
    utils.intToBin(input['value']! as int, pad: input['pad']! as int),
  ),
};

Map<String, Object?> _opBinToInt(Map<String, Object?> input) => {
  'value': utils.binToInt(_bytes(input['data'])),
};

Map<String, Object?> _opBinToHexBytes(Map<String, Object?> input) => {
  'value': utils.binToHexBytes(_bytes(input['data'])),
};

Map<String, Object?> _opIntToBytes(Map<String, Object?> input) => {
  'data': _hex(
    utils.intToBytes(
      input['value']! as int,
      removePadding: input['removePadding']! as bool,
    ),
  ),
};

Map<String, Object?> _opXor(Map<String, Object?> input) => {
  'data': _hex(utils.xor(_bytes(input['a']), _bytes(input['b']))),
};

Map<String, Object?> _opBinToHexRep(Map<String, Object?> input) => {
  'rep': utils.binToHexRep(
    _bytes(input['data']),
    asArray: input['asArray']! as bool,
  ),
};

// --- crypto suite ops ------------------------------------------------------

/// BigInts travel as minimal-form hex in vectors ("" = zero), parsed and
/// formatted by the harness, independent of the product helpers under test.
BigInt _bigInt(Object? hex) {
  final s = hex! as String;
  return s.isEmpty ? BigInt.zero : BigInt.parse(s, radix: 16);
}

String _bigIntHex(BigInt v) {
  if (v == BigInt.zero) {
    return '';
  }
  var s = v.toRadixString(16);
  if (s.length.isOdd) {
    s = '0$s';
  }
  return s;
}

ECDomainParameters _curve(Object? name) => ECDomainParameters(name! as String);

/// Harness-side point plumbing for op *inputs* (raw pointycastle decode, not
/// the validated product `ecPointDecode`, which has its own op and cases).
ECPoint _point(ECDomainParameters curve, Object? hex) =>
    curve.curve.decodePoint(_bytes(hex))!;

Map<String, Object?> _opAesEncrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.aesEncrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      _bytes(input['iv']),
    ),
  ),
};

Map<String, Object?> _opAesDecrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.aesDecrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      _bytes(input['iv']),
    ),
  ),
};

Map<String, Object?> _opAesECBEncrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.aesECBEncrypt(_bytes(input['key']), _bytes(input['message'])),
  ),
};

Map<String, Object?> _opTripleDESEncrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.tripleDESEncrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      _bytes(input['iv']),
    ),
  ),
};

Map<String, Object?> _opTripleDESDecrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.tripleDESDecrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      _bytes(input['iv']),
    ),
  ),
};

Map<String, Object?> _opDesEncrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.desEncrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      _bytes(input['iv']),
      ecb: input['ecb']! as bool,
    ),
  ),
};

Map<String, Object?> _opDesDecrypt(Map<String, Object?> input) => {
  'data': _hex(
    ciphers.desDecrypt(
      _bytes(input['key']),
      _bytes(input['message']),
      ecb: input['ecb']! as bool,
    ),
  ),
};

Map<String, Object?> _opDesMAC(Map<String, Object?> input) => {
  'mac': _hex(
    macs.desMAC(key: _bytes(input['key']), msg: _bytes(input['msg'])),
  ),
};

Map<String, Object?> _opAesMAC(Map<String, Object?> input) => {
  'mac': _hex(
    macs.aesMAC(key: _bytes(input['key']), msg: _bytes(input['msg'])),
  ),
};

Map<String, Object?> _opMac(Map<String, Object?> input) {
  final algo = switch (input['algoName']! as String) {
    'DES' => macs.SecureMessagingSupportedAlgorithms.des,
    'AES' => macs.SecureMessagingSupportedAlgorithms.aes,
    final other => fail('unknown algoName "$other"'),
  };
  return {
    'mac': _hex(
      macs.mac(
        algoName: algo,
        key: _bytes(input['key']),
        msg: _bytes(input['msg']),
      ),
    ),
  };
}

Map<String, Object?> _opCalcHash(Map<String, Object?> input) => {
  'hash': _hex(
    hashes.calcHash(_bytes(input['data']), input['algorithm']! as String),
  ),
};

Map<String, Object?> _opDeriveKey(Map<String, Object?> input) {
  final mode = switch (input['mode']! as String) {
    'ENC' => SMSMode.encMode,
    'MAC' => SMSMode.macMode,
    'PACE' => SMSMode.paceMode,
    final other => fail('unknown mode "$other"'),
  };
  final nonce = input['nonce'];
  return {
    'key': _hex(
      const SecureMessagingSessionKeyGenerator().deriveKey(
        keySeed: _bytes(input['keySeed']),
        cipherAlgName: input['cipherAlgName'] as String? ?? 'DESede',
        keyLength: input['keyLength'] as int? ?? 128,
        nonce: nonce == null ? null : _bytes(nonce),
        mode: mode,
        paceKeyReference:
            input['paceKeyReference'] as int? ??
            SecureMessagingSessionKeyGenerator.noPaceKeyReference,
      ),
    ),
  };
}

Map<String, Object?> _opBigIntToBytes(Map<String, Object?> input) => {
  'data': _hex(
    ec_dh.bigIntToBytes(
      _bigInt(input['value']),
      length: input['length'] as int?,
    ),
  ),
};

Map<String, Object?> _opBytesToBigInt(Map<String, Object?> input) => {
  'value': _bigIntHex(ec_dh.bytesToBigInt(_bytes(input['data']))),
};

Map<String, Object?> _opEcPublicFromPrivate(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'point': _hex(
      ec_dh.ecPointEncode(
        ec_dh.ecPublicFromPrivate(curve, _bigInt(input['d'])),
      ),
    ),
  };
}

Map<String, Object?> _opEcdhSharedSecretX(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'secret': _hex(
      ec_dh.ecdhSharedSecretX(
        curve,
        _bigInt(input['d']),
        _point(curve, input['peer']),
      ),
    ),
  };
}

Map<String, Object?> _opEcPointDecode(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'point': _hex(
      ec_dh.ecPointEncode(ec_dh.ecPointDecode(curve, _bytes(input['encoded']))),
    ),
  };
}

Map<String, Object?> _opEcMulAdd(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'point': _hex(
      ec_dh.ecPointEncode(
        ec_dh.ecMulAdd(
          curve,
          _bigInt(input['s']),
          _point(curve, input['g']),
          _point(curve, input['h']),
        ),
      ),
    ),
  };
}

Map<String, Object?> _opEcPointMul(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'point': _hex(
      ec_dh.ecPointEncode(
        ec_dh.ecPointMul(
          curve,
          _bigInt(input['d']),
          _point(curve, input['point']),
        ),
      ),
    ),
  };
}

Map<String, Object?> _opDhPublic(Map<String, Object?> input) => {
  'y': _bigIntHex(
    ec_dh.dhPublic(
      _bigInt(input['p']),
      _bigInt(input['g']),
      _bigInt(input['x']),
    ),
  ),
};

Map<String, Object?> _opDhSharedSecret(Map<String, Object?> input) => {
  'secret': _bigIntHex(
    ec_dh.dhSharedSecret(
      _bigInt(input['p']),
      _bigInt(input['x']),
      _bigInt(input['peerPublic']),
    ),
  ),
};

// --- transport/APDU suite ops ----------------------------------------------

String _hexByte(int b) => b.toRadixString(16).padLeft(2, '0');

/// Structured-command codec shared by the apdu ops: CLA/INS/P1/P2 travel as
/// hex bytes, `data` as a hex string, `le` as a JSON number (-1/null =
/// absent: CoreNFC's `expectedResponseLength` semantics).
Map<String, Object?> _cmdToMap(CommandAPDU c) => {
  'cla': _hexByte(c.instructionClass),
  'ins': _hexByte(c.instructionCode),
  'p1': _hexByte(c.p1Parameter),
  'p2': _hexByte(c.p2Parameter),
  'data': _hex(c.data),
  'le': c.expectedResponseLength,
};

CommandAPDU _cmdFromMap(Map<String, Object?> m) => CommandAPDU(
  instructionClass: int.parse(m['cla']! as String, radix: 16),
  instructionCode: int.parse(m['ins']! as String, radix: 16),
  p1Parameter: int.parse(m['p1']! as String, radix: 16),
  p2Parameter: int.parse(m['p2']! as String, radix: 16),
  data: _bytes(m['data']),
  expectedResponseLength: (m['le'] as num?)?.toInt() ?? -1,
);

/// Serves canned data‖SW frames in order without asserting commands;
/// command-shape assertions are the transcript layer's job.
class _CannedTransceiver implements NfcTransceiver {
  _CannedTransceiver(this._responses);

  final List<Uint8List> _responses;
  int _next = 0;

  bool get exhausted => _next == _responses.length;

  @override
  int get maxTransceiveLength => 261;

  @override
  bool get isExtendedLengthApduSupported => false;

  @override
  Uint8List? get historicalBytes => null;

  @override
  TagCapabilities? get tagCapabilities => null;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    if (_next >= _responses.length) {
      fail('canned responses exhausted after $_next transceive(s)');
    }
    return _responses[_next++];
  }
}

/// Records every wire frame and answers each with the same canned response.
class _CapturingTransceiver implements NfcTransceiver {
  _CapturingTransceiver(this._response);

  final Uint8List _response;
  final List<Uint8List> sent = [];

  @override
  int get maxTransceiveLength => 261;

  @override
  bool get isExtendedLengthApduSupported => false;

  @override
  Uint8List? get historicalBytes => null;

  @override
  TagCapabilities? get tagCapabilities => null;

  @override
  Future<Uint8List> transceive(Uint8List capdu) async {
    sent.add(capdu);
    return _response;
  }
}

Map<String, Object?> _opApduEncode(Map<String, Object?> input) => {
  'wire': _hex(_cmdFromMap(input).encode()),
};

Map<String, Object?> _opApduParse(Map<String, Object?> input) =>
    _cmdToMap(CommandAPDU.parse(_bytes(input['raw'])));

Future<Map<String, Object?>> _opApduResponse(Map<String, Object?> input) async {
  final cmd = _cmdFromMap((input['cmd']! as Map).cast<String, Object?>());
  final responses = (input['responses']! as List)
      .map((r) => (r as Map).cast<String, Object?>())
      .map(
        (r) => Uint8List.fromList([..._bytes(r['data']), ..._bytes(r['sw'])]),
      )
      .toList();
  final transceiver = _CannedTransceiver(responses);
  final rep = await TagReader(transceiver).send(cmd);
  if (!transceiver.exhausted) {
    fail('send() left canned responses unconsumed');
  }
  return {
    'data': _hex(rep.data),
    'sw': _hex([rep.sw1, rep.sw2]),
  };
}

/// The pure chunk fit: the largest read length whose response frame fits.
Map<String, Object?> _opReadLengthFit(Map<String, Object?> input) => {
  'length': fitReadLength(
    requested: input['requested']! as int,
    maxTransceiveLength: input['maxTransceiveLength']! as int,
    smBlockSize: input['smBlockSize'] as int?,
  ),
};

/// The `7F66` walk over an EF.ATR/INFO (or ATS) payload.
Map<String, Object?> _opAtrInfoParse(Map<String, Object?> input) {
  final sizes = parseExtendedLengthInfo(_bytes(input['data']));
  return sizes == null
      ? {'present': false}
      : {
          'present': true,
          'maxCommandBytes': sizes.maxCommandBytes,
          'maxResponseBytes': sizes.maxResponseBytes,
        };
}

Map<String, Object?> _opApduStatusMessages(Map<String, Object?> input) => {
  'message': decodeError(
    int.parse(input['sw1']! as String, radix: 16),
    int.parse(input['sw2']! as String, radix: 16),
  ),
};

Future<Map<String, Object?>> _opApduCommandBuild(
  Map<String, Object?> input,
) async {
  final method = input['method']! as String;
  final args = (input['args']! as Map).cast<String, Object?>();
  // sendGeneralAuthenticate unwraps a 7C DO from the response; everything
  // else just needs 90 00.
  final transceiver = _CapturingTransceiver(
    Uint8List.fromList(
      method == 'sendGeneralAuthenticate'
          ? [0x7C, 0x00, 0x90, 0x00]
          : [0x90, 0x00],
    ),
  );
  final reader = TagReader(transceiver);
  switch (method) {
    case 'getChallenge':
      await reader.getChallenge();
    case 'doMutualAuthentication':
      await reader.doMutualAuthentication(
        Uint8List.fromList(_bytes(args['cmdData'])),
      );
    case 'selectFile':
      await reader.selectFile(_bytes(args['tag']));
    case 'selectPassportApplication':
      await reader.selectPassportApplication();
    case 'sendMSESetATMutualAuth':
      await reader.sendMSESetATMutualAuth(
        oid: args['oid']! as String,
        keyType: args['keyType']! as int,
        parameterId: args['parameterId'] as int?,
      );
    case 'sendGeneralAuthenticate':
      await reader.sendGeneralAuthenticate(
        data: _bytes(args['data']),
        lengthExpected: args['lengthExpected'] as int? ?? 256,
        isLast: args['isLast']! as bool,
      );
    default:
      fail('unknown commandBuild method "$method"');
  }
  if (transceiver.sent.length != 1) {
    fail(
      'commandBuild expects exactly one emitted command, got '
      '${transceiver.sent.length}',
    );
  }
  return _cmdToMap(CommandAPDU.parse(transceiver.sent.single));
}

// --- BAC / secure-messaging suite ops --------------------------------------

/// Response APDUs travel as `{data, sw}` with `sw` = SW1‖SW2 hex (SCHEMA.md).
Map<String, Object?> _rapduToMap(ResponseAPDU r) => {
  'data': _hex(r.data),
  'sw': _hex([r.sw1, r.sw2]),
};

ResponseAPDU _rapduFromMap(Map<String, Object?> m) {
  final sw = _bytes(m['sw']);
  if (sw.length != 2) {
    fail('rapdu sw must be two bytes, got "${m['sw']}"');
  }
  return ResponseAPDU(Uint8List.fromList(_bytes(m['data'])), sw[0], sw[1]);
}

SecureMessaging _smFromInput(Map<String, Object?> input) {
  final algo = switch (input['algo']! as String) {
    'DES' => macs.SecureMessagingSupportedAlgorithms.des,
    'AES' => macs.SecureMessagingSupportedAlgorithms.aes,
    final other => fail('unknown algo "$other"'),
  };
  return SecureMessaging(
    encryptionAlgorithm: algo,
    ksenc: _bytes(input['ksenc']),
    ksmac: _bytes(input['ksmac']),
    ssc: _bytes(input['ssc']),
  );
}

Map<String, Object?> _opSmProtect(Map<String, Object?> input) {
  final protected = _smFromInput(input).protect(
    _cmdFromMap((input['cmd']! as Map).cast<String, Object?>()),
    useExtendedMode: input['useExtendedMode'] as bool? ?? false,
  );
  return _cmdToMap(protected);
}

Map<String, Object?> _opSmUnprotect(Map<String, Object?> input) => _rapduToMap(
  _smFromInput(
    input,
  ).unprotect(_rapduFromMap((input['rapdu']! as Map).cast<String, Object?>())),
);

/// Interleaved protect/unprotect over one session object: the shape a real
/// exchange sequence has, pinning the SSC trajectory across both directions.
Map<String, Object?> _opSmExchange(Map<String, Object?> input) {
  final sm = _smFromInput(input);
  final out = <Map<String, Object?>>[];
  for (final raw in input['exchanges']! as List) {
    final e = (raw as Map).cast<String, Object?>();
    final protected = sm.protect(
      _cmdFromMap((e['cmd']! as Map).cast<String, Object?>()),
      useExtendedMode: e['useExtendedMode'] as bool? ?? false,
    );
    final unprotected = sm.unprotect(
      _rapduFromMap((e['rapdu']! as Map).cast<String, Object?>()),
    );
    out.add({'cmd': _cmdToMap(protected), 'rapdu': _rapduToMap(unprotected)});
  }
  return {'exchanges': out};
}

/// The BAC derivation ops never touch the tag; the reader is a dummy the
/// constructor requires (upstream's for-testing-only `init()` is not ported).
BACHandler _bacHandler({List<int> rng = const []}) => BACHandler(
  tagReader: TagReader(_CannedTransceiver(const [])),
  random: FixedRandom(rng),
);

/// Derives keys and injects RND.IFD ‖ K.IFD for the ops that continue into
/// `authentication` (8 + 16 bytes, in that order).
BACHandler _bacAuthSetup(Map<String, Object?> input) {
  final handler = _bacHandler(
    rng: [..._bytes(input['rndIfd']), ..._bytes(input['kifd'])],
  );
  handler.deriveDocumentBasicAccessKeys(input['mrz']! as String);
  return handler;
}

Map<String, Object?> _opBacGenerateInitialKseed(Map<String, Object?> input) => {
  'kseed': _hex(_bacHandler().generateInitialKseed(input['kmrz']! as String)),
};

Map<String, Object?> _opBacDeriveDocumentBasicAccessKeys(
  Map<String, Object?> input,
) {
  final keys = _bacHandler().deriveDocumentBasicAccessKeys(
    input['mrz']! as String,
  );
  return {'ksenc': _hex(keys.ksenc), 'ksmac': _hex(keys.ksmac)};
}

Map<String, Object?> _opBacAuthentication(Map<String, Object?> input) => {
  'cmdData': _hex(_bacAuthSetup(input).authentication(_bytes(input['rndIcc']))),
};

Map<String, Object?> _opBacSessionKeys(Map<String, Object?> input) {
  final handler = _bacAuthSetup(input);
  handler.authentication(_bytes(input['rndIcc']));
  final session = handler.sessionKeys(_bytes(input['response']));
  return {
    'ksenc': _hex(session.ksenc),
    'ksmac': _hex(session.ksmac),
    'ssc': _hex(session.ssc),
  };
}

Map<String, Object?> _opBacComposeMrzKey(Map<String, Object?> input) => {
  'mrzKey': composeMrzKey(
    documentNumber: input['documentNumber']! as String,
    dateOfBirth: input['dateOfBirth']! as String,
    dateOfExpiry: input['dateOfExpiry']! as String,
  ),
};

// --- PACE / CardAccess suite ops -------------------------------------------

/// PACE public-key input codec: `{kind:"ec", curve, point}` (raw pointycastle
/// decode, not the validated `ecPointDecode`; that has its own ec_dh op) or
/// `{kind:"dh", p, y}`.
PACEPublicKey _pacePublicKey(Map<String, Object?> m) {
  switch (m['kind']! as String) {
    case 'ec':
      final curve = _curve(m['curve']);
      final point = curve.curve.decodePoint(_bytes(m['point']))!;
      return EcdhPublicKey(domain: curve, point: point);
    case 'dh':
      return DhPublicKey(p: _bigInt(m['p']), y: _bigInt(m['y']));
    default:
      return fail('unknown PACE key kind "${m['kind']}"');
  }
}

/// The password codec plus K_π in one op; `keyReference` and
/// `keySeed` are f(π)'s two halves (Table 14 / TR-03110-3 Table 5), `key` the
/// derived K_π. A charset-rejected password throws from the factory, before
/// any derivation (`expect.error`).
Map<String, Object?> _opPaceCreatePaceKey(Map<String, Object?> input) {
  final value = input['password']! as String;
  final password = switch (input['passwordType']! as String) {
    'mrz' => pace.PacePassword.mrz(value),
    'can' => pace.PacePassword.can(value),
    'pin' => pace.PacePassword.pin(value),
    'cuk' => pace.PacePassword.cuk(value),
    final other => fail('unknown password type "$other"'),
  };
  return {
    'keyReference': password.keyReference,
    'keySeed': _hex(password.keySeed),
    'key': _hex(
      pace.paceCreatePaceKey(
        password: password,
        cipherAlgName: input['cipherAlgName'] as String? ?? 'AES',
        keyLength: input['keyLength'] as int? ?? 128,
      ),
    ),
  };
}

/// The 9303-11 §4.4.3.5.3/.4 decrypt. Total by contract: every malformed
/// shape comes back as `{caIc: null, cause: "malformed"}` rather than a throw,
/// because a CAM session's mutual authentication has already succeeded.
Map<String, Object?> _opPaceCamDecrypt(Map<String, Object?> input) {
  final caIc = pace.paceCamDecryptChipAuthenticationData(
    ksEnc: _bytes(input['ksEnc']),
    encryptedData: _bytes(input['encryptedData']),
    groupOrder: _curve(input['curve']).n,
  );
  return {
    'caIc': caIc == null ? null : _hex(caIc),
    'cause': caIc == null ? 'malformed' : null,
  };
}

/// The 9303-11 §4.4.3.5.2 check PK_Map,IC = KA(CA_IC, PK_IC, D_IC).
Map<String, Object?> _opPaceCamVerify(Map<String, Object?> input) {
  final curve = _curve(input['curve']);
  return {
    'verified': pace.paceCamVerifyChipAuthenticationData(
      domain: curve,
      chipAuthenticationValue: _bigInt(input['caIc']),
      chipPublicKey: ec_dh.ecPointDecode(curve, _bytes(input['chipPublicKey'])),
      mappingPublicKey: _bytes(input['mappingPublicKey']),
    ),
  };
}

Map<String, Object?> _opPaceEncodePublicKey(Map<String, Object?> input) => {
  'data': _hex(
    pace.paceEncodePublicKey(
      input['oid']! as String,
      _pacePublicKey((input['key']! as Map).cast<String, Object?>()),
    ),
  ),
};

Map<String, Object?> _opPaceGenerateAuthenticationToken(
  Map<String, Object?> input,
) => {
  'token': _hex(
    pace.paceGenerateAuthenticationToken(
      oid: input['oid']! as String,
      cipherAlg: input['cipherAlg']! as String,
      publicKey: _pacePublicKey((input['key']! as Map).cast<String, Object?>()),
      macKey: _bytes(input['macKey']),
    ),
  ),
};

Map<String, Object?> _opPaceDhMappedGenerator(Map<String, Object?> input) => {
  'ghat': _bigIntHex(
    pace.paceDhMappedGenerator(
      p: _bigInt(input['p']),
      g: _bigInt(input['g']),
      mappingPrivateKey: _bigInt(input['x']),
      peerPublicKeyData: _bytes(input['peerPublic']),
      nonce: _bigInt(input['nonce']),
    ),
  ),
};

Map<String, Object?> _opPaceDhSharedSecretBytes(Map<String, Object?> input) => {
  'secret': _hex(
    pace.paceDhSharedSecretBytes(
      p: _bigInt(input['p']),
      x: _bigInt(input['x']),
      peerPublic: _bigInt(input['peerPublic']),
    ),
  ),
};

Map<String, Object?> _opPaceValidateDhPublicKey(Map<String, Object?> input) => {
  'valid': pace.paceValidateDhPublicKey(
    p: _bigInt(input['p']),
    q: _bigInt(input['q']),
    y: _bigInt(input['y']),
  ),
};

Map<String, Object?> _opPaceImPseudoRandom(Map<String, Object?> input) {
  final out = pace.paceImPseudoRandom(
    s: _bytes(input['s']),
    t: _bytes(input['t']),
    p: _bigInt(input['p']),
    cipherAlg: input['cipherAlg']! as String,
    keyLength: input['keyLength']! as int,
  );
  return {'blocks': _hex(out.blocks), 'value': _bigIntHex(out.value)};
}

Map<String, Object?> _opPaceImMapDh(Map<String, Object?> input) => {
  'ghat': _bigIntHex(
    pace.paceImMapDh(
      p: _bigInt(input['p']),
      q: _bigInt(input['q']),
      x: _bigInt(input['x']),
    ),
  ),
};

Map<String, Object?> _opPaceImMapEcdh(Map<String, Object?> input) => {
  'ghat': _hex(
    ec_dh.ecPointEncode(
      pace.paceImMapEcdh(
        domain: _curve(input['curve']),
        x: _bigInt(input['x']),
      ),
    ),
  ),
};

Map<String, Object?> _opPaceInfoProtocolOIDString(Map<String, Object?> input) =>
    {
      'name': PACEInfo(
        oid: input['oid']! as String,
        version: 2,
        parameterId: null,
      ).getProtocolOIDString(),
    };

Map<String, Object?> _opPaceInfoOidInfo(Map<String, Object?> input) {
  final info = PACEInfo(
    oid: input['oid']! as String,
    version: 2,
    parameterId: null,
  );
  return {
    'mappingType': info.getMappingType().name,
    'keyAgreementAlgorithm': info.getKeyAgreementAlgorithm(),
    'cipherAlgorithm': info.getCipherAlgorithm(),
    'digestAlgorithm': info.getDigestAlgorithm(),
    'keyLength': info.getKeyLength(),
  };
}

Map<String, Object?> _opPaceInfoParameterSpec(Map<String, Object?> input) {
  // getParameterSpec depends only on parameterId; any valid ECDH-GM oid works.
  final info = PACEInfo(
    oid: '0.4.0.127.0.7.2.2.4.2.2',
    version: 2,
    parameterId: input['parameterId'] as int?,
  );
  final spec = info.getParameterSpec();
  return switch (spec) {
    ECStandardizedDomain(:final domain) => {
      'kind': 'ec',
      'curve': domain.domainName,
    },
    DHStandardizedDomain(:final p, :final q, :final g) => {
      'kind': 'dh',
      'p': _bigIntHex(p),
      'q': _bigIntHex(q),
      'g': _bigIntHex(g),
    },
  };
}

Map<String, Object?> _infoMap(SecurityInfo si) => si is PACEInfo
    ? {
        'oid': si.getObjectIdentifier(),
        'version': si.getVersion(),
        'parameterId': si.getParameterId(),
      }
    : {'oid': si.getObjectIdentifier()};

Map<String, Object?> _opCardAccessSecurityInfos(Map<String, Object?> input) => {
  'infos': CardAccess(
    _bytes(input['data']),
  ).securityInfos.map(_infoMap).toList(),
};

Map<String, Object?> _opCardAccessPaceInfo(Map<String, Object?> input) {
  final pi = CardAccess(_bytes(input['data'])).paceInfo;
  return pi == null
      ? {'present': false}
      : {
          'oid': pi.getObjectIdentifier(),
          'version': pi.getVersion(),
          'parameterId': pi.getParameterId(),
        };
}

// --- Chip Authentication / DG14 suite ops ----------------------------------

Map<String, Object?> _opChipAuthInfoOidInfo(Map<String, Object?> input) {
  final oid = input['oid']! as String;
  return {
    'keyAgreementAlgorithm': ChipAuthenticationInfo.toKeyAgreementAlgorithm(
      oid,
    ),
    'cipherAlgorithm': ChipAuthenticationInfo.toCipherAlgorithm(oid),
    'keyLength': ChipAuthenticationInfo.toKeyLength(oid),
    'protocolOIDString': ChipAuthenticationInfo(
      oid: oid,
      version: 1,
    ).getProtocolOIDString(),
  };
}

Map<String, Object?> _opChipAuthPublicKeyInfoOidString(
  Map<String, Object?> input,
) => {
  'name': ChipAuthenticationPublicKeyInfo(
    oid: input['oid']! as String,
    pubKey: SpkiDhPublicKey(
      Uint8List(0),
      p: BigInt.one,
      g: BigInt.one,
      y: BigInt.one,
    ),
  ).getProtocolOIDString(),
};

/// The `EC_GROUP`/`DH` domain summary both runners can produce: prime-field
/// parameters as minimal big-endian hex, the generator uncompressed.
Map<String, Object?> _ecDomainMap(ECDomainParameters d) {
  final c = d.curve as fp.ECCurve;
  return {
    'p': _bigIntHex(c.q!),
    'a': _bigIntHex(c.a!.toBigInteger()!),
    'b': _bigIntHex(c.b!.toBigInteger()!),
    'g': _hex(ec_dh.ecPointEncode(d.G)),
    'n': _bigIntHex(d.n),
    // The cofactor lives on the impl, not the interface; every curve in
    // scope (registry, or the SPKI parser's explicit-params build) is one
    // of those.
    'h': (d as ECDomainParametersImpl).h!.toInt(),
  };
}

Map<String, Object?> _opSpkiPublicKeyData(Map<String, Object?> input) {
  final key = parseSubjectPublicKeyInfo(_bytes(input['data']));
  return switch (key) {
    null => {'parsed': false},
    SpkiEcPublicKey(:final domain, :final point) => {
      'parsed': true,
      'kind': 'ec',
      // Upstream: EC_POINT_point2oct in the key's conversion form.
      'publicKey': _hex(ec_dh.ecPointEncode(point)),
      'domain': _ecDomainMap(domain),
    },
    SpkiDhPublicKey(:final p, :final g, :final q, :final y) => {
      'parsed': true,
      'kind': 'dh',
      // Upstream: BN_bn2bin(pub); minimal, leading zeros stripped.
      'publicKey': _bigIntHex(y),
      'domain': {
        'p': _bigIntHex(p),
        'g': _bigIntHex(g),
        'q': q == null ? null : _bigIntHex(q),
      },
    },
    // The parser has an RSA arm. CA can do nothing with such a key
    // (upstream's getPublicKeyData yields [] for one), so the case stays
    // dart-only here and the RSA coverage proper lives in dg15.json.
    SpkiRsaPublicKey(:final modulus, :final exponent) => {
      'parsed': true,
      'kind': 'rsa',
      'modulus': _bigIntHex(modulus),
      'exponent': _bigIntHex(exponent),
    },
  };
}

Map<String, Object?> _opChipAuthDeriveSessionKeys(Map<String, Object?> input) {
  final (ksEnc, ksMac) = chipAuthDeriveSessionKeys(
    keySeed: _bytes(input['keySeed']),
    oid: input['oid']! as String,
  );
  return {'ksEnc': _hex(ksEnc), 'ksMac': _hex(ksMac)};
}

Map<String, Object?> _opChipAuthInferOid(Map<String, Object?> input) => {
  'oid': chipAuthInferOid(input['publicKeyOid']! as String),
};

/// Typed DG14 rows. `type` is the runtime class name: the same string
/// Swift's `String(describing: type(of: si))` yields.
Map<String, Object?> _securityInfoRow(SecurityInfo si) => switch (si) {
  ChipAuthenticationInfo() => {
    'type': 'ChipAuthenticationInfo',
    'oid': si.getObjectIdentifier(),
    'version': si.version,
    'keyId': si.keyId,
  },
  ChipAuthenticationPublicKeyInfo() => {
    'type': 'ChipAuthenticationPublicKeyInfo',
    'oid': si.getObjectIdentifier(),
    'keyId': si.keyId,
  },
  ActiveAuthenticationInfo() => {
    'type': 'ActiveAuthenticationInfo',
    'oid': si.getObjectIdentifier(),
    'version': si.version,
    'signatureAlgorithmOID': si.signatureAlgorithmOID,
  },
  PACEInfo() => {
    'type': 'PACEInfo',
    'oid': si.getObjectIdentifier(),
    'version': si.getVersion(),
    'parameterId': si.getParameterId(),
  },
  _ => {'type': si.runtimeType.toString(), 'oid': si.getObjectIdentifier()},
};

Map<String, Object?> _opDg14SecurityInfos(Map<String, Object?> input) => {
  'infos': DataGroup14(
    _bytes(input['data']),
  ).securityInfos.map(_securityInfoRow).toList(),
};

// --- Active Authentication / DG15 suite ops --------------------------------

Map<String, Object?> _opAaInfoSignatureAlgorithm(Map<String, Object?> input) =>
    {
      'name': ActiveAuthenticationInfo(
        oid: SecurityInfo.ID_AA_OID,
        version: 1,
        signatureAlgorithmOID: input['oid'] as String?,
      ).getSignatureAlgorithmOIDString(),
    };

Map<String, Object?> _opAaInfoProtocolOIDString(Map<String, Object?> input) => {
  'name': ActiveAuthenticationInfo(
    oid: input['oid']! as String,
    version: 1,
  ).getProtocolOIDString(),
};

/// DG15's key, in the shape both runners can produce: EC via the shared
/// domain summary + uncompressed point, RSA via `{n, e}` (`RSA_get0_key`
/// Swift-side), and `"none"` for the never-throws skip contract.
Map<String, Object?> _opDg15Parse(Map<String, Object?> input) {
  final dg15 = DataGroup15(_bytes(input['data']));
  return switch (dg15.publicKey) {
    SpkiEcPublicKey(:final domain, :final point) => {
      'keyType': 'ec',
      'publicKey': _hex(ec_dh.ecPointEncode(point)),
      'domain': _ecDomainMap(domain),
    },
    SpkiRsaPublicKey(:final modulus, :final exponent) => {
      'keyType': 'rsa',
      'modulus': _bigIntHex(modulus),
      'exponent': _bigIntHex(exponent),
    },
    // DH SPKI, unparseable body, or anything else.
    _ => {'keyType': 'none'},
  };
}

Map<String, Object?> _opAaVerify(Map<String, Object?> input) {
  final dg14Hex = input['dg14'] as String?;
  final verdict = verifyActiveAuthentication(
    dg15: DataGroup15(_bytes(input['dg15'])),
    dg14: dg14Hex == null ? null : DataGroup14(_bytes(dg14Hex)),
    challenge: _bytes(input['challenge']),
    signature: _bytes(input['signature']),
  );
  return {
    'passed': verdict.passed,
    'scheme': verdict.scheme?.name,
    'digestAlgorithm': verdict.digestAlgorithm,
  };
}

// --- extended data-group suite ops -----------------------------------------

/// Images travel as SHA-256 (the dg2 precedent), never as bytes.
Map<String, Object?> _opDg7Parse(Map<String, Object?> input) => {
  'imageSha256': _hex(
    hashes.calcSHA256Hash(DataGroup7(_bytes(input['data'])).imageData),
  ),
};

/// Dart-only: upstream has no image-format surface on DG7. `null`
/// is a legitimate outcome: the sniff never throws.
Map<String, Object?> _opDg7ImageFormat(Map<String, Object?> input) => {
  'format': DataGroup7(_bytes(input['data'])).imageFormat?.name,
};

/// The twelve upstream fields under upstream's own spellings, so both runners
/// emit the same shape.
Map<String, Object?> _opDg11Parse(Map<String, Object?> input) {
  final dg11 = DataGroup11(_bytes(input['data']));
  return {
    'fullName': dg11.fullName,
    'personalNumber': dg11.personalNumber,
    'dateOfBirth': dg11.dateOfBirth,
    'placeOfBirth': dg11.placeOfBirth,
    'address': dg11.address,
    'telephone': dg11.telephone,
    'profession': dg11.profession,
    'title': dg11.title,
    'personalSummary': dg11.personalSummary,
    'proofOfCitizenship': dg11.proofOfCitizenship,
    'tdNumbers': dg11.tdNumbers,
    'custodyInfo': dg11.custodyInfo,
  };
}

/// Dart-only, since upstream drops them: the raw `A0`/`5F0F` record strings.
Map<String, Object?> _opDg11OtherNames(Map<String, Object?> input) => {
  'otherNames': DataGroup11(_bytes(input['data'])).otherNames,
};

/// Upstream's DG12 field set minus the dead `otherPersonsDetails` (nil on
/// swift, not ported in dart), images as SHA-256.
Map<String, Object?> _opDg12Parse(Map<String, Object?> input) {
  final dg12 = DataGroup12(_bytes(input['data']));
  final front = dg12.frontImage;
  final rear = dg12.rearImage;
  return {
    'issuingAuthority': dg12.issuingAuthority,
    'dateOfIssue': dg12.dateOfIssue,
    'endorsementsOrObservations': dg12.endorsementsOrObservations,
    'taxOrExitRequirements': dg12.taxOrExitRequirements,
    'frontImageSha256': front == null
        ? null
        : _hex(hashes.calcSHA256Hash(front)),
    'rearImageSha256': rear == null ? null : _hex(hashes.calcSHA256Hash(rear)),
    'personalizationTime': dg12.personalizationTime,
    'personalizationDeviceSerialNr': dg12.personalizationDeviceSerialNr,
  };
}

/// Dart-only, since upstream drops them: the raw `A0`/`5F1A` record strings.
Map<String, Object?> _opDg12OtherPersons(Map<String, Object?> input) => {
  'otherPersons': DataGroup12(_bytes(input['data'])).otherPersons,
};

// --- LDS / SOD-oracle suite ops --------------------------------------------

/// The runtime class name: the same string Swift's
/// `String(describing: type(of: dg))` yields, so both runners emit it.
String _dgTypeName(DataGroup dg) => switch (dg) {
  COM() => 'COM',
  DataGroup1() => 'DataGroup1',
  DataGroup2() => 'DataGroup2',
  DataGroup7() => 'DataGroup7',
  DataGroup11() => 'DataGroup11',
  DataGroup12() => 'DataGroup12',
  DataGroup14() => 'DataGroup14',
  DataGroup15() => 'DataGroup15',
  SOD() => 'SOD',
  NotImplementedDG() => 'NotImplementedDG',
  DataGroup() => 'DataGroup',
};

Map<String, Object?> _opDgParseDG(Map<String, Object?> input) {
  final dg = DataGroupParser().parseDG(data: _bytes(input['data']));
  return {
    'type': _dgTypeName(dg),
    'datagroupType': dg.datagroupType.getName(),
    'body': _hex(dg.body),
  };
}

Map<String, Object?> _opDgHash(Map<String, Object?> input) {
  final dg = DataGroupParser().parseDG(data: _bytes(input['data']));
  return {'hash': _hex(dg.hash(input['algorythm']! as String))};
}

Map<String, Object?> _opComParse(Map<String, Object?> input) {
  final com = COM(_bytes(input['data']));
  return {
    'version': com.version,
    'unicodeVersion': com.unicodeVersion,
    'dataGroupsPresent': com.dataGroupsPresent,
  };
}

Map<String, Object?> _opDg1Parse(Map<String, Object?> input) => {
  'elements': DataGroup1(_bytes(input['data'])).elements,
};

Map<String, Object?> _opDg2Parse(Map<String, Object?> input) {
  final dg2 = DataGroup2(_bytes(input['data']));
  return {
    'nrImages': dg2.nrImages,
    'versionNumber': dg2.versionNumber,
    'lengthOfRecord': dg2.lengthOfRecord,
    'numberOfFacialImages': dg2.numberOfFacialImages,
    'facialRecordDataLength': dg2.facialRecordDataLength,
    'nrFeaturePoints': dg2.nrFeaturePoints,
    'gender': dg2.gender,
    'eyeColor': dg2.eyeColor,
    'hairColor': dg2.hairColor,
    'featureMask': dg2.featureMask,
    'expression': dg2.expression,
    'poseAngle': dg2.poseAngle,
    'poseAngleUncertainty': dg2.poseAngleUncertainty,
    'faceImageType': dg2.faceImageType,
    'imageDataType': dg2.imageDataType,
    'imageWidth': dg2.imageWidth,
    'imageHeight': dg2.imageHeight,
    'imageColorSpace': dg2.imageColorSpace,
    'sourceType': dg2.sourceType,
    'deviceType': dg2.deviceType,
    'quality': dg2.quality,
    'imageSha256': _hex(hashes.calcSHA256Hash(dg2.imageData)),
  };
}

Map<String, Object?> _opDg2FaceImageFormat(Map<String, Object?> input) => {
  'format': DataGroup2(_bytes(input['data'])).faceImageFormat.name,
};

Map<String, Object?> _opDg2Encoding(Map<String, Object?> input) => {
  'encoding': DataGroup2(_bytes(input['data'])).encoding.name,
};

Map<String, Object?> _opFaceImageInfoFrom(Map<String, Object?> input) {
  final info = FaceImageInfo.from(DataGroup2(_bytes(input['data'])));
  return {
    'expression': info.expression?.name,
    'eyeColor': info.eyeColor?.name,
    'faceImageType': info.faceImageType?.name,
    // Declaration order for determinism (the Swift op wraps its optional as
    // nil -> [] / single flag -> [name]).
    'features': [
      for (final f in Features.values)
        if (info.features.contains(f)) f.name,
    ],
    'hairColor': info.hairColor?.name,
    'imageColorSpace': info.imageColorSpace?.name,
    'imageDataType': info.imageDataType?.name,
    'sourceType': info.sourceType?.name,
  };
}

Map<String, Object?> _opSodParse(Map<String, Object?> input) => {
  'pkcs7CertificateData': _hex(SOD(_bytes(input['data'])).pkcs7CertificateData),
};

Map<String, Object?> _opSodEncapsulatedContent(Map<String, Object?> input) => {
  'content': _hex(SOD(_bytes(input['data'])).getEncapsulatedContent()),
};

Map<String, Object?> _opSodParseSignatureContent(Map<String, Object?> input) {
  final sod = SOD(_bytes(input['data']));
  final (algorythm, sodHashes) = parseSODSignatureContent(
    sod.getEncapsulatedContent(),
  );
  return {
    'algorythm': algorythm,
    'hashes': {for (final e in sodHashes.entries) e.key.getName(): e.value},
  };
}

Map<String, Object?> _opSodLdsVersionInfo(Map<String, Object?> input) {
  final (ldsVersion, unicodeVersion) = parseLdsVersionInfo(
    _bytes(input['content']),
  );
  return {'ldsVersion': ldsVersion, 'unicodeVersion': unicodeVersion};
}

Map<String, Object?> _opSodCheckDataGroupHashes(Map<String, Object?> input) {
  final sod = SOD(_bytes(input['sod']));
  final parser = DataGroupParser();
  // Mirror the model's dataGroupsRead: the SOD itself is in the read set
  // (it is exempt from the missing check), then the input DGs in order.
  final dataGroupsRead = <DataGroupId, DataGroup>{DataGroupId.SOD: sod};
  for (final e
      in (input['dataGroups']! as Map).cast<String, Object?>().entries) {
    dataGroupsRead[DataGroupId.getIDFromName(e.key)] = parser.parseDG(
      data: _bytes(e.value),
    );
  }
  final result = checkDataGroupHashes(sod: sod, dataGroupsRead: dataGroupsRead);
  return {
    'algorythm': result.sodHashAlgorythm,
    'hashes': {
      for (final e in result.dataGroupHashes.entries)
        e.key.getName(): {
          'id': e.value.id,
          'sodHash': e.value.sodHash,
          'computedHash': e.value.computedHash,
          'match': e.value.match,
        },
    },
    'errors': result.errors,
    'passed': result.passed,
  };
}

// --- passive-authentication ops --------------------------------------------

/// The trust store a case describes: `trust` is a list of certificate DERs as
/// hex (the Swift op writes them out as a temp PEM file).
CscaTrustStore _trustStore(Map<String, Object?> input) =>
    CscaTrustStore.fromCertificates(
      ((input['trust'] as List?) ?? const []).map((c) => _bytes(c)),
    );

DateTime? _verificationTime(Map<String, Object?> input) {
  final iso = input['verificationTime'] as String?;
  return iso == null ? null : DateTime.parse(iso);
}

Map<DataGroupId, DataGroup> _readDataGroups(Map<String, Object?> input) {
  final raw = (input['dataGroups'] as Map?)?.cast<String, Object?>();
  if (raw == null) {
    return const {};
  }
  final parser = DataGroupParser();
  return {
    for (final e in raw.entries)
      DataGroupId.getIDFromName(e.key): parser.parseDG(data: _bytes(e.value)),
  };
}

PassiveAuthResult _paVerify(Map<String, Object?> input) => verifyPassiveAuth(
  sod: SOD(_bytes(input['sod'])),
  trustStore: _trustStore(input),
  dataGroupsRead: _readDataGroups(input),
  verificationTime: _verificationTime(input),
);

Map<String, Object?> _opPaSodSignature(Map<String, Object?> input) => {
  'valid': verifySodSignature(SOD(_bytes(input['sod']))).valid,
};

Map<String, Object?> _opPaSodSignatureDetail(Map<String, Object?> input) {
  final check = verifySodSignature(SOD(_bytes(input['sod'])));
  return {
    'valid': check.valid,
    'digestAlgorithm': check.digestAlgorithm,
    'signatureScheme': check.signatureScheme,
    'cause': check.cause?.wireName,
    'annotations': [for (final a in check.annotations) a.wireName],
  };
}

Map<String, Object?> _opPaTrust(Map<String, Object?> input) => {
  'trusted': _paVerify(input).passportCorrectlySigned,
};

Map<String, Object?> _opPaTrustDetail(Map<String, Object?> input) {
  final trust = _paVerify(input).trust!;
  return {
    'trusted': trust.trusted,
    'cause': trust.cause?.wireName,
    'chainLength': trust.chain.length,
    'cscaFingerprintSha256': trust.trusted
        ? trust.chain.last.fingerprintSha256
        : null,
  };
}

/// The upstream boolean triple, computed off the verdict.
Map<String, Object?> _opPaVerify(Map<String, Object?> input) {
  final r = _paVerify(input);
  return {
    'passportCorrectlySigned': r.passportCorrectlySigned,
    'documentSigningCertificateVerified': r.documentSigningCertificateVerified,
    'passportDataNotTampered': r.passportDataNotTampered,
  };
}

Map<String, Object?> _opPaVerdict(Map<String, Object?> input) {
  final r = _paVerify(input);
  return {
    'outcome': r.outcome.name,
    'cause': r.cause?.wireName,
    'annotations': [for (final a in r.annotations) a.wireName],
  };
}

Map<String, Object?> _opPaMasterList(Map<String, Object?> input) {
  final pinned = input['pinnedSigner'] as String?;
  final store = CscaTrustStore.fromSignedMasterList(
    Uint8List.fromList(_bytes(input['masterList'])),
    pinnedSignerDer: pinned == null ? null : _bytes(pinned),
    allowUnpinned: (input['allowUnpinned'] as bool?) ?? false,
  );
  return {
    'certificateCount': store.certificateCount,
    'signerVerified': store.masterListInfo!.signatureVerified,
    'skipped': store.skippedCertificates,
    'pinned': store.masterListInfo!.pinned,
  };
}

Map<String, Object?> _opX509Parse(Map<String, Object?> input) {
  final cert = X509Certificate.tryParse(_bytes(input['certificate']))!;
  return {
    'subject': cert.subjectString,
    'issuer': cert.issuerString,
    'serialNumber': cert.serialNumberHex,
    'notBefore': cert.notBefore.toIso8601String(),
    'notAfter': cert.notAfter.toIso8601String(),
    'ski': cert.subjectKeyIdentifier == null
        ? null
        : _hex(cert.subjectKeyIdentifier!),
    'aki': cert.authorityKeyIdentifier == null
        ? null
        : _hex(cert.authorityKeyIdentifier!),
    'ca': cert.basicConstraintsCa,
    'keyCertSign': cert.keyCertSign,
    'fingerprintSha256': cert.fingerprintSha256,
    'publicKeyBits': cert.info.publicKeyBits,
    'publicKeyCurve': cert.info.publicKeyCurve,
  };
}

// ---------------------------------------------------------------------------

/// Maps a thrown error to the code string vectors assert on: upstream case
/// names for [EmrtdException], `ArgumentError` for dart-only guard
/// rejections, and the trust-store ingestion codes.
String? _thrownCode(Object e) => switch (e) {
  EmrtdException(:final code) => code,
  MasterListException(:final code) => code,
  ArgumentError() => 'ArgumentError',
  _ => null,
};

const _runnerName = 'dart';
const _supportedSchemaVersion = 1;

void main() {
  final vectorsDir = Directory('conformance/vectors');
  final files = vectorsDir.existsSync()
      ? (vectorsDir
            .listSync()
            .whereType<File>()
            .where((f) => f.path.endsWith('.json'))
            .toList()
          ..sort((a, b) => a.path.compareTo(b.path)))
      : <File>[];

  test('vector discovery finds at least one suite', () {
    expect(
      files,
      isNotEmpty,
      reason:
          'no *.json under conformance/vectors: run `flutter test` from the '
          'package root',
    );
  });

  for (final file in files) {
    final suite = jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
    final suiteName = suite['suite'] as String? ?? file.path;

    group('conformance/$suiteName', () {
      test('schemaVersion is supported', () {
        expect(suite['schemaVersion'], _supportedSchemaVersion);
      });

      final suiteRunners =
          (suite['runners'] as List?)?.cast<String>() ?? const [_runnerName];
      if (!suiteRunners.contains(_runnerName)) {
        // Visible skip, never silent (SCHEMA.md).
        test(
          'suite gated off this runner',
          () {},
          skip: 'runners: $suiteRunners excludes "$_runnerName"',
        );
        return;
      }

      for (final rawCase in (suite['cases']! as List)) {
        final c = rawCase as Map<String, Object?>;
        final name = c['name']! as String;
        final caseRunners = (c['runners'] as List?)?.cast<String>();
        final skip = caseRunners != null && !caseRunners.contains(_runnerName)
            ? 'runners: $caseRunners excludes "$_runnerName"'
            : null;

        test(name, skip: skip, () async {
          final opName = c['op']! as String;
          final op = _ops[opName];
          if (op == null) {
            fail(
              'unknown op "$opName": add it to the runner registry and to '
              'the SCHEMA.md op table (a runner encountering an unknown op '
              'fails; see conformance/SCHEMA.md)',
            );
          }
          final input = (c['input']! as Map).cast<String, Object?>();
          final expectation = (c['expect']! as Map).cast<String, Object?>();

          final expectedError = expectation['error'] as String?;
          if (expectedError != null) {
            await expectLater(
              Future<Object?>(() async => op(input)),
              throwsA(
                predicate(
                  (e) => _thrownCode(e as Object) == expectedError,
                  'error with code "$expectedError"',
                ),
              ),
            );
          } else {
            expect(await op(input), equals(expectation['out']));
          }
        });
      }
    });
  }
}
