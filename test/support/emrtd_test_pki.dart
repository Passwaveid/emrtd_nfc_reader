/// The passive-authentication test PKI: a deterministic generator for
/// CSCA->DSC chains, SODs and CSCA master lists, mirroring the server-side
/// verifier's own `EmrtdTestPki` fixture generator and extending it with the
/// link certificates and validity variants the port's path builder needs.
///
/// Everything is **fixed input in, fixed bytes out**: the key material below
/// was generated once with OpenSSL and is embedded verbatim, and every
/// randomized signature scheme (ECDSA's `k`, PSS's salt) draws from
/// [DeterministicRandom]. Re-running the generator therefore reproduces the
/// committed `conformance/vectors/passive_auth.json` byte-for-byte, which is
/// what lets the same builders serve both the committed vectors and the
/// runtime unit suites.
///
/// Identities are fictional (`UTOPIA`, the ICAO specimen state) per the
/// fixture policy: no real document data is ever committed.
///
/// Cross-checked against OpenSSL 3.0.13 at authoring time; the commands and
/// their results are recorded in `test/pki/README-fixtures.md`.
library;

// ignore_for_file: implementation_imports

import 'dart:convert';
import 'dart:typed_data';

import 'package:emrtd_core/src/crypto/hashes.dart';
import 'package:emrtd_core/src/pki/cms_signed_data.dart';
import 'package:pointycastle/api.dart'
    show
        Digest,
        ParametersWithRandom,
        ParametersWithSaltConfiguration,
        PrivateKeyParameter,
        SecureRandom;
import 'package:pointycastle/asymmetric/api.dart' show RSAPrivateKey;
import 'package:pointycastle/asymmetric/rsa.dart' show RSAEngine;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/ecc_base.dart' show ECDomainParametersImpl;
import 'package:pointycastle/ecc/ecc_fp.dart' as fp;
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:pointycastle/signers/pss_signer.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

// ===========================================================================
// DER writer: fixture-side only. The product layer never re-encodes.
// ===========================================================================

/// Minimal DER/BER encoder for building fixtures.
class Der {
  static Uint8List _tlv(int tag, List<int> content) =>
      Uint8List.fromList([tag, ..._len(content.length), ...content]);

  static List<int> _len(int n) {
    if (n < 0x80) {
      return [n];
    }
    final bytes = <int>[];
    var rest = n;
    while (rest > 0) {
      bytes.insert(0, rest & 0xFF);
      rest >>= 8;
    }
    return [0x80 | bytes.length, ...bytes];
  }

  static Uint8List tagged(int tag, List<int> content) => _tlv(tag, content);

  static Uint8List seq(List<List<int>> children) =>
      _tlv(0x30, [for (final c in children) ...c]);

  static Uint8List set(List<List<int>> children) =>
      _tlv(0x31, [for (final c in children) ...c]);

  /// A DER `SET OF`: members sorted by their encodings (X.690 §11.6).
  static Uint8List setOf(List<List<int>> children) {
    final sorted = [...children]..sort(_compareBytes);
    return set(sorted);
  }

  /// `[n] EXPLICIT`: a constructed context tag wrapping a complete element.
  static Uint8List explicit(int n, List<int> inner) => _tlv(0xA0 | n, inner);

  /// `[n] IMPLICIT` over a constructed body.
  static Uint8List implicitConstructed(int n, List<int> content) =>
      _tlv(0xA0 | n, content);

  /// `[n] IMPLICIT` over a primitive body.
  static Uint8List implicitPrimitive(int n, List<int> content) =>
      _tlv(0x80 | n, content);

  /// The BER indefinite-length form: `tag 80 <content> 00 00`.
  static Uint8List indefinite(int tag, List<int> content) =>
      Uint8List.fromList([tag, 0x80, ...content, 0x00, 0x00]);

  static Uint8List integer(BigInt v) {
    if (v == BigInt.zero) {
      return _tlv(0x02, const [0]);
    }
    var bytes = <int>[];
    var x = v.abs();
    while (x > BigInt.zero) {
      bytes.insert(0, (x & BigInt.from(0xFF)).toInt());
      x >>= 8;
    }
    if ((bytes.first & 0x80) != 0) {
      bytes = [0, ...bytes];
    }
    return _tlv(0x02, bytes);
  }

  static Uint8List int32(int v) => integer(BigInt.from(v));

  static Uint8List nul() => _tlv(0x05, const []);

  static Uint8List octetString(List<int> v) => _tlv(0x04, v);

  static Uint8List bitString(List<int> v) => _tlv(0x03, [0x00, ...v]);

  static Uint8List boolean(bool v) => _tlv(0x01, [v ? 0xFF : 0x00]);

  static Uint8List printableString(String s) => _tlv(0x13, ascii.encode(s));

  static Uint8List utf8String(String s) => _tlv(0x0C, utf8.encode(s));

  static Uint8List oid(String dotted) {
    final arcs = dotted.split('.').map(int.parse).toList();
    final body = <int>[];
    void base128(int v) {
      final tmp = <int>[v & 0x7F];
      var rest = v >> 7;
      while (rest > 0) {
        tmp.add(0x80 | (rest & 0x7F));
        rest >>= 7;
      }
      body.addAll(tmp.reversed);
    }

    base128(40 * arcs[0] + arcs[1]);
    for (final a in arcs.skip(2)) {
      base128(a);
    }
    return _tlv(0x06, body);
  }

  /// X.509 `Time`: UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280
  /// §4.1.2.5); the far-future fixtures therefore travel as
  /// GeneralizedTime.
  static Uint8List time(DateTime t) {
    final u = t.toUtc();
    String two(int v) => v.toString().padLeft(2, '0');
    final body =
        '${two(u.month)}${two(u.day)}${two(u.hour)}'
        '${two(u.minute)}${two(u.second)}Z';
    if (u.year < 2050) {
      return _tlv(0x17, ascii.encode('${two(u.year % 100)}$body'));
    }
    return _tlv(
      0x18,
      ascii.encode('${u.year.toString().padLeft(4, '0')}$body'),
    );
  }

  static int _compareBytes(List<int> a, List<int> b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      if (a[i] != b[i]) {
        return a[i] - b[i];
      }
    }
    return a.length - b.length;
  }
}

/// `Name` from a country/organisation/common-name triple: the DN shape ICAO
/// CSCA and DSC certificates use.
Uint8List testDn({
  required String country,
  required String organisation,
  required String commonName,
}) => Der.seq([
  Der.set([
    Der.seq([Der.oid('2.5.4.6'), Der.printableString(country)]),
  ]),
  Der.set([
    Der.seq([Der.oid('2.5.4.10'), Der.printableString(organisation)]),
  ]),
  Der.set([
    Der.seq([Der.oid('2.5.4.3'), Der.printableString(commonName)]),
  ]),
]);

// ===========================================================================
// Key material: generated once with OpenSSL 3.0.13, embedded verbatim.
// ===========================================================================

BigInt _h(String hex) => BigInt.parse(hex, radix: 16);

/// An RSA or EC key pair the generator can sign with.
sealed class TestKeyPair {
  const TestKeyPair();

  /// The `SubjectPublicKeyInfo` DER for this key.
  Uint8List spki();
}

class RsaTestKey extends TestKeyPair {
  const RsaTestKey(this.n, this.e, this.d, this.p, this.q);

  final BigInt n;
  final BigInt e;
  final BigInt d;
  final BigInt p;
  final BigInt q;

  @override
  Uint8List spki() => Der.seq([
    Der.seq([Der.oid('1.2.840.113549.1.1.1'), Der.nul()]),
    Der.bitString(Der.seq([Der.integer(n), Der.integer(e)])),
  ]);
}

class EcTestKey extends TestKeyPair {
  EcTestKey(
    this.d,
    this.curveName,
    this.curveOid, {
    this.explicitParams = false,
  }) : domain = ECDomainParameters(curveName);

  final BigInt d;
  final String curveName;
  final String curveOid;

  /// Emit `ECParameters` explicitly instead of the named-curve OID: the
  /// explicit-parameters fixture (upstream tolerates these only via its
  /// `X509_V_ERR_EC_KEY_EXPLICIT_PARAMS` callback exemption).
  final bool explicitParams;

  final ECDomainParameters domain;

  ECPoint get point => (domain.G * d)!;

  Uint8List get publicPointBytes => Uint8List.fromList(point.getEncoded(false));

  Uint8List _explicitParameters() {
    final curve = domain.curve as fp.ECCurve;
    final p = curve.q!;
    final cofactor = (domain as ECDomainParametersImpl).h ?? BigInt.one;
    final fieldSize = (p.bitLength + 7) ~/ 8;
    List<int> fe(BigInt v) {
      final out = List<int>.filled(fieldSize, 0);
      var x = v;
      for (var i = fieldSize - 1; i >= 0; i--) {
        out[i] = (x & BigInt.from(0xFF)).toInt();
        x >>= 8;
      }
      return out;
    }

    return Der.seq([
      Der.int32(1),
      Der.seq([Der.oid('1.2.840.10045.1.1'), Der.integer(p)]),
      Der.seq([
        Der.octetString(fe(curve.a!.toBigInteger()!)),
        Der.octetString(fe(curve.b!.toBigInteger()!)),
      ]),
      Der.octetString(domain.G.getEncoded(false)),
      Der.integer(domain.n),
      Der.integer(cofactor),
    ]);
  }

  @override
  Uint8List spki() => Der.seq([
    Der.seq([
      Der.oid('1.2.840.10045.2.1'),
      if (explicitParams) _explicitParameters() else Der.oid(curveOid),
    ]),
    Der.bitString(publicPointBytes),
  ]);
}

/// A subject key whose SPKI names an algorithm no parser knows: a
/// structurally valid `SubjectPublicKeyInfo` that
/// `parseSubjectPublicKeyInfo` rejects. Subject-only: it cannot sign.
class UnknownAlgorithmTestKey extends TestKeyPair {
  const UnknownAlgorithmTestKey();

  @override
  Uint8List spki() => Der.seq([
    Der.seq([Der.oid('1.2.3.4.5'), Der.nul()]),
    Der.bitString(const [0x04, 0x01, 0x02, 0x03, 0x04]),
  ]);
}

/// An RSA-4096 DSC key: the width some issuers sign with; exists so the
/// certificate surface's key-size projection is pinned above 2048. Used by
/// the `x509.parse` fixture only, never on a trust path.
final RsaTestKey dscRsa4096Key = RsaTestKey(
  _h(
    'f77dd1ac65a5ade2617544e55f080916158b41f113b2e5e7c29a9320a9dbe8e5'
    'a27af0213f51cd0ee3c709fbc0268068c0b22c0dcf6dcb15a32e7fe754ba7f47'
    '9babd2d79ba9768ec6175a2d7967921cf0ae8dbfdce4e4e7ac72615f279407b8'
    '985529d3e84e55fdf4886820b51412b79bf3a3844e4ab0fd9181a72e5d3c4364'
    '9b0307d3ce461ca5e934f78b8dcb7b4e6f7d1e04ff6ea5b538558aeb6fd4247d'
    '6cbf7b2cdcd11228cb7fb85563083667c39f84cf02c3d2eef50634816968df80'
    'c907818e2d2e3ba0ac36c71beefb55836b8fb1d89c539ac9038c8e02e7b6c5dd'
    'cb8701febb91e820828892bc549c749ee2bf46fcb3bc12e10c8b349b96248cec'
    '0c6ebfc10f4eb92493b04413be58efccd6fb996618d2eb2e93539566d3236079'
    '1b83baf6cb648b6e5b580b0af300b2af6cd9a3019a6896d112b522265001fd61'
    '9532db5e0add1afe0b1cebaee0ef11aa260d02397e08a17097dd529c13835208'
    '6fc152e3823f9a31473270184a11150d3d2b97d22ce084db04104246967aefb7'
    'c47bfc0eebeee70d7e72987fb42670950dad692e4b5a2c864a25051fe60162bc'
    'ca27de9ae4d928f0467f80ae9acc52f89bb4b58fab886280df58d51ffc3a9a50'
    '3f521147b47008ac1a78ca3a0c108e616ff85dfb7be9ed36e52b26b664d0b1aa'
    '62e1d51e138a03a4dcb1b555525532b467f0df197aee4468181ebf690fb78c2f',
  ),
  _h('10001'),
  _h(
    '1190594ffdcabb43649d38ed7a480cb507846182a55e3dd8abc3e28b1fe2de6d'
    '659189f7221241163c6e04b45c179f674fbd9548c99ec619dc01d1cbee046a41'
    'ffb73af85830b79c3c4cadf6aa360275915321f62acc07beb54b4cc3bf004f67'
    'f74f9bef50fe363616a3939836a19d0e70bfe2abe20e84ef09e384a4d2b31329'
    '51a2ee6c46a84d222d21b82bac3d739bc667bfb8a5140a28893df0e4f283c0af'
    '320788cb4f447b207008b9613decf84776e79c3a40bcfafc4061575a93cb8089'
    '183b33238eeb480a080ebf24a95a26e073c2b7e1627ec06e61951902f5c4cfd8'
    '04b8a91895e12df318b06e917503c177012a87f4292140c9bde5272f9f812a8a'
    'f63f92089f05a75475ddcf89baf938f6b0be6bc63ed20eff7beba3c9c1fa1e3c'
    '7b89a200e47d946ff4e55d5805ad1e5d411b5738e8b5268eb3feb1004b3d869d'
    '432d946706c70f3ca7c526f7fe1ef0fe1b762aa9260616f84b32343d98c1d0a9'
    'd5b61047ba35e4a60fba0ab269cef96963a56ee422b255edeca81f9404fb8341'
    '17052fd2152463fcf80578a4a29d7811b5542186a517e7b3a3f0ca4bda3b0b93'
    '7f3085d45e01808a3fdfd2714081f761b7c5b43f5bff1364ae025a3e4ebafe8d'
    '8d8774d0e670d0b2544b27bf25f373065c6c4f4053acd4cc7eb7c44e155ce337'
    'ec141752a28c2c23fe89fc1aaa4dceeb960eac75a5f12b7e5f4fc4762ab7c059',
  ),
  _h(
    'ffdff517aa8b2c6a68e55a351d26e0a021f531297df7b3c1647df98a6857ccab'
    'd85dc1321e4d421fb31de979ea95c8703435c481113c9b1a46ff5b705d3ba3b2'
    '74698caa5268ec2426156e874dd3124abc8022b2b4c413299a811b384e03c2c7'
    'eb6bc2a4cb518cecd201c223ae064eaa3fcb88a7347094fd174b7c0417f0b610'
    'c0e06965b79ddef3470ca9c2aa2082cbab57c5aea13b59c6bb4760ef2cad9836'
    '0deaf80548f881941ecf1d1d914f70e8f81b99993ae9eee77ff248bcc10adf32'
    'fa671f964618618cd7840b445691281402e9dd35a94f0f782a6a1a4f576bcd86'
    '1aa6c18072997a060bf7069517ad12417d3343ba3e726218296e7d33b528b363',
  ),
  _h(
    'f79ccfd338ef742c17d7e1956550016b40384d3ac17aa0bf332d080d327e81c5'
    '20e7e9e3246556fbb0cbc2448603fc0145ed712cd227748a04294f372c69e34c'
    'f1d823053a4b02c73c2bd4b7e3bfd9e2f000acb49933fd0e3b79a3c73b7c49f9'
    '378e6c180c5220344f50ccf95ed06b1b6e9b33224be8f091707b39bad712b755'
    'c1d13f5e2114b2d29b38523f959a8f37017836872bd2ee83b13030f3c375ed80'
    'cdbd7a4498a324519e85460f5c6c8aac01338030c55c0caf25a8ea40b8aa5946'
    '5372c4c25eabcdeb3142cb0d64c5f6f68b91691fee2c1883091e903c77d8c708'
    'f70b0ed7984f01b6722b190e5dbf5794460a78d7cf9efa0f7d2f32a29a22cbc5',
  ),
);

/// The root CSCA key (RSA-2048): anchors the RSA chains.
final RsaTestKey cscaRsaKey = RsaTestKey(
  _h(
    'c9837df15fe34f205b1b5fe8e883894e45a67aa0528c5c41fa474e9ff21635b4'
    'f7d2c9dee376764355ffd5fa9840b7fbbc99c6ba36bda3110aea847981d61b8e'
    '2558741bc9a5b4a92bf293602b4a725ccae93ba2c493bbc6f3ef386bd2adbf66'
    '5da8b0f67f990690ba1d9a288e062c3d132e0a5b33e1c365b6dd282d6632ff8c'
    'da9950164999669a165599f7de75c66a86987c531e1d7a7c410b893293e3f581'
    '52097f47a14031766e66b634bd7a3dbeebb4e6c37f876c2c7733f5b50126c16f'
    '73faa58e53618c9629c35fe00eb287a28c5d12aae2ad1667d660956ce7f82855'
    '0bbef3d8d1595ea1ec4a6190c8d5a67a0d7d7992f2bf90309cfcd175d35ffa7f',
  ),
  _h('10001'),
  _h(
    '50992fb3edc2c880ac000075f31dbd3ad9bfd2f731dd22ff5e9fcbb24c8d1691'
    '19b82cf6e1aa9d75a43d8df3cb96c31fc4590b33aab661b4ecd54d041e6aa91d'
    'cb111c6b8ad524b3af38b83a74463404aa41ec10d7a831284ba3c840d4049b73'
    'd18d29ae85ed8a4333b5a855852cb1e001be5df50984c876f3d37400e88a084c'
    'b3a2c62ecf9f45c61274d073cf8382d1b23e04697cdce9526d2cc06fdda8018a'
    '0bef2de362dc65e2d25ba7e45842ba000c6df85dfbaac888dd71e451d43997fb'
    'cd74a36999515b4a1f54f889c45ddca36d1925fbdcfda9c3441feb17a09bae6c'
    '858436fd0be8340ac97caecdbd6171be29c4f7eeee58162eb0770ff3283d5495',
  ),
  _h(
    'efd32c6c1cb89e1c01bdcdfe7d20730e6112a1321332a4d997b732e26877ae2f'
    '30a1028cc525d2433727a3836361f429dfb7c9c80c3138b9f89b27e651444acc'
    '9f5da0afe07fa47eb990476e896d9e612223e719179e3a1556a924ce5b4c87d6'
    '37c4ce9b0f8db53c45a62ca2b65307889d3b9be8508eb18692c863dbf76e9835',
  ),
  _h(
    'd71ad5b083fbb0c087403553c5d862f5aaf7cc5b819089bf689ef0eafe90043e'
    'c11d62c7b6f7f8f1c4ec0206ca8c7215dc4dee7d7469ce0e7e0ae6c359100bb5'
    'db1e4998e18412150519e00ce123cb20e2c73880010a8bdbaecb1a3114e361f3'
    '2908e2009b2c12101dfb3f117434b930682522e06b3ece5b4c2005af61de6663',
  ),
);

/// The superseded CSCA key: the *old* half of the link-certificate pair.
final RsaTestKey cscaRsaOldKey = RsaTestKey(
  _h(
    'b7f0b1d2467f2288507c242acf8dcfe043d1928050c5864b7c9b5c3a63d9ee65'
    '50a0a6d5265a28e9f5501a4bba03041bf59e273873ec7442004e189bd2a54f9a'
    'b9370b58976cda2bf68614ddd38fb3f04993b5df729593cd428b83b99af40861'
    'fe13681ea749320a7c0c4f719a3d030a85507fcaf7e973e369cdd5213c2e180c'
    'e960d9c2fc34b8b9545be0d97088b33cc6316b9f0c5ae42a719b65df53f372f4'
    'effe833b4a797986e4703563338612fcf0c07147b32fedf1b63356c02eb21faf'
    '900f78be927e6f33a5a67a41cafbf1383223076523730d990e214c725372e65b'
    'd8f4720c89714993dddda96d7ac2db7fdda4ba7c474d703e655227ecb422feb3',
  ),
  _h('10001'),
  _h(
    '16524631ff4e1451b87aa824edd506c1ef58f24f51fdf66318b6fdc53432d124'
    '485986855d4719a9f2940aecdfa0d811d087a5b8cb1089b72cb44d763364ce39'
    '377abf8cbbab80fa4ecb4ca2f2b6809e8b3f3a95e820d0b3dafc753ac3dc135c'
    '58e9dffbc04f389c5f1b5b54ace3f48785501481fbfdbf8b7c5e771bb662dd96'
    '16919ab2f6c2bd88e14c51302af1a65fb9acc173033e1d7bc8998f2bfc93098f'
    'f8929ff3e4822caf481d66dfa2b209a502b4dd1bd5fa13c1ecf7b8a24d3a6a88'
    'e979380530c7abf59c8aeed0a18581207f0f8fbb90e0d1c7384c8e7d8bb278c7'
    'c3ca93e10312dfc519a3482c0fc11c9eb818fdf5f287a71d4963816c6a3d1cc9',
  ),
  _h(
    'f1411ee2a38b2387fa9ff681533d504956597d5b12c70a29a551ede034a07aa3'
    '3d301dd525e819df3d13d62e0db1372c88daecabdbbdc7c7cc307ba2490f6e4c'
    'bb43165a79f8310fdc6573db099dcf56b61d7be16eaafe0ac5f72d0c1c64518a'
    '433f3a2d3722d0cd76cce4a9665fbcd3b494ba143262ab67542c92daf1b5c96f',
  ),
  _h(
    'c32ec92ea5cc0c3d85fcdb7d49e1dc4275a77b6c17ab95718dc3c33477c76d01'
    '1ff0b996cc455e72ffb2abd943015d80a142f80c6fb4043c7efe64fb650c920e'
    '34af7eac0b7e02bde436013ba4aecf4056f85aa5b5dd0f22d508024c0a0e5733'
    '7c54f3841120933c3bdafc9a5d6b2fee6a287ee1294e3ea54952d0657e85d4fd',
  ),
);

/// The rolled-over CSCA key: the *new* half of the link-certificate pair.
final RsaTestKey cscaRsaNewKey = RsaTestKey(
  _h(
    '9b69014c03e89e608b70bcc4e71d0326d0fd809abb23ac5c34e3caa406c3037c'
    'f85daf8ae025864a5c5c9565db3d10d44c72219c09daec2f06718a95b815e264'
    'ce1917e2fed659e9111ba1812720c75bef14ccefeec3df4cb2681905555962f8'
    'd06af5d81388512e9013ba0ad2d1b5b4b5794460c3dea6868b446d5bde76b526'
    'dea8191ad514e074591d2710531b36d4cf2679a280941019d128756c2ccad52c'
    'eec0d5654faf263f9c9d4ce2453b9028d1fe4ca3ab11371ce1956488fee3f5e4'
    '5d3b4cf6947344aaeb32ffa06a04082fa697f77081d8c57b81a159965b213c82'
    '959a770ebf5eae3ef7f897ea3a31d49ee3472f0fb5eb42b38cede6f73cebc297',
  ),
  _h('10001'),
  _h(
    '45717fdb5c39c31f67df89f2404566059fc84f019512c52f7490bf19594e25ce'
    '5f5ad998683d4c4b090773d88e4534b270b065154910128e96c60083933cf02b'
    '542ec14e34ca4a65cb37ba0cb093c4916f7d2f701d145840f8cd6c34c6650945'
    '1e38553f66c6f863a28cb60aa5168127cd197174fdc10d4f3c86e888ef18c32b'
    'f72428720a3be0a25448914e7e4f51623c5a8ff7ede70081ba6dea17fd3abef4'
    'a12cd75d4a5606f9b5256861319caef2bff5d83ba51ea0a50240fd1835ff4241'
    '23a9412c8bb1a35033e7e0992980b0950e980878a8ebbe0a6078c62f807e2190'
    'e885c1376a70e59f753cabcbea841b9eedc77936fc51ae3a85adba0635dc0479',
  ),
  _h(
    'd42edcab8a93542d51ced05eef43cac0d6e9cc224f52cc78e479d2ca67b1b981'
    'c5722c640fbf7712289479c90324445e9b31c363ffd600e91782001e5860f4c8'
    '965d85c1b3f49725baa4fc867a83495d69b5660d5771eff95e8065e6303edda3'
    'c83b966101f20b2a9e583f666354394ffcf6dd0854470125599d12b312a9885f',
  ),
  _h(
    'bb80d2be8c17a216251cb702847b126409d18fb32f420e5cd6e21805b9ba2eef'
    'c9b4f8440fd0697c5466b2cf51e37838872849e4753c2aa9724c91ca0ff27938'
    'da55d5e08857355a26d8a2fd2c8fbdc2e615108380a99abb4cc71fb7e3ad32aa'
    'bc3224c589c6614b4d6d0ea316af656c5b2aa5c7beb800e1b52251069a0e50c9',
  ),
);

/// The Document Signing key (RSA-2048): signs the v1.5 and PSS SODs.
final RsaTestKey dscRsaKey = RsaTestKey(
  _h(
    'c9c793dd631a29b121f2c202436e8d66cf31ee0cf2d1426983099d6fb8a64240'
    'bf8571370db5eb327b1229e4f2e836a1fdd13f0d34c09a3997994739f2f8b279'
    '5a5e528ad705447b364010a3ad10b9aa207ee8d3a59fdaab3c52c4819ee72815'
    'f25485a5e12dbabaaa29ccbed6cb1388a27e63e24f30cc82f3a884c7d735178d'
    'fd0a0d66c5dae1bf098c5f3806b8b66665bf220ef75cde57e9c202df33d669c3'
    '478e37a9e7c9b3e5ddb29cf5a4a3f085178f689b9c054e1528a1e52f1ecf4662'
    '6975ca763587cf88ad48b5cf1c202585490cea1a15bcb629299806e5813cad35'
    '49e91e9a9d8b3fb5ade1c92be33be637dc2e27563a7c28eb8e0fe600eb4d4569',
  ),
  _h('10001'),
  _h(
    '25ee7ebd7f83cb92a0ef21c98b239d315681ec5e42c753d4c1ed6ccb33cb0d69'
    '5e979750e222f0b3ecaedd714cb89a8c994a5caffedab6235d7c530771c58ec7'
    '815579eedfbcfdc2abd01f50a5981f4efc0cdf77ea0ac2f0adc6616a7c94b7d4'
    '6859bb4613aea50bb231696bf6b4f6571934e95201d10aa1136cfa8916cbc441'
    '77519e0cfda93288f74345327a92a22ae8eb8439c75c8e4c1e3f04c68da1e71c'
    '2d5c3b4c4baf6a2e2003295d4efa0d114a54bd6b0c2e13438efba2455db2eedc'
    'cafa86807918a2788f8cda74c59283299038e6662ebeac74f3b45847d2d1943c'
    '5cbd44c997e6317f07b4dd27470cf605aab3ddc0008abade8b4d99a431963a9',
  ),
  _h(
    'f1f5668a7178cd1e014bc9ae7eb5397d60ce1eb09a8f8441115516e5bd5ae6ab'
    'a3a4fbf1b68465d4333869f31cd52b59ee91b714efb5cbcc029dc60df7c31358'
    '3868aea846dea24121b6ed2a4fc13f798e71366e20dc5fc0fa53fbf33b48261c'
    '789c4059af4a51c1f6177c2ee280d2772187bedf159689834bdb38e5e101b71f',
  ),
  _h(
    'd57d447aac5bc276f00f73d6ab2621dd7c29eca6998318149707c9f26e53d992'
    'e491482d13701246a620e73290a1a305700384509d28f449c44994cd5f0fed8f'
    '4e7d1e916e78ba8da7625d8e309fe1790a59673925fb08dddff201b78741837b'
    '8a48d8caa41e285b96cb87952f85473b0fe566b90218eb0463dd778a84181a77',
  ),
);

/// The Master List Signer key (RSA-2048).
final RsaTestKey mlSignerRsaKey = RsaTestKey(
  _h(
    'ad83a5c5427a1104234a439de263416f33a252c61e1b68d01ed2fb613e86cf3f'
    'fb8685d915a7cf34d3a49d4e20666e26a7f012738ccac30bfc3ca78d070488ff'
    'e453d412bd5a06c54fbef3780b248e77f6a76179c45471f619331ae0c3b2ab84'
    '6ad8fe76d2a27b63ec0027474aec72e1c0f6fbfb427d9702273437649d561ccb'
    '6b0491298155dd1398e04c48f529efa48a3f76131314b596476a8ef106995e71'
    '711412375611bf71f63246f7ee3a639e6a6db133b2e59cd1245f3e4b19a068ec'
    '4eeed7c502e5b09d00ec20d17a376bbe01904c964bc9fcc837a42e3cd3356824'
    '997d61cbf5d9b222e46e98fc5c48ea98b5213e10ebd24916429c63a641e701c7',
  ),
  _h('10001'),
  _h(
    '15cacdfc1b604758d4b1d4123547b0052e5ff9b3663e9d085e86b309c0979fd9'
    'f2562fe356e3ef933bed95d02523983c04a5933badf81d4d190de9213e3b6495'
    '76f0cc56da2f3f6072a691df86cebd91f5898a2587f1ef2a307a09ab2708fe9f'
    'afe7b6f5e7787eb4cb042deab74f41127770cdaefde7d61a70200fc0f43dc779'
    'd3d2101b9fa120bdc960efa47b777f3fe46b7b2bf2590fc4aeaea1e71977f32b'
    'c2bfa72198c4aa38fc456e34b2aa9b6fc0fb579e6ea13534045b25805ec7f509'
    '8b9b71f6f0b8ea87db93e129e3028464a16ca723c41c210efe4c0070889834bb'
    '95f817f31f6df8a9d9aeb53e018ff308844fe1cff562c8e3d6b0261de0c53661',
  ),
  _h(
    'e206597e4f0c0789941e92eabd7c5c1b7690424d9991afa5fa4638f0e8d93d62'
    '340a1ab877180ac444ef17c38cbd5e7a571fd706fa4951dd06bbcdb1c23f586b'
    'cdf953eebf0dae05dabea9fd7d306418f21ecbf18a915b7714265a44911be7c5'
    'cbb2440c8fbc23a931b9576b2074f2e7f1b180b0e3803c3a2628d32325af3e37',
  ),
  _h(
    'c4868a193e45383276814fb3a6ae74bb80df249c8742340233b8cc61fb81784f'
    '37b527d1fa7e136d0422daca3be06b2cd548abaf2f9e220c2bd8d0b0196200cf'
    '9b655ef026cc8e8669b543648b7634ecb1999b40f8d5b08d96f91fcf8b7231a8'
    '667b9751810404dad9897789be850b1d5c52385b6c5a30bb67aff874374610f1',
  ),
);

const String _oidP256 = '1.2.840.10045.3.1.7';
const String _oidBrainpoolP256r1 = '1.3.36.3.3.2.8.1.1.7';

/// The EC CSCA (P-256): anchors the ECDSA chains.
final EcTestKey cscaEcKey = EcTestKey(
  _h('da520411c2d2146c0ecb4ec7e0c34f2c46c0fb6bd60e3cffb4f988107e69dec4'),
  'secp256r1',
  _oidP256,
);

/// The EC Document Signer (P-256).
final EcTestKey dscEcKey = EcTestKey(
  _h('88291fc5732d7c55627bf18143b839db28e195ebed0add209897de0407c0062'),
  'secp256r1',
  _oidP256,
);

/// The same curve carried as **explicit** `ECParameters`.
final EcTestKey dscEcExplicitKey = EcTestKey(
  _h('4c3b520e18f43e48108903d6778c8b84f9e6eb90d25a80e3ddd75721622b7db5'),
  'secp256r1',
  _oidP256,
  explicitParams: true,
);

/// The brainpoolP256r1 Document Signer.
final EcTestKey dscBrainpoolKey = EcTestKey(
  _h('4ea9029f276f901e8bbcad2a2c051bf9e553ff01a48cc65538fdc547c6dc9c18'),
  'brainpoolp256r1',
  _oidBrainpoolP256r1,
);

// ===========================================================================
// Deterministic randomness
// ===========================================================================

/// A `SecureRandom` whose stream is `SHA-256(seed ‖ counter)`, so ECDSA `k`
/// and PSS salts are reproducible and the committed fixtures stay stable.
class DeterministicRandom implements SecureRandom {
  DeterministicRandom(this._seed);

  final String _seed;
  int _counter = 0;
  final List<int> _buffer = [];

  @override
  String get algorithmName => 'DeterministicRandom';

  void _fill() {
    _buffer.addAll(calcSHA256Hash(ascii.encode('$_seed/${_counter++}')));
  }

  @override
  Uint8List nextBytes(int count) {
    while (_buffer.length < count) {
      _fill();
    }
    final out = Uint8List.fromList(_buffer.sublist(0, count));
    _buffer.removeRange(0, count);
    return out;
  }

  @override
  int nextUint8() => nextBytes(1)[0];

  @override
  int nextUint16() {
    final b = nextBytes(2);
    return (b[0] << 8) | b[1];
  }

  @override
  int nextUint32() {
    final b = nextBytes(4);
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
  }

  @override
  BigInt nextBigInteger(int bitLength) {
    final bytes = nextBytes((bitLength + 7) ~/ 8);
    var v = BigInt.zero;
    for (final b in bytes) {
      v = (v << 8) | BigInt.from(b);
    }
    return v >> (bytes.length * 8 - bitLength);
  }

  @override
  void seed(covariant Object params) {}
}

// ===========================================================================
// Signing
// ===========================================================================

/// Signature-algorithm OIDs the generator can emit.
const String sigSha1Rsa = '1.2.840.113549.1.1.5';
const String sigSha256Rsa = '1.2.840.113549.1.1.11';
const String sigSha384Rsa = '1.2.840.113549.1.1.12';
const String sigSha512Rsa = '1.2.840.113549.1.1.13';
const String sigRsaEncryption = '1.2.840.113549.1.1.1';
const String sigRsassaPss = '1.2.840.113549.1.1.10';
const String sigEcdsaSha256 = '1.2.840.10045.4.3.2';
const String sigDsaWithSha1 = '1.2.840.10040.4.3';

const String digestSha1 = '1.3.14.3.2.26';
const String digestSha224 = '2.16.840.1.101.3.4.2.4';
const String digestSha256 = '2.16.840.1.101.3.4.2.1';
const String digestSha384 = '2.16.840.1.101.3.4.2.2';
const String digestSha512 = '2.16.840.1.101.3.4.2.3';

const Map<String, String> _digestNameForOid = {
  digestSha1: 'SHA1',
  digestSha224: 'SHA224',
  digestSha256: 'SHA256',
  digestSha384: 'SHA384',
  digestSha512: 'SHA512',
};

const Map<String, String> _rsaSigDigest = {
  sigSha1Rsa: 'SHA1',
  sigSha256Rsa: 'SHA256',
  sigSha384Rsa: 'SHA384',
  sigSha512Rsa: 'SHA512',
};

const Map<String, String> _digestInfoOids = {
  'SHA1': '06052b0e03021a',
  'SHA224': '0609608648016503040204',
  'SHA256': '0609608648016503040201',
  'SHA384': '0609608648016503040202',
  'SHA512': '0609608648016503040203',
};

Digest _digest(String name) => switch (name) {
  'SHA1' => SHA1Digest(),
  'SHA224' => SHA224Digest(),
  'SHA256' => SHA256Digest(),
  'SHA384' => SHA384Digest(),
  'SHA512' => SHA512Digest(),
  _ => throw ArgumentError('unknown digest $name'),
};

/// `RSASSA-PSS-params` (RFC 4055) for [digestName] with an equal-length salt.
Uint8List pssParameters(String digestName) {
  final oid = _digestNameForOid.entries
      .firstWhere((e) => e.value == digestName)
      .key;
  final saltLength = _digest(digestName).digestSize;
  return Der.seq([
    Der.explicit(0, Der.seq([Der.oid(oid), Der.nul()])),
    Der.explicit(
      1,
      Der.seq([
        Der.oid('1.2.840.113549.1.1.8'),
        Der.seq([Der.oid(oid), Der.nul()]),
      ]),
    ),
    Der.explicit(2, Der.int32(saltLength)),
    Der.explicit(3, Der.int32(1)),
  ]);
}

/// The `AlgorithmIdentifier` for a signature OID (NULL parameters for the RSA
/// forms, absent for ECDSA, the RFC 4055 structure for PSS).
Uint8List signatureAlgorithmIdentifier(String oid, {Uint8List? pssParams}) {
  if (oid == sigRsassaPss) {
    return Der.seq([Der.oid(oid), pssParams ?? pssParameters('SHA256')]);
  }
  if (oid.startsWith('1.2.840.10045.4')) {
    return Der.seq([Der.oid(oid)]);
  }
  return Der.seq([Der.oid(oid), Der.nul()]);
}

/// Signs [data] under [key] with [sigAlgOid].
///
/// [signerDigestOid] supplies the digest for the plain-`rsaEncryption` form
/// (RFC 3370 §3.2), which carries none of its own.
Uint8List testSign({
  required TestKeyPair key,
  required String sigAlgOid,
  required List<int> data,
  String? signerDigestOid,
  Uint8List? pssParams,
  String randomSeed = 'ws14',
}) {
  if (sigAlgOid == sigRsassaPss) {
    final rsa = key as RsaTestKey;
    final params = pssParams ?? pssParameters('SHA256');
    final digestName = _pssDigestName(params);
    final digest = _digest(digestName);
    final signer = PSSSigner(RSAEngine(), digest, _digest(digestName))
      ..init(
        true,
        ParametersWithSaltConfiguration(
          PrivateKeyParameter<RSAPrivateKey>(
            RSAPrivateKey(rsa.n, rsa.d, rsa.p, rsa.q),
          ),
          DeterministicRandom('$randomSeed/pss'),
          digest.digestSize,
        ),
      );
    return signer.generateSignature(Uint8List.fromList(data)).bytes;
  }
  if (sigAlgOid == sigRsaEncryption || _rsaSigDigest.containsKey(sigAlgOid)) {
    final rsa = key as RsaTestKey;
    final digestName =
        _rsaSigDigest[sigAlgOid] ??
        _digestNameForOid[signerDigestOid ?? digestSha256]!;
    final signer = RSASigner(_digest(digestName), _digestInfoOids[digestName]!)
      ..init(
        true,
        PrivateKeyParameter<RSAPrivateKey>(
          RSAPrivateKey(rsa.n, rsa.d, rsa.p, rsa.q),
        ),
      );
    return signer.generateSignature(Uint8List.fromList(data)).bytes;
  }
  if (sigAlgOid.startsWith('1.2.840.10045.4')) {
    final ec = key as EcTestKey;
    final digestName = switch (sigAlgOid) {
      '1.2.840.10045.4.1' => 'SHA1',
      '1.2.840.10045.4.3.1' => 'SHA224',
      '1.2.840.10045.4.3.2' => 'SHA256',
      '1.2.840.10045.4.3.3' => 'SHA384',
      _ => 'SHA512',
    };
    final signer = ECDSASigner(_digest(digestName))
      ..init(
        true,
        ParametersWithRandom(
          PrivateKeyParameter<ECPrivateKey>(ECPrivateKey(ec.d, ec.domain)),
          DeterministicRandom('$randomSeed/ecdsa'),
        ),
      );
    final sig =
        signer.generateSignature(Uint8List.fromList(data)) as ECSignature;
    return Der.seq([Der.integer(sig.r), Der.integer(sig.s)]);
  }
  throw ArgumentError('the generator cannot sign with $sigAlgOid');
}

String _pssDigestName(Uint8List params) {
  // The fixtures only ever build params through [pssParameters], so reading
  // the hash OID back out of the [0] field is enough.
  final hex = params.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  for (final e in _digestNameForOid.entries) {
    final oidHex = Der.oid(
      e.key,
    ).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
    if (hex.contains(oidHex)) {
      return e.value;
    }
  }
  return 'SHA256';
}

// ===========================================================================
// Certificates
// ===========================================================================

/// A certificate's PEM block: the format upstream's `masterList.pem` and
/// [CscaTrustStore.fromPem] consume.
String certificateToPem(List<int> der) {
  final b64 = base64.encode(der);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    lines.add(b64.substring(i, i + 64 > b64.length ? b64.length : i + 64));
  }
  return '-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n'
      '-----END CERTIFICATE-----\n';
}

/// The RFC 5280 subjectKeyIdentifier method 1: SHA-1 of the BIT STRING body.
Uint8List keyIdentifierFor(TestKeyPair key) {
  final spki = key.spki();
  // The BIT STRING is the SPKI's second element; slice it back out.
  var i = 0;
  int readLen() {
    final b = spki[i++];
    if (b < 0x80) {
      return b;
    }
    var n = 0;
    for (var k = 0; k < (b & 0x7F); k++) {
      n = (n << 8) | spki[i++];
    }
    return n;
  }

  i = 1;
  readLen();
  i++; // algorithm SEQUENCE tag
  final algLen = readLen();
  i += algLen;
  i++; // BIT STRING tag
  final bitLen = readLen();
  return calcSHA1Hash(spki.sublist(i + 1, i + bitLen));
}

/// Builds an X.509 v3 certificate.
Uint8List buildCertificate({
  required Uint8List subject,
  required Uint8List issuer,
  required int serial,
  required DateTime notBefore,
  required DateTime notAfter,
  required TestKeyPair subjectKey,
  required TestKeyPair issuerKey,
  required String signatureAlgorithmOid,
  Uint8List? pssParams,
  bool isCa = false,
  bool includeBasicConstraints = true,
  bool includeKeyUsage = true,
  bool keyCertSign = true,
  bool includeSki = true,
  bool includeAki = true,
  String randomSeed = 'cert',
}) {
  final algId = signatureAlgorithmIdentifier(
    signatureAlgorithmOid,
    pssParams: pssParams,
  );
  final extensions = <List<int>>[
    if (includeBasicConstraints)
      Der.seq([
        Der.oid('2.5.29.19'),
        Der.boolean(true),
        Der.octetString(Der.seq([if (isCa) Der.boolean(true)])),
      ]),
    if (includeKeyUsage)
      Der.seq([
        Der.oid('2.5.29.15'),
        Der.boolean(true),
        Der.octetString(
          isCa
              ? Der.tagged(0x03, keyCertSign ? [0x01, 0x06] : [0x01, 0x02])
              : Der.tagged(0x03, [0x07, 0x80]),
        ),
      ]),
    if (includeSki)
      Der.seq([
        Der.oid('2.5.29.14'),
        Der.octetString(Der.octetString(keyIdentifierFor(subjectKey))),
      ]),
    if (includeAki)
      Der.seq([
        Der.oid('2.5.29.35'),
        Der.octetString(
          Der.seq([Der.implicitPrimitive(0, keyIdentifierFor(issuerKey))]),
        ),
      ]),
  ];

  final tbs = Der.seq([
    Der.explicit(0, Der.int32(2)), // v3
    Der.int32(serial),
    algId,
    issuer,
    Der.seq([Der.time(notBefore), Der.time(notAfter)]),
    subject,
    subjectKey.spki(),
    Der.explicit(3, Der.seq(extensions)),
  ]);

  final signature = testSign(
    key: issuerKey,
    sigAlgOid: signatureAlgorithmOid,
    data: tbs,
    pssParams: pssParams,
    randomSeed: randomSeed,
  );
  return Der.seq([tbs, algId, Der.bitString(signature)]);
}

// ===========================================================================
// CMS SignedData (SOD + master list)
// ===========================================================================

/// Builds a CMS `SignedData` `ContentInfo`.
///
/// Every knob below exists to author one enumerated fixture: the strictness
/// cases flip [eContentType] / [contentTypeAttributeOid] /
/// [includeSignedAttributes], the certless case empties [certificates], the
/// bad-signature case sets [corruptSignature], and the BER case sets
/// [indefiniteLengths].
Uint8List buildCmsSignedData({
  required String eContentType,
  required List<int> eContent,
  required List<Uint8List> certificates,
  required TestKeyPair signerKey,
  required Uint8List signerIssuer,
  required int signerSerial,
  String digestOid = digestSha256,
  String signatureAlgorithmOid = sigSha256Rsa,
  Uint8List? pssParams,
  String? contentTypeAttributeOid,
  bool includeSignedAttributes = true,
  bool corruptSignature = false,
  bool corruptMessageDigest = false,
  bool indefiniteLengths = false,
  Uint8List Function(Uint8List)? signatureTransform,
  String? signerInfoAlgorithmOverride,
  String randomSeed = 'cms',
}) {
  final digestName = _digestNameForOid[digestOid]!;
  final messageDigest = calcHash(eContent, digestName);
  if (corruptMessageDigest) {
    messageDigest[0] ^= 0xFF;
  }

  final attributes = <List<int>>[
    Der.seq([
      Der.oid(oidContentTypeAttribute),
      Der.set([Der.oid(contentTypeAttributeOid ?? eContentType)]),
    ]),
    Der.seq([
      Der.oid(oidMessageDigestAttribute),
      Der.set([Der.octetString(messageDigest)]),
    ]),
  ];
  final signedAttrsSet = Der.setOf(attributes);
  // `[0] IMPLICIT` on the wire; the signature is over the SET-tagged form
  // (RFC 5652 §5.4), the byte-swap the port reproduces.
  final signedAttrsImplicit = Uint8List.fromList(signedAttrsSet)..[0] = 0xA0;

  final signedBytes = includeSignedAttributes
      ? signedAttrsSet
      : Uint8List.fromList(eContent);
  var signature = testSign(
    key: signerKey,
    sigAlgOid: signatureAlgorithmOid,
    data: signedBytes,
    signerDigestOid: digestOid,
    pssParams: pssParams,
    randomSeed: randomSeed,
  );
  if (signatureTransform != null) {
    signature = signatureTransform(signature);
  }
  if (corruptSignature) {
    signature[signature.length - 1] ^= 0xFF;
  }

  final signerInfo = Der.seq([
    Der.int32(1),
    Der.seq([signerIssuer, Der.int32(signerSerial)]),
    Der.seq([Der.oid(digestOid), Der.nul()]),
    if (includeSignedAttributes) signedAttrsImplicit,
    // `signerInfoAlgorithmOverride` writes a *different* algorithm identifier
    // than the one the bytes were actually signed with, the fixture shape the
    // "unsupported algorithm" case needs, where resolution must fail before
    // any verify runs.
    signatureAlgorithmIdentifier(
      signerInfoAlgorithmOverride ?? signatureAlgorithmOid,
      pssParams: pssParams,
    ),
    Der.octetString(signature),
  ]);

  final encapContent = indefiniteLengths
      ? Der.indefinite(0x30, [
          ...Der.oid(eContentType),
          ...Der.indefinite(0xA0, Der.octetString(eContent)),
        ])
      : Der.seq([
          Der.oid(eContentType),
          Der.explicit(0, Der.octetString(eContent)),
        ]);

  final signedDataBody = <int>[
    ...Der.int32(3),
    ...Der.set([
      Der.seq([Der.oid(digestOid), Der.nul()]),
    ]),
    ...encapContent,
    if (certificates.isNotEmpty)
      ...Der.implicitConstructed(0, [for (final c in certificates) ...c]),
    ...Der.set([signerInfo]),
  ];

  if (indefiniteLengths) {
    return Der.indefinite(0x30, [
      ...Der.oid(oidSignedData),
      ...Der.indefinite(0xA0, Der.indefinite(0x30, signedDataBody)),
    ]);
  }
  return Der.seq([
    Der.oid(oidSignedData),
    Der.explicit(0, Der.seq([signedDataBody])),
  ]);
}

/// `LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm,
/// dataGroupHashValues, ldsVersionInfo OPTIONAL }`: the SOD's eContent.
/// With [ldsVersionInfo] (the raw `"aabb"` / `"aabbcc"` strings) the object
/// is V1 and the member is emitted fourth, where 9303-10 §4.6.2.1 puts it;
/// without it the object is V0.
Uint8List buildLdsSecurityObject({
  required Map<int, List<int>> dataGroupHashes,
  String digestOid = digestSha256,
  (String, String)? ldsVersionInfo,
}) => Der.seq([
  Der.int32(ldsVersionInfo == null ? 0 : 1),
  Der.seq([Der.oid(digestOid), Der.nul()]),
  Der.seq([
    for (final e in dataGroupHashes.entries)
      Der.seq([Der.int32(e.key), Der.octetString(e.value)]),
  ]),
  if (ldsVersionInfo != null)
    Der.seq([
      Der.printableString(ldsVersionInfo.$1),
      Der.printableString(ldsVersionInfo.$2),
    ]),
]);

/// A complete EF.SOD file (`77` wrapper + CMS), signed for real.
Uint8List buildSignedSod({
  required Map<int, List<int>> dataGroupFiles,
  required List<Uint8List> certificates,
  required TestKeyPair signerKey,
  required Uint8List signerIssuer,
  required int signerSerial,
  String ldsDigestOid = digestSha256,
  String cmsDigestOid = digestSha256,
  String signatureAlgorithmOid = sigSha256Rsa,
  Uint8List? pssParams,
  String eContentType = oidLdsSecurityObject,
  String? contentTypeAttributeOid,
  bool includeSignedAttributes = true,
  bool corruptSignature = false,
  bool corruptMessageDigest = false,
  bool indefiniteLengths = false,
  bool wrapInFileTag = true,
  Uint8List Function(Uint8List)? signatureTransform,
  String? signerInfoAlgorithmOverride,
  String randomSeed = 'sod',
  (String, String)? ldsVersionInfo,
}) {
  final digestName = _digestNameForOid[ldsDigestOid]!;
  final lds = buildLdsSecurityObject(
    dataGroupHashes: {
      for (final e in dataGroupFiles.entries)
        e.key: calcHash(e.value, digestName),
    },
    digestOid: ldsDigestOid,
    ldsVersionInfo: ldsVersionInfo,
  );
  final cms = buildCmsSignedData(
    eContentType: eContentType,
    eContent: lds,
    certificates: certificates,
    signerKey: signerKey,
    signerIssuer: signerIssuer,
    signerSerial: signerSerial,
    digestOid: cmsDigestOid,
    signatureAlgorithmOid: signatureAlgorithmOid,
    pssParams: pssParams,
    contentTypeAttributeOid: contentTypeAttributeOid,
    includeSignedAttributes: includeSignedAttributes,
    corruptSignature: corruptSignature,
    corruptMessageDigest: corruptMessageDigest,
    indefiniteLengths: indefiniteLengths,
    signatureTransform: signatureTransform,
    signerInfoAlgorithmOverride: signerInfoAlgorithmOverride,
    randomSeed: randomSeed,
  );
  return wrapInFileTag ? Der.tagged(0x77, cms) : cms;
}

/// A signed CSCA master list (ICAO 9303-12 §9).
Uint8List buildMasterList({
  required List<Uint8List> cscaCertificates,
  required List<Uint8List> signerCertificates,
  required TestKeyPair signerKey,
  required Uint8List signerIssuer,
  required int signerSerial,
  int version = 0,
  String eContentType = oidCscaMasterList,
  String signatureAlgorithmOid = sigSha256Rsa,
  bool corruptSignature = false,
  bool indefiniteLengths = false,
  String randomSeed = 'ml',
}) {
  final content = Der.seq([
    Der.int32(version),
    Der.set([for (final c in cscaCertificates) c]),
  ]);
  return buildCmsSignedData(
    eContentType: eContentType,
    eContent: content,
    certificates: signerCertificates,
    signerKey: signerKey,
    signerIssuer: signerIssuer,
    signerSerial: signerSerial,
    signatureAlgorithmOid: signatureAlgorithmOid,
    corruptSignature: corruptSignature,
    indefiniteLengths: indefiniteLengths,
    randomSeed: randomSeed,
  );
}
