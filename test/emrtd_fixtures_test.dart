/// Pins the session-test fixture builders against the vector-derived
/// literals they stand in for: [buildSpecimenSod] over DG1+DG2 must
/// reproduce [sodHex] byte-for-byte, so the DG14-covering SODs are built the
/// same way the vectors' SOD fixture was.
library;

import 'package:emrtd_core/emrtd_core.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/emrtd_chip_sim.dart';
import 'support/emrtd_fixtures.dart';

void main() {
  test('buildSpecimenSod with no DG14 reproduces the vector SOD fixture', () {
    expect(buildSpecimenSod(), hx(sodHex));
  });

  test('adding DG14 adds exactly one hash row', () {
    final dg14 = buildDg14(caOid: '0.4.0.127.0.7.2.2.3.2.2');
    final sod = SOD(buildSpecimenSod(dg14: dg14));
    final (algo, hashes) = parseSODSignatureContent(
      sod.getEncapsulatedContent(),
    );
    expect(algo, 'SHA256');
    expect(hashes.keys.map((k) => k.getName()).toList(), [
      'DG1',
      'DG2',
      'DG14',
    ]);
  });

  test('buildDg14 produces a parseable DG14 with the expected entries', () {
    final dg14 = DataGroup14(
      buildDg14(caOid: '0.4.0.127.0.7.2.2.3.2.2', keyId: 3),
    );
    expect(dg14.datagroupType, DataGroupId.DG14);
    expect(dg14.securityInfos, hasLength(2));

    final info = dg14.securityInfos.first as ChipAuthenticationInfo;
    expect(info.getObjectIdentifier(), '0.4.0.127.0.7.2.2.3.2.2');
    expect(info.getKeyId(), 3);

    final pk = dg14.securityInfos.last as ChipAuthenticationPublicKeyInfo;
    expect(pk.getObjectIdentifier(), '0.4.0.127.0.7.2.2.1.2');
    expect(pk.getKeyId(), 3);
    expect(pk.pubKey, isA<SpkiEcPublicKey>());
    expect((pk.pubKey as SpkiEcPublicKey).domain.domainName, 'brainpoolp256r1');
  });

  test('a public-key-less DG14 parses to exactly one info', () {
    final dg14 = DataGroup14(
      buildDg14(caOid: '0.4.0.127.0.7.2.2.3.2.2', withPublicKey: false),
    );
    expect(dg14.securityInfos, hasLength(1));
    expect(dg14.securityInfos.single, isA<ChipAuthenticationInfo>());
  });
}
