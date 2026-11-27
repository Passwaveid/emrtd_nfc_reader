# Passive authentication fixtures: provenance and the OpenSSL cross-check

The `passive_auth` conformance suite and the `test/pki/` unit suites run
against a self-generated PKI, not against any real document or any real CSCA.
This file records where those bytes come from and how they were independently
verified.

## Where the bytes come from

| Layer | File |
|---|---|
| Key material + DER writer + certificate/CMS/master-list builders | [`../support/emrtd_test_pki.dart`](../support/emrtd_test_pki.dart) |
| The concrete fixture set (14 certificates, 20 SODs, 5 master lists) | [`../support/pki_fixtures.dart`](../support/pki_fixtures.dart) |
| The vector generator + drift guard | [`../conformance/passive_auth_vectors_test.dart`](../conformance/passive_auth_vectors_test.dart) |

The private keys were generated **once** with `openssl genrsa 2048` /
`openssl ecparam -genkey` (OpenSSL 3.0.13) and embedded verbatim; the
RSA-4096 DSC key (`dscRsa4096Key`, added 2026-08-25 with `openssl genrsa
4096`, same OpenSSL build) likewise; it backs `dscRsa4096Cert`, which only the
`x509.parse` surface reads (no SOD, no trust path). Every
randomized signature scheme (ECDSA's `k`, PSS's salt) draws from
`DeterministicRandom`. The generator is therefore a pure function: re-running
it reproduces `conformance/vectors/passive_auth.json` byte-for-byte, which is
what the drift guard asserts on every `flutter test` run. To regenerate after
a deliberate fixture change:

```sh
REGENERATE_PASSIVE_AUTH_VECTORS=1 flutter test \
    test/conformance/passive_auth_vectors_test.dart
```

Identities are fictional throughout (`C=UT`, "Utopia Ministry of Interior":
the ICAO specimen state), and the data groups are the specimen DG1/DG2 of
`../support/emrtd_fixtures.dart`, so the SODs here hash exactly the files the
SOD hash oracle suite pins.

Validity strategy: every certificate on a **valid** path runs
2015-01-01 to 2126-01-01, so a Swift oracle run on a real clock (OpenSSL has
no time injection) agrees with the Dart runner, which injects
`verificationTime`. The expired fixtures are expired on any real clock
(2018 to 2019).

## The cross-check, as run

OpenSSL 3.0.13 (Ubuntu), 2026-07-25, against the fixtures dumped from the
generator.

### CMS signatures: `openssl cms -verify -inform DER -in <f> -noverify`

| Fixture | Result |
|---|---|
| `sodRsaSha256` (PKCS#1 v1.5, SHA-256) | Verification successful |
| `sodRsaPssSha384` (RSASSA-PSS, SHA-384 params) | Verification successful |
| `sodEcdsaP256` | Verification successful |
| `sodEcdsaBrainpool` (brainpoolP256r1) | Verification successful |
| `sodEcdsaExplicitParams` (explicit `ECParameters` SPKI) | Verification successful |
| `sodRsaEncryptionSha512` (plain `rsaEncryption` + SHA-512) | Verification successful |
| `sodRsaSha1` | Verification successful |
| `cmsIndefiniteLengths` (BER indefinite lengths) | Verification successful |
| `masterListValid` | Verification successful |
| `masterListIndefiniteLengths` | Verification successful |
| **`sodEcdsaLeadingZero`** | **Verification failure**: expected, see below |

`sodEcdsaLeadingZero` pins an upstream quirk: its `ECDSA-Sig-Value` INTEGERs
carry an extra leading `0x00`, which strict DER forbids and `d2i_ECDSA_SIG`
rejects.
The CLI has no repair step, so it fails. **Upstream does not go through the
CLI**: `OpenSSLUtils.verifySignature` (`:456-520`) detects exactly this
malformation, strips the invalid prefix and re-encodes before verifying, so
both runners accept the fixture, by different mechanisms. The failure above is
the *reason the quirk exists*, recorded rather than papered over.

### Chains: `openssl verify -CAfile <anchors> <leaf>`

| Leaf | Anchors | Result |
|---|---|---|
| `dscRsaCert` | `cscaRsaCert` + `cscaEcCert` | OK |
| `dscEcCert` | same | OK |
| `dscBrainpoolCert` | same | OK |
| `mlSignerCert` | same | OK |
| `dscUnderNewCert` | `cscaOldCert` + `cscaLinkCert` (link chain) | OK |
| `dscRsa4096Cert` (2026-08-25, `Public-Key: (4096 bit)` per `openssl x509 -text`) | `cscaRsaCert` + `cscaEcCert` | OK |
| **`dscEcExplicitCert`** | `cscaRsaCert` + `cscaEcCert` | **error 94: Certificate public key has explicit ECC parameters** |

That last row is the whole reason upstream installs a verify callback:
`verifyTrustAndGetIssuerCertificate` (`:174-179`) ignores
`X509_V_ERR_EC_KEY_EXPLICIT_PARAMS` specifically, because ICAO documents use
explicit parameters and OpenSSL 3 rejects them by default. The port reaches
the same answer through its SPKI parser's explicit-parameters arm, so both
runners report `trusted`.

### Structure: `openssl asn1parse -inform DER -in <f>`

Spot-checked on `sodRsaSha256` (ContentInfo -> `pkcs7-signedData` -> SignedData
-> `sha256` digestAlgorithms -> eContentType `2.23.136.1.1.1` -> certificate set
-> SignerInfo) and on the upstream `masterList.pem` entries that a strict X.509
parse rejects: three Lithuanian CSCAs (indices 473-475) whose
`subjectKeyIdentifier` extension carries a bare key id with no inner
`OCTET STRING` wrapper. OpenSSL parses those certificates too and only fails
when the extension is *asked for*, so `X509Certificate.tryParse` ignores an
unreadable extension rather than rejecting the certificate. All 720 entries
parse.
