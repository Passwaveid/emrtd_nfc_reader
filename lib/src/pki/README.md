# src/pki

On-device **passive authentication** (ICAO 9303-11 §5.1): the CMS signature
over EF.SOD and the DSC-to-CSCA trust chain behind it. All of it is plain
Dart.

Upstream keeps all of this inside OpenSSL 3.x C calls
(`OpenSSLUtils.swift`, `X509Wrapper.swift`, and the verification slice of
`NFCPassportModel.swift`); the port does it in Dart over `pointycastle`,
with `package:crypto` for the digests, and adds no dependency.

## Files

| File | Content |
|---|---|
| `asn1_reader.dart` | The BER/DER walker the rest of the layer stands on: indefinite lengths, byte-exact raw slices, total on hostile input. Its own, rather than pointycastle's `ASN1Parser` |
| `cms_signed_data.dart` | RFC 5652 `SignedData`: the SOD's and the master list's container, including the `A0`-to-`31` signed-attributes re-tag (RFC 5652 §5.4) |
| `x509_certificate.dart` | The X.509 slice: TBS/DN/validity/SPKI + SKI/AKI/basicConstraints/keyUsage, and `X509CertificateInfo` (upstream's `X509Wrapper.getItemsAsDict`, plus the key width and curve taken from the parsed SPKI) |
| `signature_verifier.dart` | The **explicit algorithm allowlist**: PKCS#1 v1.5, params-driven RSASSA-PSS, ECDSA with a lenient DER decoder |
| `csca_trust_store.dart` | `CscaTrustStore`: a PEM concatenation (upstream's format), a list of DER certificates, or a signed ICAO 9303-12 §9 master list, verify-signature-first with signer pinning |
| `passive_auth.dart` | `verifySodSignature` / `verifyPassiveAuth` -> `PassiveAuthResult`, and `X509_verify_cert`-with-`flags=0` path building |

## Contracts

- **Verification never throws.** Hostile input becomes a verdict. Upstream
  force-unwraps the certificate stack and crashes, and swallows every
  signature failure; neither is reproduced. Only *trust-store construction*
  raises, and only through the `MasterListException` family.
- **One vocabulary**: outcomes `verified`/`invalid`/`unverifiable`, causes
  `dg_hash_mismatch`, `bad_ds_signature`, `malformed_sod`, `unknown_csca`,
  `expired_chain_element`, `unsupported_algorithm`, plus the composable
  `weak_digest` annotation. Upstream's three booleans are computable off the
  result. Precedence, highest first: tamper, unsupported, bad signature,
  chain.
- **The hash half is not here.** `lds/sod_hash_oracle.dart` checks the
  data-group hashes; this layer adds signature and trust on top of it.
- **Nothing is re-encoded.** Every signature input is a byte-exact slice of
  the original DER. The single exception is documented in
  `CmsSignerInfo.signedAttributesForVerification`, where a BER
  indefinite-length `signedAttrs` cannot be fixed by upstream's byte swap.
- **Building a trust store is expensive** (parsing every certificate of a
  1.5 MB PEM, or verifying a signed `.ml` first) and fully synchronous. Do it
  once, off the NFC path; lookups afterwards are indexed.
- **No revocation, ever**: no CRL, no OCSP, no Deviation Lists. That is
  upstream's posture too, and a deliberate limit, not an oversight.
- **The device clock is trusted** for validity windows. `verifyPassiveAuth`
  takes a `verificationTime` for a caller that wants another; the reader's
  own passive authentication uses the device clock.
