#!/usr/bin/env python3
"""Independent oracle for the CAM + PACE-password vectors.

Why this exists
---------------
The port implements two things ICAO 9303 barely publishes vectors for:

* **PACE-CAM** (P11 §4.4.3.5). App I is the *only* published chain: one
  suite (ECDH, Brainpool P-256, AES-128, MRZ password). Every negative shape
  and both other CAM suites (AES-192/256) have no published expectation
  anywhere, and the surveyed ecosystem implements the verify almost nowhere
  (gmrtd only).
* **CAN/PIN/PUK passwords** (P11 §9.7.3 Table 14, TR-03110-3 Table 5 +
  D.2.1.4). The *encodings* are specified; no worked example uses them:
  App G and App I are both MRZ.

So the expectations for all of that are generated *here*, by an implementation
written from the spec text that shares no code with the Dart port, and are
never frozen from the port's own output: the same "python oracle"
discipline as the other oracles in this directory, committed in tree.

Self-check first: `verify` recomputes the whole App I.1 chain (K, K_pi, the
encrypted nonce, the mapping, the ephemeral round, both session keys, the IV,
A_IC -> CA_IC and the §4.4.3.5.2 verification) against the values transcribed
from the spec. If that passes, the same code path is trusted for the
synthetics.

Usage
-----
    python3 conformance/tools/pace_cam_password_oracle.py verify
    python3 conformance/tools/pace_cam_password_oracle.py emit-passwords  # kdf_pace.json rows
    python3 conformance/tools/pace_cam_password_oracle.py emit-cam        # pace_cam.json rows

Requires only `cryptography` (AES primitives); all curve arithmetic is plain
Python integers.
"""

import hashlib
import json
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def h(s):
    return bytes.fromhex("".join(s.split()))


# --------------------------------------------------------------------------
# Standardized domain parameters (P11 §9.5.1 Table 12 ids): the curves the
# CAM suites can run on. RFC 5639 / FIPS 186-4 values, typed from the RFCs.
# --------------------------------------------------------------------------

BRAINPOOL_P256R1 = dict(
    name="brainpoolp256r1",
    p=int("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
    a=int("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
    b=int("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16),
    n=int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
    gx=int("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
    gy=int("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16),
)

BRAINPOOL_P384R1 = dict(
    name="brainpoolp384r1",
    p=int("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123"
          "ACD3A729901D1A71874700133107EC53", 16),
    a=int("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F"
          "8AA5814A503AD4EB04A8C7DD22CE2826", 16),
    b=int("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D5"
          "7CB4390295DBC9943AB78696FA504C11", 16),
    n=int("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7"
          "CF3AB6AF6B7FC3103B883202E9046565", 16),
    gx=int("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8"
           "E826E03436D646AAEF87B2E247D4AF1E", 16),
    gy=int("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF9912928"
           "0E4646217791811142820341263C5315", 16),
)

BRAINPOOL_P512R1 = dict(
    name="brainpoolp512r1",
    p=int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717"
          "D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16),
    a=int("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2"
          "DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16),
    b=int("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72"
          "BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16),
    n=int("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870"
          "553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16),
    gx=int("81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EF"
           "F3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", 16),
    gy=int("7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111"
           "B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", 16),
)

CURVES = {c["name"]: c for c in (BRAINPOOL_P256R1, BRAINPOOL_P384R1, BRAINPOOL_P512R1)}


class Curve:
    """Short-Weierstrass curve over F_p, affine arithmetic."""

    def __init__(self, spec):
        self.__dict__.update(spec)
        self.G = (self.gx, self.gy)
        assert self.on_curve(self.G), f"{self.name}: G is not on the curve"
        assert self.mul(self.n, self.G) is None, f"{self.name}: n*G != O"

    def on_curve(self, P):
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % self.p == 0:
            return None
        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, self.p) % self.p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p) % self.p
        x = (lam * lam - P[0] - Q[0]) % self.p
        return (x, (lam * (P[0] - x) - P[1]) % self.p)

    def mul(self, k, P):
        R, Q = None, P
        while k:
            if k & 1:
                R = self.add(R, Q)
            Q = self.add(Q, Q)
            k >>= 1
        return R

    @property
    def byte_len(self):
        return (self.n.bit_length() + 7) // 8

    def encode(self, P):
        f = (self.p.bit_length() + 7) // 8
        return b"\x04" + P[0].to_bytes(f, "big") + P[1].to_bytes(f, "big")


# --------------------------------------------------------------------------
# Primitives (TR-SAC 1.01 §4.2 KDF, AES-CBC, ISO 9797-1 method 2)
# --------------------------------------------------------------------------


def kdf(seed, counter, key_bits, cipher="AES"):
    """KDF(K, c): TR-SAC 1.01 §4.2 / P11 §9.7.1.

    The digest is SHA-1 for 3DES and AES-128, SHA-256 for AES-192/256; the key
    cut is the cipher's. 3DES takes a two-key EDE key as octets 1..16 with
    octets 1..8 repeated (§4.2.1), so a 128-bit 3DES key is 24 bytes on the
    wire; AES simply truncates to the key length (§4.2.2).
    """
    digest = hashlib.sha1 if key_bits == 128 else hashlib.sha256
    out = digest(seed + counter.to_bytes(4, "big")).digest()
    if cipher == "DESede":
        assert key_bits in (112, 128), "3DES is a 128-bit-labelled key only"
        return out[:16] + out[:8]
    return out[: key_bits // 8]


def aes_cbc_encrypt(key, data, iv=b"\x00" * 16):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def aes_cbc_decrypt(key, data, iv):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def pad2(data, block=16):
    """ISO/IEC 9797-1 padding method 2."""
    out = data + b"\x80"
    while len(out) % block:
        out += b"\x00"
    return out


def unpad2(data):
    """Strip method-2 padding; None when there is none to strip."""
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        return None
    return data[:i]


# --------------------------------------------------------------------------
# f(pi): P11 §9.7.3 Table 14 / TR-03110-3 Table 5, D.2.1.4
# --------------------------------------------------------------------------

MRZ_REF, CAN_REF, PIN_REF, PUK_REF = 1, 2, 3, 4


def f_pi(password_type, value):
    """The key seed. MRZ hashes; every other type is ISO 8859-1 octets."""
    if password_type == "mrz":
        return hashlib.sha1(value.encode("ascii")).digest()
    octets = value.encode("iso-8859-1")
    for i, b in enumerate(octets):
        if b <= 0x1F or 0x7F <= b <= 0x9F:
            raise ValueError(f"unassigned ISO 8859-1 code point at index {i}")
    return octets


def k_pi(password_type, value, key_bits=128, cipher="AES"):
    """KDF_pi(pi) = KDF(f(pi), 3)."""
    return kdf(f_pi(password_type, value), 3, key_bits, cipher)


# --------------------------------------------------------------------------
# CAM (P11 §4.4.3.5)
# --------------------------------------------------------------------------


def cam_iv(ks_enc):
    """IV = E(KS_Enc, -1): the all-ones block, one CBC block off a zero IV."""
    return aes_cbc_encrypt(ks_enc, b"\xff" * 16)


def cam_encrypt(ks_enc, ca_ic, curve):
    """A_IC = E(KS_Enc, CA_IC), CA_IC FE2OS to byteLen(n) then method-2 padded."""
    plain = pad2(ca_ic.to_bytes(curve.byte_len, "big"))
    return aes_cbc_encrypt(ks_enc, plain, cam_iv(ks_enc))


def cam_decrypt(ks_enc, a_ic, curve):
    """The terminal side. Returns CA_IC bytes, or None for every malformed shape."""
    if len(a_ic) == 0 or len(a_ic) % 16:
        return None
    plain = aes_cbc_decrypt(ks_enc, a_ic, cam_iv(ks_enc))
    ca_ic = unpad2(plain)
    if ca_ic is None or len(ca_ic) != curve.byte_len:
        return None
    value = int.from_bytes(ca_ic, "big")
    if value == 0 or value >= curve.n:
        return None
    return ca_ic


def cam_ca_ic(curve, sk_ic, sk_map_ic):
    """The chip side: CA_IC = (SK_IC)^-1 * SK_Map,IC mod n (§4.4.3.5.1)."""
    return pow(sk_ic, -1, curve.n) * sk_map_ic % curve.n


def cam_verify(curve, ca_ic, pk_ic, pk_map_ic):
    """§4.4.3.5.2: PK_Map,IC = KA(CA_IC, PK_IC, D_IC)."""
    return curve.mul(ca_ic, pk_ic) == pk_map_ic


# --------------------------------------------------------------------------
# The App I.1 chain, transcribed from ICAO 9303 Part 11 Appendix I.1
# --------------------------------------------------------------------------

APP_I = dict(
    mrz_info="C11T002JM496081222310314",
    K=h("894D03F1 48C6265E 89845B21 8856EA34 D00EF8E8"),
    K_pi=h("4E6F6FBF 7BE748B9 32C7B741 61BBA9DF"),
    s=h("658B860B C94DF6F0 44FCE6D5 C82CF8E5"),
    z=h("CB60E8E0 D85B76A9 BD304747 C2AD42E2"),
    sk_map_ifd=int("5D8BB87BD74D985A4B7D4325B9F7B976FE83512277340079"
                   "8914AA22738135CC", 16),
    pk_map_ifd_x=int("7F1D410ADB7DDB3B84BF1030800981A9105D7457B4A3ADE0"
                     "02384F3086C67EDE", 16),
    sk_map_ic=int("9E56A6B59C95D06ECE5CD10F983BB2F4F1943528E577F238"
                  "81D89D8C3BBEE0AA", 16),
    pk_map_ic=(int("A234236AA9B9621E8EFB73B5245C0E09D2576E5277183C12"
                   "08BDD55280CAE8B3", 16),
               int("04F365713A356E65A451E165ECC9AC0AC46E3771342C8FE5"
                   "AEDD092685338E23", 16)),
    shared_h_x=int("2C1DCC1773346492C6636A36EE4B965E292E9AAE7EE37736"
                   "EF58B9D0A043F348", 16),
    ghat_x=int("89F0B5EABF3BE293C75903A3986131925C9F5B515CA95AF4"
               "85DC7E886F03245D", 16),
    sk_eph_ifd=int("76ECFDAA9841C323A3F5FC5E88B88DB3EFF7E35EBF57A7E6"
                   "946CB630006C2120", 16),
    sk_eph_ic=int("CD626EF3C256E235FE8912CAC28279E626008EDA6B3A05C4"
                  "CF862A3BDAB79E78", 16),
    shared_secret=h("67950559 D0C06B4D 4B86972D 14460837"
                    "461087F8 419FDBC3 6AAF6CEA AC462832"),
    ks_enc=h("0A9DA4DB 03BDDE39 FC5202BC 44B2E89E"),
    ks_mac=h("4B1C0649 1ED5140C A2B537D3 44C6C0B1"),
    a_ic=h("1EEA964D AAE372AC 990E3EFD E6333353 BFC89A67 04D93DA8"
           "798CF77F 5B7A54BD 10CBA372 B42BE0B9 B5F28AA8 DE2F4F92"),
    ca_ic=h("85DC3FA9 3D0952BF A82F5FD1 89EE75BD"
            "82F11D1F 0B8ED4BF 5319AC9B 53C426B3"),
    iv=h("F6A3B75A 1E933941 DD7A13E2 520779DF"),
    pk_ic=(int("1872709494399E7470A6431BE25E83EEE24FEA568C2ED28D"
               "B48E05DB3A610DC8", 16),
           int("84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138"
               "A6E7A4A08F68E16F", 16)),
)


def verify():
    """Recompute App I.1 end to end and compare against the published values."""
    c = Curve(BRAINPOOL_P256R1)
    v = APP_I
    checks = []

    def check(label, got, want):
        checks.append((label, got == want, got, want))

    check("K = SHA-1(MRZ_information)",
          hashlib.sha1(v["mrz_info"].encode()).digest(), v["K"])
    check("K_pi = KDF(K, 3)", k_pi("mrz", v["mrz_info"]), v["K_pi"])
    check("z = E(K_pi, s)", aes_cbc_encrypt(v["K_pi"], v["s"]), v["z"])

    pk_map_ifd = c.mul(v["sk_map_ifd"], c.G)
    check("PK_Map,IFD", pk_map_ifd[0], v["pk_map_ifd_x"])
    check("PK_Map,IC", c.mul(v["sk_map_ic"], c.G), v["pk_map_ic"])
    shared = c.mul(v["sk_map_ic"], pk_map_ifd)
    check("H = KA(SK_Map,IC, PK_Map,IFD)", shared[0], v["shared_h_x"])
    ghat = c.add(c.mul(int.from_bytes(v["s"], "big"), c.G), shared)
    check("Ghat = s*G + H", ghat[0], v["ghat_x"])

    eph_ifd = c.mul(v["sk_eph_ifd"], ghat)
    eph_ic = c.mul(v["sk_eph_ic"], ghat)
    secret = c.mul(v["sk_eph_ifd"], eph_ic)[0].to_bytes(32, "big")
    check("shared secret (x-coordinate)", secret, v["shared_secret"])
    check("KS_Enc", kdf(secret, 1, 128), v["ks_enc"])
    check("KS_MAC", kdf(secret, 2, 128), v["ks_mac"])
    assert eph_ifd and eph_ic  # used only via the token, pinned Dart-side

    check("IV = E(KS_Enc, -1)", cam_iv(v["ks_enc"]), v["iv"])
    check("CA_IC = D(KS_Enc, A_IC) unpadded",
          cam_decrypt(v["ks_enc"], v["a_ic"], c), v["ca_ic"])
    check("A_IC = E(KS_Enc, CA_IC) round-trip",
          cam_encrypt(v["ks_enc"], int.from_bytes(v["ca_ic"], "big"), c),
          v["a_ic"])
    check("PK_Map,IC = KA(CA_IC, PK_IC, D_IC)",
          cam_verify(c, int.from_bytes(v["ca_ic"], "big"), v["pk_ic"],
                     v["pk_map_ic"]),
          True)
    # The §4.4.3.5.1 chip identity is self-consistent with the published
    # CA_IC: SK_IC is not published, but CA_IC * SK_IC = SK_Map,IC must hold
    # for whatever SK_IC the example used, i.e. SK_Map,IC / CA_IC mod n is a
    # scalar whose public key is PK_IC.
    sk_ic = pow(int.from_bytes(v["ca_ic"], "big"), -1, c.n) * v["sk_map_ic"] % c.n
    check("recovered SK_IC yields the published PK_IC", c.mul(sk_ic, c.G),
          v["pk_ic"])

    width = max(len(label) for label, *_ in checks)
    failed = 0
    for label, ok, got, want in checks:
        print(f"{label.ljust(width)}  {'OK' if ok else 'FAIL'}")
        if not ok:
            failed += 1
            print(f"    got  {got}\n    want {want}")
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
    return 1 if failed else 0


# --------------------------------------------------------------------------
# Synthetic emission
# --------------------------------------------------------------------------

# Synthetic passwords. CAN/PIN are numeric in the field; the PUK row exercises
# the printable-ASCII width, and the last row a legal high-Latin-1 character
# (0xC4 "A-umlaut") to prove the guard bounds the *unassigned* ranges only.
PASSWORDS = [
    ("can", "123456", "AES", 128),
    ("can", "500184", "DESede", 128),
    ("pin", "123456", "AES", 128),
    ("cuk", "9876543210", "AES", 128),
    ("can", "AB1234CD", "AES", 256),
    ("can", "MÜNCHEN01", "AES", 128),
]


def emit_passwords():
    rows = []
    for ptype, value, cipher, bits in PASSWORDS:
        seed = f_pi(ptype, value)
        rows.append({
            "name": f"pace.createPaceKey {ptype.upper()} \"{value}\" "
                    f"{cipher}-{bits} (synthetic: python oracle)",
            "op": "pace.createPaceKey",
            "runners": ["dart"],
            "input": {
                "passwordType": ptype,
                "password": value,
                "cipherAlgName": cipher,
                "keyLength": bits,
            },
            "expect": {"out": {
                "keyReference": {"mrz": 1, "can": 2, "pin": 3, "cuk": 4}[ptype],
                "keySeed": seed.hex(),
                "key": kdf(seed, 3, bits, cipher).hex(),
            }},
        })
    print(json.dumps(rows, indent=2))


def emit_cam():
    """AES-192/256 CAM chains and the decrypt negatives: no published source."""
    rows = []

    # Two further CAM suites. Session keys and chip scalars are arbitrary but
    # fixed; what the row pins is the decrypt chain at that key width.
    for bits, curve_name, ks_enc_hex, sk_ic_hex, sk_map_hex in (
        (192, "brainpoolp384r1",
         "3d1e5a7c9b0f2648ad8351726ec4f09b17538a2c6d4e0f91",
         "5c1d3f7a9b2e4068ad81c35f7092e4b6d8a0c2e4f60817293b5d7f91a3c5e70918"
         "2a4c6e80b1d3f5a7c9e1b3d5",
         "7e9c1a3b5d7f91a3c5e709182a4c6e80b1d3f5a7c9e1b3d5f7091a2b3c4d5e6f70"
         "81929a3b4c5d6e7f80912a3b"),
        (256, "brainpoolp512r1",
         "9f2b4d6081a3c5e709182a4c6e80b1d3f5a7c9e1b3d5f70912a3b4c5d6e7f809",
         "4a6c8e0b1d3f5a7c9e1b3d5f70912a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c"
         "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7081929a3b4c",
         "6b8d0f2a4c6e80b1d3f5a7c9e1b3d5f70912a3b4c5d6e7f8091a2b3c4d5e6f7081"
         "92a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819"),
    ):
        c = Curve(CURVES[curve_name])
        ks_enc = h(ks_enc_hex)
        sk_ic = int(sk_ic_hex, 16) % c.n
        sk_map_ic = int(sk_map_hex, 16) % c.n
        ca_ic = cam_ca_ic(c, sk_ic, sk_map_ic)
        a_ic = cam_encrypt(ks_enc, ca_ic, c)
        pk_ic = c.mul(sk_ic, c.G)
        pk_map_ic = c.mul(sk_map_ic, c.G)
        assert cam_verify(c, ca_ic, pk_ic, pk_map_ic)
        assert cam_decrypt(ks_enc, a_ic, c) == ca_ic.to_bytes(c.byte_len, "big")
        rows.append({
            "name": f"CAM decrypt AES-{bits} on {curve_name} "
                    f"(synthetic: python oracle)",
            "op": "pace.camDecryptChipAuthenticationData",
            "runners": ["dart"],
            "input": {"ksEnc": ks_enc.hex(), "encryptedData": a_ic.hex(),
                      "curve": curve_name},
            "expect": {"out": {"caIc": ca_ic.to_bytes(c.byte_len, "big").hex(),
                               "cause": None}},
        })
        rows.append({
            "name": f"CAM verify AES-{bits} on {curve_name} "
                    f"(synthetic: python oracle)",
            "op": "pace.camVerifyChipAuthenticationData",
            "runners": ["dart"],
            "input": {"curve": curve_name,
                      "caIc": ca_ic.to_bytes(c.byte_len, "big").hex(),
                      "chipPublicKey": c.encode(pk_ic).hex(),
                      "mappingPublicKey": c.encode(pk_map_ic).hex()},
            "expect": {"out": {"verified": True}},
        })

    # Decrypt negatives, all off the App I.1 material.
    c = Curve(BRAINPOOL_P256R1)
    v = APP_I
    ks_enc, a_ic = v["ks_enc"], v["a_ic"]

    def negative(name, key, data):
        assert cam_decrypt(key, data, c) is None, name
        rows.append({
            "name": name,
            "op": "pace.camDecryptChipAuthenticationData",
            "runners": ["dart"],
            "input": {"ksEnc": key.hex(), "encryptedData": data.hex(),
                      "curve": c.name},
            "expect": {"out": {"caIc": None, "cause": "malformed"}},
        })

    wrong_key = bytes(b ^ 0xFF for b in ks_enc)
    negative("CAM decrypt under the wrong KS_Enc; padding does not check out "
             "(synthetic: python oracle)", wrong_key, a_ic)
    negative("CAM decrypt of a truncated A_IC (not a block multiple) "
             "(synthetic: python oracle)", ks_enc, a_ic[:-1])
    negative("CAM decrypt of an empty A_IC "
             "(synthetic: python oracle)", ks_enc, b"")
    # An unpadded length != byteLen(n): pad a 31-byte CA_IC instead of 32.
    short = aes_cbc_encrypt(ks_enc, pad2(b"\x11" * 31), cam_iv(ks_enc))
    negative("CAM decrypt whose unpadded CA_IC is 31 bytes, not byteLen(n) "
             "(§4.4.5.6 FE2OS: synthetic, python oracle)",
             ks_enc, short)
    # CA_IC = 0: a degenerate scalar that cannot be an inverse mod n.
    zero = aes_cbc_encrypt(ks_enc, pad2(b"\x00" * 32), cam_iv(ks_enc))
    negative("CAM decrypt whose CA_IC is 0 (degenerate scalar) "
             "(synthetic: python oracle)", ks_enc, zero)
    # CA_IC = n: out of [1, n-1] by one.
    at_n = aes_cbc_encrypt(ks_enc, pad2(c.n.to_bytes(32, "big")), cam_iv(ks_enc))
    negative("CAM decrypt whose CA_IC equals the group order n "
             "(synthetic: python oracle)", ks_enc, at_n)
    # Method-2 padding absent altogether: exactly 32 bytes of ciphertext whose
    # plaintext ends in a non-zero, non-0x80 byte.
    unpadded = aes_cbc_encrypt(ks_enc, b"\x22" * 32, cam_iv(ks_enc))
    negative("CAM decrypt of an unpadded 32-byte plaintext (§4.4.3.5.3 makes "
             "method-2 padding mandatory; synthetic, python oracle)",
             ks_enc, unpadded)

    # A perturbed CA_IC that decrypts cleanly but does not verify.
    bad = (int.from_bytes(v["ca_ic"], "big") + 1) % c.n
    rows.append({
        "name": "CAM verify rejects a perturbed CA_IC (App I.1 + 1) "
                "(synthetic: python oracle)",
        "op": "pace.camVerifyChipAuthenticationData",
        "runners": ["dart"],
        "input": {"curve": c.name, "caIc": bad.to_bytes(32, "big").hex(),
                  "chipPublicKey": c.encode(v["pk_ic"]).hex(),
                  "mappingPublicKey": c.encode(v["pk_map_ic"]).hex()},
        "expect": {"out": {"verified": False}},
    })
    assert not cam_verify(c, bad, v["pk_ic"], v["pk_map_ic"])

    print(json.dumps(rows, indent=2))


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    return {
        "verify": verify,
        "emit-passwords": emit_passwords,
        "emit-cam": emit_cam,
    }[sys.argv[1]]() or 0


if __name__ == "__main__":
    sys.exit(main())
