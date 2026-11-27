#!/usr/bin/env python3
"""Independent oracle for the PACE mapping vectors.

Why this exists
---------------
The port completes DH-GM steps 3-4 and implements the Integrated Mapping. ICAO
9303 Part 11 publishes exactly three worked chains for that surface: App G.2
(DH-GM, RFC 5114 1024/160, AES-128), App H.1 (ECDH-IM, Brainpool P-256,
AES-128) and App H.2 (DH-IM, RFC 5114 1024/160, AES-128). Every other suite
combination the port implements (3DES-IM, AES-192-IM (the truncation note),
AES-256-IM, IM on other curves/groups, DH-GM on the 2048-bit groups) has no
published vector anywhere, and the surveyed ecosystem implements IM nowhere.
Their expectations are therefore *generated here*, by an
implementation written from the spec text and sharing no code with the Dart
port, and never frozen from the port's own output.

The synthetic rows of `ec_dh.json` follow the same "python oracle" discipline,
but their generator is out of tree (only the provenance tags in case names
survive). This script is committed, because for the non-published IM suites it
is the *only* reproducibility anchor.

Self-check first: `verify` recomputes all three published chains and compares
them against the values transcribed from the spec. If that passes, the same
code path is trusted to emit the synthetic rows.

Usage
-----
    python3 conformance/tools/pace_mapping_oracle.py verify
    python3 conformance/tools/pace_mapping_oracle.py emit-im        # pace_im.json synthetic rows
    python3 conformance/tools/pace_mapping_oracle.py emit-dh-gm     # pace_gm_dh.json synthetic rows
    python3 conformance/tools/pace_mapping_oracle.py emit-ec-dh     # ec_dh.json App G.2 step-3/4 rows
    python3 conformance/tools/pace_mapping_oracle.py leading-zero   # the forced-leading-zero session

Requires only `cryptography` (AES/3DES/CMAC primitives); all group, curve and
mapping arithmetic is plain Python integers.
"""

import hashlib
import json
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


def h(s):
    return bytes.fromhex("".join(s.split()))


# --------------------------------------------------------------------------
# Standardized domain parameters (P11 §9.5.1 Table 12 ids)
# --------------------------------------------------------------------------

# RFC 5114 §2.1: 1024-bit MODP Group with 160-bit Prime Order Subgroup (id 0).
DH_1024_160 = dict(
    p=int(
        "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
        "6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF"
        "ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
        "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16),
    g=int(
        "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31"
        "266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4"
        "D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
        "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16),
    q=int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16),
)

# RFC 5114 §2.2: 2048-bit MODP Group with 224-bit Prime Order Subgroup (id 1).
DH_2048_224 = dict(
    p=int(
        "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75"
        "E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6"
        "6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207"
        "C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836"
        "81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074"
        "15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8"
        "BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29"
        "E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F", 16),
    g=int(
        "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3"
        "A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652"
        "BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A"
        "E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1"
        "19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC"
        "B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381"
        "B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD"
        "7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA", 16),
    q=int("801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB", 16),
)

# RFC 5114 §2.3: 2048-bit MODP Group with 256-bit Prime Order Subgroup (id 2).
DH_2048_256 = dict(
    p=int(
        "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00"
        "E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C"
        "209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B"
        "6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76"
        "B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E"
        "F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026"
        "C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103"
        "A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16),
    g=int(
        "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125"
        "10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62"
        "901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B"
        "777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193"
        "B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A"
        "DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915"
        "B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3"
        "2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659", 16),
    q=int("8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3", 16),
)

DH_GROUPS = {0: DH_1024_160, 1: DH_2048_224, 2: DH_2048_256}

CURVES = {
    # id: (name, p, a, b, Gx, Gy, n, cofactor)
    12: ("secp256r1",
         int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16),
         int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
         int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16),
         int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
         int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16),
         int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16), 1),
    13: ("brainpoolp256r1",
         int("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
         int("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
         int("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16),
         int("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", 16),
         int("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", 16),
         int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16), 1),
    10: ("secp224r1",
         int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", 16),
         int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", 16),
         int("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", 16),
         int("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", 16),
         int("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", 16),
         int("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16), 1),
}


# --------------------------------------------------------------------------
# Short-Weierstrass arithmetic over GF(p) (affine, textbook: this is an
# oracle, not production code)
# --------------------------------------------------------------------------

class Curve:
    def __init__(self, cid):
        self.name, self.p, self.a, self.b, gx, gy, self.n, self.f = CURVES[cid]
        self.G = (gx, gy)

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
        R, k = None, k % self.n if P == self.G else k
        while k > 0:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R

    def on_curve(self, P):
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def encode(self, P):
        blen = (self.p.bit_length() + 7) // 8
        return b"\x04" + P[0].to_bytes(blen, "big") + P[1].to_bytes(blen, "big")


# --------------------------------------------------------------------------
# P11 §4.4.3.3.2: the Integrated Mapping
# --------------------------------------------------------------------------

C0_128 = h("a668892a7c41e3ca739f40b057d85904")
C1_128 = h("a4e136ac725f738b01c1f60217c188ad")
C0_256 = h("d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676")
C1_256 = h("54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517")


def im_params(cipher_alg, key_length):
    """(key bytes, block bytes, l bytes, c0, c1) for a PACE suite.

    §4.4.3.3.2: k is the key size of E; fixed at 128 bits for 3DES by the
    explicit "In case of DES, k is considered to be equal to 128 bits" rule;
    l is the smallest multiple of E's block size with l >= k. The 128-bit
    constant pair serves 3DES and AES-128, the 256-bit pair AES-192/256.
    """
    if cipher_alg == "DESede":
        k, block = 16, 8
    elif cipher_alg == "AES":
        k, block = key_length // 8, 16
    else:
        raise ValueError(cipher_alg)
    l = ((k + block - 1) // block) * block
    c0, c1 = (C0_128, C1_128) if l == 16 else (C0_256, C1_256)
    return k, block, l, c0, c1


def cbc_encrypt(cipher_alg, key, data):
    """E() in CBC mode, IV = 0 ([ISO/IEC 10116])."""
    if cipher_alg == "AES":
        algo, bs = algorithms.AES(key), 16
    else:
        # 2-key EDE: K1||K2 -> K1||K2||K1 (the Dart cipher layer's fix-up, and CommonCrypto's).
        algo, bs = algorithms.TripleDES(key[:16] + key[:8] if len(key) == 16 else key), 8
    enc = Cipher(algo, modes.CBC(b"\x00" * bs)).encryptor()
    return enc.update(data) + enc.finalize()


def R_p(s, t, p, cipher_alg, key_length):
    """Figure 2: k0 = E(t, s); x_i = E(k_{i-1}, c1); k_i = E(k_{i-1}, c0).

    Returns (blocks, blocks mod p). Only k_i is truncated to the key size:
    "the truncation is only necessary for AES-192".
    """
    k, block, l, c0, c1 = im_params(cipher_alg, key_length)
    assert len(t) == k, "t is k bits wide"
    assert len(s) == l, "s is l bits wide"
    n = -(-(p.bit_length() + 64) // (l * 8))
    ki = cbc_encrypt(cipher_alg, t, s)[:k]
    out = b""
    for _ in range(n):
        out += cbc_encrypt(cipher_alg, ki, c1)
        ki = cbc_encrypt(cipher_alg, ki, c0)[:k]
    return out, int.from_bytes(out, "big") % p


def f_g(x, p, q):
    """DH: ghat = x^((p-1)/q) mod p. Callers MUST check ghat != 1."""
    return pow(x, (p - 1) // q, p)


def f_G(curve, t):
    """ECDH: App B.2, affine coordinates. Requires p = 3 mod 4."""
    p, a, b = curve.p, curve.a, curve.b
    assert p % 4 == 3, "App B point encoding requires p = 3 mod 4"
    assert 0 < t < p
    alpha = (-t * t) % p
    asum = (alpha + alpha * alpha) % p
    X2 = (-b * pow(a, -1, p) % p) * ((1 + pow(asum, -1, p)) % p) % p
    X3 = alpha * X2 % p
    h2 = (pow(X2, 3, p) + a * X2 + b) % p
    U = pow(t, 3, p) * h2 % p
    A = pow(h2, p - 1 - (p + 1) // 4, p)
    if A * A % p * h2 % p == 1:
        P = (X2, A * h2 % p)
    else:
        P = (X3, A * U % p)
    return P if curve.f == 1 else curve.mul(curve.f, P)


# --------------------------------------------------------------------------
# Shared PACE tail: KDF (§9.7.1, SHA-1/SHA-256) and the §4.4.3.4 token
# --------------------------------------------------------------------------

def kdf(shared, cipher_alg, key_length, counter):
    digest = hashlib.sha1 if key_length == 128 else hashlib.sha256
    d = digest(shared + counter.to_bytes(4, "big")).digest()
    return d[:16] if key_length in (128,) else (d[:24] if key_length == 192 else d[:32])


def oid_bytes(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for v in parts[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.insert(0, (v & 0x7F) | 0x80)
            v >>= 7
        body += bytes(chunk)
    return body


def der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def token_input(oid, key_bytes, tag):
    ob = oid_bytes(oid)
    inner = b"\x06" + der_len(len(ob)) + ob + bytes([tag]) + der_len(len(key_bytes)) + key_bytes
    return b"\x7f\x49" + der_len(len(inner)) + inner


def auth_token(oid, cipher_alg, key_bytes, tag, kmac):
    data = token_input(oid, key_bytes, tag)
    if cipher_alg == "DESede":
        # ISO 9797-1 method 2 padding then retail MAC, not exercised by the
        # committed rows (every synthetic chain below uses AES/CMAC), so the
        # oracle deliberately declines rather than guessing.
        raise NotImplementedError("3DES retail-MAC tokens are not generated here")
    c = CMAC(algorithms.AES(kmac))
    c.update(data)
    return c.finalize()[:8]


def hexint(v):
    """Even-length lowercase hex: the runners' BigInt wire form (0 -> "")."""
    if v == 0:
        return ""
    s = "%x" % v
    return s if len(s) % 2 == 0 else "0" + s


def i2os(v, length):
    return v.to_bytes(length, "big")


def bn2bin(v):
    """BN_bn2bin parity: minimal big-endian, 0 -> b'' (the DH wire encoding)."""
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


# --------------------------------------------------------------------------
# verify: the published chains, recomputed
# --------------------------------------------------------------------------

def _check(label, got, want):
    ok = got == want
    print(("  PASS  " if ok else "  FAIL  ") + label)
    if not ok:
        print("        got  " + (got.hex() if isinstance(got, bytes) else hex(got)))
        print("        want " + (want.hex() if isinstance(want, bytes) else hex(want)))
    return ok


def verify():
    ok = True
    print("Standardized domain invariants")
    for gid, grp in sorted(DH_GROUPS.items()):
        sub = pow(grp["g"], grp["q"], grp["p"]) == 1 and (grp["p"] - 1) % grp["q"] == 0
        ok &= _check(f"RFC 5114 group {gid}: g has order q", sub, True)
    for cid in sorted(CURVES):
        c = Curve(cid)
        ok &= _check(f"{c.name}: on-curve generator", c.on_curve(c.G), True)
        # App B needs p = 3 mod 4; P-224 is the one standardized curve that fails.
        ok &= _check(f"{c.name}: usable with IM (p = 3 mod 4)", c.p % 4 == 3, cid != 10)

    g = DH_1024_160
    print("App G.2: DH-GM, RFC 5114 1024/160, AES-128")
    s = int("FA5B7E3E49753A0DB9178B7B9BD898C8", 16)
    x_t = int("5265030F751F4AD18B08AC565FC7AC952E41618D", 16)
    x_c = int("66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C", 16)
    y_t, y_c = pow(g["g"], x_t, g["p"]), pow(g["g"], x_c, g["p"])
    ok &= _check("mapping PK_IFD", bn2bin(y_t), h(
        "23FB3749EA030D2A25B278D2A562047ADE3F01B74F17A15402CB7352CA7D2B3E"
        "B71C343DB13D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC702489A4"
        "4D41DB914DE9613DC5E98C94160551C0DF86274B9359BC0490D01B03AD54022D"
        "CB4F57FAD6322497D7A1E28D46710F461AFE710FBBBC5F8BA166F4311975EC6C"))
    hh = pow(y_c, x_t, g["p"])
    ghat = pow(g["g"], s, g["p"]) * hh % g["p"]
    ok &= _check("mapped generator ghat", bn2bin(ghat), h(
        "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496"
        "84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301"
        "BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84"
        "EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5"))
    e_t = int("89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA", 16)
    e_c = int("A5B780126B7C980E9FCEA1D4539DA1D27C342DFA", 16)
    p_t, p_c = pow(ghat, e_t, g["p"]), pow(ghat, e_c, g["p"])
    K = pow(p_c, e_t, g["p"])
    Kb = i2os(K, 128)
    ok &= _check("shared secret K", Kb, h(
        "6BABC7B3A72BCD7EA385E4C62DB2625BD8613B24149E146A629311C4CA6698E3"
        "8B834B6A9E9CD7184BA8834AFF5043D436950C4C1E7832367C10CB8C314D40E5"
        "990B0DF7013E64B4549E2270923D06F08CFF6BD3E977DDE6ABE4C31D55C0FA2E"
        "465E553E77BDF75E3193D3834FC26E8EB1EE2FA1E4FC97C18C3F6CFFFE2607FD"))
    ks_enc, ks_mac = kdf(Kb, "AES", 128, 1), kdf(Kb, "AES", 128, 2)
    ok &= _check("KSenc", ks_enc, h("2F7F46ADCC9E7E521B45D192FAFA9126"))
    ok &= _check("KSmac", ks_mac, h("805A1D27D45A5116F73C54469462B7D8"))
    oid_dh_gm = "0.4.0.127.0.7.2.2.4.1.2"
    ok &= _check("T_IFD", auth_token(oid_dh_gm, "AES", bn2bin(p_c), 0x84, ks_mac),
                 h("B46DD9BD4D98381F"))
    ok &= _check("T_IC", auth_token(oid_dh_gm, "AES", bn2bin(p_t), 0x84, ks_mac),
                 h("917F37B5C0E6D8D1"))

    print("App H.1: ECDH-IM, Brainpool P-256, AES-128")
    c = Curve(13)
    s1 = h("2923BE84 E16CD6AE 529049F1 F1BBE9EB")
    t1 = h("5DD4CBFC 96F5453B 130D890A 1CDBAE32")
    blocks, xval = R_p(s1, t1, c.p, "AES", 128)
    ok &= _check("PRF blocks", blocks, h(
        "E4447E2DFB3586BAC05DDB00156B57FBB2179A3949294C97254189800C517BAA"
        "8DA0FF397ED8C445D3E421E4FEB57322"))
    ok &= _check("R_p(s,t)", i2os(xval, 32),
                 h("A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E"))
    Ghat = f_G(c, xval)
    ok &= _check("Ghat", c.encode(Ghat), h(
        "04 8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427"
        "   4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD"))
    sk_ic = int("107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A", 16)
    sk_ifd = int("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595", 16)
    pk_ic, pk_ifd = c.mul(sk_ic, Ghat), c.mul(sk_ifd, Ghat)
    K1 = i2os(c.mul(sk_ifd, pk_ic)[0], 32)
    ok &= _check("shared secret K", K1,
                 h("4F150FDE1D4F0E38E95017B891BAE17133A0DF45B0D3E18B60BA7BEAFDC2C713"))
    kmac1 = kdf(K1, "AES", 128, 2)
    ok &= _check("KEnc", kdf(K1, "AES", 128, 1), h("0D3FEB33251A6370893D62AE8DAAF51B"))
    ok &= _check("KMac", kmac1, h("B01E89E3D9E8719E586B50B4A7506E0B"))
    oid_ec_im = "0.4.0.127.0.7.2.2.4.4.2"
    ok &= _check("T_IC", auth_token(oid_ec_im, "AES", c.encode(pk_ifd), 0x86, kmac1),
                 h("75D4D96E8D5B0308"))
    ok &= _check("T_IFD", auth_token(oid_ec_im, "AES", c.encode(pk_ic), 0x86, kmac1),
                 h("450F02B86F6A0909"))

    print("App H.2: DH-IM, RFC 5114 1024/160, AES-128")
    s2 = h("FA5B7E3E 49753A0D B9178B7B 9BD898C8")
    t2 = h("B3A6DB3C 870C3E99 245E0D1C 06B747DE")
    blocks2, xval2 = R_p(s2, t2, g["p"], "AES", 128)
    ok &= _check("PRF blocks", blocks2, h(
        "EAB98D13E09052952AA729907C3C946184DEA0FE74AD2B3AF506F0A83018459C"
        "38099CD1F7FF4EA0A078DB1FAC1365505E3DC85500EF95E20B4EEF2E88489233"
        "BEE0546B472F994B618D168702406791DEEF3CB4810932EC278F3533FDB860EB"
        "4835C36FA4F1BF3FA0B828A718C96BDE88FBA38A3E6C35AAA10959251EB5FC71"
        "0FC187258995944C0F926E249373F485"))
    ok &= _check("R_p(s,t)", i2os(xval2, 128), h(
        "A0C7C50C002061A51CC87D254EF38068607417B6EE1B36473CFB800D2D2E5FA2"
        "B6980F01105D24FAB22ACD1BFA5C8A4C093ECDFAFE6D7125D42A843E33860383"
        "5CF19AFAFF75EFE21DC5F6AA1F9AE46C25087E7368166FB08C1E4627AFED7D93"
        "570417B790FF7F747E57F432B04E1236819E0DFEF5B6E77CA4999925328182D2"))
    ghat2 = f_g(xval2, g["p"], g["q"])
    ok &= _check("mapped generator ghat", i2os(ghat2, 128), h(
        "1D7D767F11E333BCD6DBAEF40E799E7A926B96973550656FF3C830726D118D61"
        "C276CDCC61D475CF03A98E0C0E79CAEBA5BE25578BD4551D0B10903236F0B0F9"
        "76852FA78EEA14EA0ACA87D1E91F688FE0DFF897BBE35A472621D343564B262F"
        "34223AE8FC59B664BFEDFA2BFE7516CA5510A6BBB633D517EC25D4E0BBAA16C2"))
    sk_ic2 = int(
        "020F018C7284B047FA7721A337EFB7ACB1440BB30C5252BD41C97C30C994BB78"
        "E9F0C5B32744D84017D21FFA6878396A6469CA283EF5C000DAF7D261A39AB886"
        "0ED4610AB5343390897AAB5A7787E4FAEFA0649C6A94FDF82D991E8E3FC332F5"
        "142729E7040A3F7D5A4D3CD75CBEE1F043C1CAD2DD484FEB4ED22B597D36688E", 16)
    sk_ifd2 = int(
        "4BD0E54740F9A028E6A515BFDAF967848C4F5F5FFF65AA0915947FFD1A0DF2FA"
        "6981271BC905F3551457B7E03AC3B8066DE4AA406C1171FB43DD939C4BA16175"
        "103BA3DEE16419AA248118F90CC36A3D6F4C373652E0C3CCE7F0F1D0C5425B36"
        "00F0F0D6A67F004C8BBA33F2B4733C7252445C1DFC4F1107203F71D2EFB28161", 16)
    pk_ic2, pk_ifd2 = pow(ghat2, sk_ic2, g["p"]), pow(ghat2, sk_ifd2, g["p"])
    K2 = i2os(pow(pk_ic2, sk_ifd2, g["p"]), 128)
    ok &= _check("shared secret K", K2, h(
        "419410D6C0A17A4C07C54872CE1CBCEB0A2705C1A434C8A89A4CFE41F1D78124"
        "CA7EC52BDE7615E5345E48AB1ABB6E7D1D59A57F3174084D3CA4570397C1F622"
        "28BDFDB2DA191EA2239E2C060DBE3BBC23C2FCD0AF12E0F9E0B99FCF91FF1959"
        "011D5798B2FCBC1F14FCC24E441F4C8F9B08D977E9498560E63E7FFAB3134EA7"))
    kmac2 = kdf(K2, "AES", 128, 2)
    ok &= _check("KEnc", kdf(K2, "AES", 128, 1), h("01AFC10CF87BE36D8179E87370171F07"))
    ok &= _check("KMac", kmac2, h("23F0FBD05FD6C7B8B88F4C8309669061"))
    oid_dh_im = "0.4.0.127.0.7.2.2.4.3.2"
    ok &= _check("T_IC", auth_token(oid_dh_im, "AES", bn2bin(pk_ifd2), 0x84, kmac2),
                 h("C2F04230187E1525"))
    ok &= _check("T_IFD", auth_token(oid_dh_im, "AES", bn2bin(pk_ic2), 0x84, kmac2),
                 h("55D61977CBF5307E"))

    print("\nALL PUBLISHED CHAINS REPRODUCED" if ok else "\nMISMATCH: do not emit")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# emit: the synthetic rows
# --------------------------------------------------------------------------

# Deterministic pseudo-nonces for the synthetic chains: SHA-256 of a label,
# truncated. Fixed here so the rows are reproducible from this file alone.
def synth_bytes(label, length):
    out = b""
    i = 0
    while len(out) < length:
        out += hashlib.sha256(f"ws15/{label}/{i}".encode()).digest()
        i += 1
    return out[:length]


def emit_im():
    """pace_im.json synthetic rows: every suite App H does not publish."""
    rows = []
    # DH-IM chains on all three groups x the three unpublished ciphers.
    dh_cases = [
        (0, "DESede", 128, "3DES (k=128, 64-bit blocks, l=128)"),
        (0, "AES", 192, "AES-192 (l=256, k_i truncated to 24 octets)"),
        (0, "AES", 256, "AES-256 (l=256)"),
        (1, "AES", 128, "AES-128 on the 2048/224 group"),
        (2, "AES", 128, "AES-128 on the 2048/256 group"),
    ]
    for gid, cipher, klen, note in dh_cases:
        g = DH_GROUPS[gid]
        k, block, l, _, _ = im_params(cipher, klen)
        s = synth_bytes(f"dh-im/{gid}/{cipher}{klen}/s", l)
        t = synth_bytes(f"dh-im/{gid}/{cipher}{klen}/t", k)
        blocks, xval = R_p(s, t, g["p"], cipher, klen)
        ghat = f_g(xval, g["p"], g["q"])
        assert ghat != 1
        rows.append({
            "name": f"python-oracle DH-IM chain: {note}, group {gid}",
            "op": "pace.imPseudoRandom",
            "runners": ["dart"],
            "input": {"s": s.hex(), "t": t.hex(), "p": hexint(g["p"]),
                      "cipherAlg": cipher, "keyLength": klen},
            "expect": {"out": {"blocks": blocks.hex(), "value": hexint(xval)}},
        })
        rows.append({
            "name": f"python-oracle f_g mapped generator: {note}, group {gid}",
            "op": "pace.imMapDh",
            "runners": ["dart"],
            "input": {"p": hexint(g["p"]), "q": hexint(g["q"]), "x": hexint(xval)},
            "expect": {"out": {"ghat": hexint(ghat)}},
        })
    # ECDH-IM on NIST P-256 (breaking the Brainpool monoculture) x AES-128/192/256
    # and 3DES.
    for cipher, klen, note in [("DESede", 128, "3DES"), ("AES", 128, "AES-128"),
                               ("AES", 192, "AES-192"), ("AES", 256, "AES-256")]:
        c = Curve(12)
        k, block, l, _, _ = im_params(cipher, klen)
        s = synth_bytes(f"ec-im/12/{cipher}{klen}/s", l)
        t = synth_bytes(f"ec-im/12/{cipher}{klen}/t", k)
        blocks, xval = R_p(s, t, c.p, cipher, klen)
        Ghat = f_G(c, xval)
        assert c.on_curve(Ghat)
        rows.append({
            "name": f"python-oracle ECDH-IM chain: {note}, NIST P-256",
            "op": "pace.imPseudoRandom",
            "runners": ["dart"],
            "input": {"s": s.hex(), "t": t.hex(), "p": hexint(c.p),
                      "cipherAlg": cipher, "keyLength": klen},
            "expect": {"out": {"blocks": blocks.hex(), "value": hexint(xval)}},
        })
        rows.append({
            "name": f"python-oracle f_G mapped generator: {note}, NIST P-256",
            "op": "pace.imMapEcdh",
            "runners": ["dart"],
            "input": {"curve": c.name, "x": hexint(xval)},
            "expect": {"out": {"ghat": c.encode(Ghat).hex()}},
        })
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def emit_dh_gm():
    """pace_gm_dh.json synthetic rows: DH-GM mapping on the 2048-bit groups."""
    rows = []
    for gid in (1, 2):
        g = DH_GROUPS[gid]
        x_t = int.from_bytes(synth_bytes(f"dh-gm/{gid}/xt", 28), "big") % g["q"]
        x_c = int.from_bytes(synth_bytes(f"dh-gm/{gid}/xc", 28), "big") % g["q"]
        nonce = int.from_bytes(synth_bytes(f"dh-gm/{gid}/s", 16), "big")
        y_c = pow(g["g"], x_c, g["p"])
        hh = pow(y_c, x_t, g["p"])
        ghat = pow(g["g"], nonce, g["p"]) * hh % g["p"]
        rows.append({
            "name": f"python-oracle DH-GM mapped generator: RFC 5114 group {gid}",
            "op": "pace.dhMappedGenerator",
            "runners": ["dart"],
            "input": {"p": hexint(g["p"]), "g": hexint(g["g"]), "x": hexint(x_t),
                      "peerPublic": bn2bin(y_c).hex(), "nonce": hexint(nonce)},
            "expect": {"out": {"ghat": hexint(ghat)}},
        })
        e_t = int.from_bytes(synth_bytes(f"dh-gm/{gid}/et", 28), "big") % g["q"]
        e_c = int.from_bytes(synth_bytes(f"dh-gm/{gid}/ec", 28), "big") % g["q"]
        p_c = pow(ghat, e_c, g["p"])
        K = pow(p_c, e_t, g["p"])
        blen = (g["p"].bit_length() + 7) // 8
        rows.append({
            "name": f"python-oracle DH-GM step-4 K (padded): group {gid}",
            "op": "pace.dhSharedSecretBytes",
            "runners": ["dart"],
            "input": {"p": hexint(g["p"]), "x": hexint(e_t), "peerPublic": hexint(p_c)},
            "expect": {"out": {"secret": i2os(K, blen).hex()}},
        })
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def emit_ec_dh():
    """ec_dh.json App G.2 step-3/4 primitive rows."""
    g = DH_1024_160
    ghat = int(
        "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496"
        "84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301"
        "BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84"
        "EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5", 16)
    e_t = int("89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA", 16)
    e_c = int("A5B780126B7C980E9FCEA1D4539DA1D27C342DFA", 16)
    p_t, p_c = pow(ghat, e_t, g["p"]), pow(ghat, e_c, g["p"])
    K = pow(p_c, e_t, g["p"])
    assert K == pow(p_t, e_c, g["p"])
    rows = [
        {"name": "App G.2 step-3 terminal ephemeral public key over the mapped generator",
         "op": "dhPublic",
         "input": {"p": hexint(g["p"]), "g": hexint(ghat), "x": hexint(e_t)},
         "expect": {"out": {"y": hexint(p_t)}}},
        {"name": "App G.2 step-3 chip ephemeral public key over the mapped generator",
         "op": "dhPublic",
         "input": {"p": hexint(g["p"]), "g": hexint(ghat), "x": hexint(e_c)},
         "expect": {"out": {"y": hexint(p_c)}}},
        {"name": "App G.2 step-4 shared secret (terminal side)",
         "op": "dhSharedSecret",
         "input": {"p": hexint(g["p"]), "x": hexint(e_t), "peerPublic": hexint(p_c)},
         "expect": {"out": {"secret": hexint(K)}}},
        {"name": "App G.2 step-4 shared secret (chip side: same value)",
         "op": "dhSharedSecret",
         "input": {"p": hexint(g["p"]), "x": hexint(e_c), "peerPublic": hexint(p_t)},
         "expect": {"out": {"secret": hexint(K)}}},
    ]
    # Registry coverage for the two 2048-bit groups, as `ec_dh.json` has for
    # the curves.
    for gid in (1, 2):
        grp = DH_GROUPS[gid]
        x = int.from_bytes(synth_bytes(f"ec-dh/{gid}/x", 32), "big") % grp["q"]
        y = int.from_bytes(synth_bytes(f"ec-dh/{gid}/peer", 32), "big") % grp["q"]
        py = pow(grp["g"], y, grp["p"])
        rows.append({
            "name": f"python-oracle dhPublic on RFC 5114 group {gid}",
            "op": "dhPublic",
            "input": {"p": hexint(grp["p"]), "g": hexint(grp["g"]), "x": hexint(x)},
            "expect": {"out": {"y": hexint(pow(grp["g"], x, grp["p"]))}},
        })
        rows.append({
            "name": f"python-oracle dhSharedSecret on RFC 5114 group {gid}",
            "op": "dhSharedSecret",
            "input": {"p": hexint(grp["p"]), "x": hexint(x), "peerPublic": hexint(py)},
            "expect": {"out": {"secret": hexint(pow(py, x, grp["p"]))}},
        })
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def leading_zero():
    """Find a DH-GM session whose step-4 shared secret has a leading zero byte.

    This is the session that tells the two K paddings apart: upstream's
    right-padding and the port's left-padding agree on every other session. Searched over small ephemeral
    exponents against the App G.2 mapped generator so the whole session stays
    reproducible from published values.
    """
    g = DH_1024_160
    ghat = int(
        "7C9CBFE98F9FBDDA8D143506FA7D9306F4CB17E3C71707AFF5E1C1A123702496"
        "84D64EE37AF44B8DBD9D45BF6023919CBAA027AB97ACC771666C8E98FF483301"
        "BFA4872DEDE9034EDFACB70814166B7F360676829B826BEA57291B5AD69FBC84"
        "EF1E779032A305803F74341793E869742D401325B37EE8565FFCDEE618342DC5", 16)
    blen = (g["p"].bit_length() + 7) // 8
    e_t = 2
    for e_c in range(2, 200000):
        K = pow(ghat, e_t * e_c, g["p"])
        if K.bit_length() <= (blen - 1) * 8:
            p_c = pow(ghat, e_c, g["p"])
            p_t = pow(ghat, e_t, g["p"])
            padded = i2os(K, blen)
            relocated = bn2bin(K) + b"\x00" * (blen - len(bn2bin(K)))
            print(json.dumps({
                "terminalEphemeralPrivateKey": hexint(e_t),
                "chipEphemeralPrivateKey": hexint(e_c),
                "terminalEphemeralPublicKey": bn2bin(p_t).hex(),
                "chipEphemeralPublicKey": bn2bin(p_c).hex(),
                "leadingZeroBytes": blen - len(bn2bin(K)),
                "sharedSecretPadded": padded.hex(),
                "sharedSecretRelocated": relocated.hex(),
                "ksEncFromPadded": kdf(padded, "AES", 128, 1).hex(),
                "ksMacFromPadded": kdf(padded, "AES", 128, 2).hex(),
                "ksEncFromRelocated": kdf(relocated, "AES", 128, 1).hex(),
                "ksMacFromRelocated": kdf(relocated, "AES", 128, 2).hex(),
            }, indent=2))
            return 0
    print("no leading-zero session found in the searched range", file=sys.stderr)
    return 1


COMMANDS = {
    "verify": verify,
    "emit-im": emit_im,
    "emit-dh-gm": emit_dh_gm,
    "emit-ec-dh": emit_ec_dh,
    "leading-zero": leading_zero,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(2)
    sys.exit(COMMANDS[sys.argv[1]]() or 0)
