#!/usr/bin/env python3
"""Independent oracle for the ISO/IEC 39794-5 cases in dg2.json.

Why this exists
---------------
The port parses an ISO/IEC 39794-5 face record (DO '7F2E' in DG2) by walking
its DER by hand. A hand-built fixture written from the same reading of the
schema as the parser would agree with the parser even where both misread the
schema. This script removes that blind spot: every well-formed fixture is
DER-encoded by asn1tools from the ASN.1 modules themselves, and the expected
DataGroup2 fields are computed here from the decoded values, by a mapping
that shares no code with the Dart port.

Two module sets are used, both fetched at pinned bytes and never committed:
the ICAO eMRTD application profile (ICAO TR "ISO/IEC 39794-5 Application
Profile for eMRTDs" v1.00, Annex A, published on GitHub by ISO/IEC JTC1 SC17
WG3) for the shapes the profile allows, and the ISO/IEC 39794-1/-5 modules
from the ISO Standards Maintenance Portal for the shapes only the base
standard allows (a 3D representation, PNG, the [0] code form of an enum).
Malformed shapes no schema can encode are built byte by byte with tlv().

Self-check first: `verify` decodes ICAO's two "silver" DG2 datasets with the
profile modules and ISO's sample FaceImageDataBlock with the base modules,
checks a transcribed subset of their values, re-encodes each byte for byte,
and prints the DataGroup2 fields this oracle expects from them (the values
test/lds_test.dart pins when the files are present). If that passes, the
same compiled schemas are trusted to emit the rows.

Usage
-----
    python3 conformance/tools/dg2_39794_oracle.py verify
    python3 conformance/tools/dg2_39794_oracle.py emit    # the dg2.json rows

Requires asn1tools (`pip install asn1tools`; written against 0.169.0 on
Python 3.12) and network access to raw.githubusercontent.com and
standards.iso.org on first run; downloads are cached in $DG2_39794_CACHE
(default ~/.cache/dg2_39794) and checked against the SHA-256 values below
on every run.

This software makes use of the Schema from ISO/IEC 39794-1 and ISO/IEC
39794-5 within modifications permitted in the relevant ISO/IEC standard.
"""

import hashlib
import json
import os
import sys
import urllib.request

import asn1tools

AP = ("https://raw.githubusercontent.com/ICAO-TRIP-ISO-WG3/39794-5-AP/"
      "62d3e44fe600f8dd1ece8aada0d8d3795d890898/")
ISO = "https://standards.iso.org/iso-iec/39794/"
SOURCES = {
    "ap1.asn": (AP + "ID-ICAO-ISO-IEC-39794-1-ed-1-v1.asn",
                "931f80d7e1b47fc68917b8233f1b71b549b6f95a922b6aa7702bb084d1d76623"),
    "ap5.asn": (AP + "ID-ICAO-ISO-IEC-39794-5-ed-1-v1.asn",
                "30caef3cb56a5097776261443103031291c895dd1d14cf89f6b11d0ff4a0e798"),
    "silver-all.dat": (AP + "DG2-Dataset/DG2%20Silver%20Dataset%20(All%20Fields).dat",
                       "0b63e9fe8dde699d3be7eebeed754d722e4e73670039ed5237c293d56bc70034"),
    "silver-mandatory.dat": (AP + "DG2-Dataset/DG2%20Silver%20Dataset%20(Mandatory%20Fields%20Only).dat",
                             "ea2e4070b6df3dbf777a872b8a4dc9c573cbb6987d165a3d3ae2c626d620d68f"),
    "iso1.asn": (ISO + "-1/ed-1/en/iso-iec-39794-1-ed-1-v1.asn",
                 "149421d2760f90b382c7f72c6dc4c0a245d96fabac54c95dd1e615078616f2c7"),
    "iso5.asn": (ISO + "-5/ed-1/en/iso-iec-39794-5-ed-1-v1.asn",
                 "ec3b408bcced8db975e05c7b86b6285abf5ccd92834c50adb9c179d9df82844b"),
    "iso-sample.der": (ISO + "-5/ed-1/en/sample-39794-5-ed-1-v1.der",
                       "83c5f22e2d85ad361e81459bbfc14a65b745ed3fd6199c0ec25e515218fb2949"),
}


def fetch(name):
    url, sha = SOURCES[name]
    cache = os.environ.get("DG2_39794_CACHE",
                           os.path.expanduser("~/.cache/dg2_39794"))
    path = os.path.join(cache, name)
    if not os.path.exists(path):
        os.makedirs(cache, exist_ok=True)
        with urllib.request.urlopen(url) as r:
            data = r.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path, "rb") as f:
        data = f.read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit(f"{name}: sha256 {got}, expected {sha}")
    return path


def h(s):
    return bytes.fromhex("".join(s.split()))


# --- TLV -------------------------------------------------------------------

def tlv(tag, value):
    t = tag.to_bytes((tag.bit_length() + 7) // 8 or 1, "big")
    n = len(value)
    if n < 0x80:
        ln = bytes([n])
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(body)]) + body
    return t + ln + value


def read_tlv(b, i):
    t0 = b[i]
    j = i + 1
    tag = t0
    if t0 & 0x1F == 0x1F:
        while True:
            tag = (tag << 8) | b[j]
            j += 1
            if not b[j - 1] & 0x80:
                break
    l0 = b[j]
    j += 1
    if l0 < 0x80:
        n = l0
    else:
        k = l0 & 0x7F
        n = int.from_bytes(b[j:j + k], "big")
        j += k
    return tag, b[j:j + n], j + n


def dg2_file(bdb_tag, bdb_value, format_type=0x002A):
    """DG2 around one biometric data block: 75 { 7F61 { 02, 7F60 { A1, BDB } } }."""
    bht = tlv(0x87, h("0101")) + tlv(0x88, format_type.to_bytes(2, "big"))
    bit = tlv(0xA1, bht) + tlv(bdb_tag, bdb_value)
    group = tlv(0x02, b"\x01") + tlv(0x7F60, bit)
    return tlv(0x75, tlv(0x7F61, group))


def envelope(face_image_data_block):
    """The '7F2E' value: A1 { 65 FaceImageDataBlock }."""
    return tlv(0xA1, face_image_data_block)


# --- the mapping into DataGroup2's ISO/IEC 19794-5 fields ------------------

EYE = {0: 0xFF, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5, 7: 0, 8: 6, 9: 7}
HAIR = {0: 0xFF, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5, 7: 6, 8: 7, 9: 0}
COLOUR = {0: 0, 1: 4, 2: 1, 3: 4, 4: 2, 5: 3, 6: 4}
SOURCE = {0: 7, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6}
FORMAT = {"jpeg": 0, "jpeg2000Lossy": 1, "jpeg2000Lossless": 1}
PROPERTY_BITS = {"glasses": 0x002, "moustache": 0x004, "beard": 0x008,
                 "teethVisible": 0x010, "mouthOpen": 0x040,
                 "leftEyePatch": 0x080, "rightEyePatch": 0x100,
                 "darkGlasses": 0x200}
EXPRESSION_CODES = {"neutral": 1, "raisedEyebrows": 4,
                    "eyesLookingAwayFromTheCamera": 5, "squinting": 6,
                    "frowning": 7}
COLOUR_NAMES = ["unknown", "other", "rgb24Bit", "rgb48Bit", "yuv422",
                "greyscale8Bit", "greyscale16Bit"]
EYE_NAMES = ["unknown", "other", "black", "blue", "brown", "grey", "green",
             "hazel", "multi-coloured", "pink"]
HAIR_NAMES = ["unknown", "other", "bald", "black", "blonde", "brown", "grey",
              "white", "red", "knownColoured"]
SOURCE_NAMES = ["unknown", "staticPhotographFromUnknownSource",
                "staticPhotographFromDigitalStillImageCamera",
                "staticPhotographFromScanner", "videoFrameFromUnknownSource",
                "videoFrameFromAnalogueVideoCamera",
                "videoFrameFromDigitalVideoCamera"]


def enum_value(choice, names):
    kind, v = choice
    name = v if kind == "code" else v["fallback"]
    return names.index(name)


def expected_fields(decoded, image):
    reps = decoded["representationBlocks"]
    rep = reps[0]
    _, (_, block) = rep["imageRepresentation"]
    info = block["imageInformation2DBlock"]
    out = {k: 0 for k in (
        "nrImages", "versionNumber", "lengthOfRecord", "numberOfFacialImages",
        "facialRecordDataLength", "nrFeaturePoints", "gender", "eyeColor",
        "hairColor", "featureMask", "expression", "poseAngle",
        "poseAngleUncertainty", "faceImageType", "imageDataType",
        "imageWidth", "imageHeight", "imageColorSpace", "sourceType",
        "deviceType", "quality")}
    out["nrImages"] = 1
    out["numberOfFacialImages"] = len(reps)
    out["imageDataType"] = FORMAT[info["imageDataFormat"][1]]
    size = info.get("imageSizeBlock")
    if size:
        out["imageWidth"] = size["width"]
        out["imageHeight"] = size["height"]
    if "imageColourSpace" in info:
        out["imageColorSpace"] = COLOUR[enum_value(info["imageColourSpace"], COLOUR_NAMES)]
    tech = block.get("captureDevice2DBlock", {}).get("captureDeviceTechnologyId2D")
    if tech:
        out["sourceType"] = SOURCE[enum_value(tech, SOURCE_NAMES)]
    meta = rep.get("identityMetadataBlock", {})
    if "eyeColour" in meta:
        out["eyeColor"] = EYE[enum_value(meta["eyeColour"], EYE_NAMES)]
    if "hairColour" in meta:
        out["hairColor"] = HAIR[enum_value(meta["hairColour"], HAIR_NAMES)]
    if "propertiesBlock" in meta:
        mask = 0x001
        for name, value in meta["propertiesBlock"].items():
            if value:
                mask |= PROPERTY_BITS.get(name, 0)
        out["featureMask"] = mask
    if "expressionBlock" in meta:
        true = [k for k, v in meta["expressionBlock"].items() if v]
        if len(true) == 1:
            out["expression"] = EXPRESSION_CODES.get(true[0], 0)
    out["imageSha256"] = hashlib.sha256(image).hexdigest()
    return out


# --- schemas -----------------------------------------------------------------

def schemas():
    ap = asn1tools.compile_files([fetch("ap1.asn"), fetch("ap5.asn")], "der")
    iso = asn1tools.compile_files([fetch("iso1.asn"), fetch("iso5.asn")], "der")
    return ap, iso


VERSION = {"generation": 3, "year": 2019}


def rep2d(image, info, *, device=None, meta=None, rep_id=0):
    block = {"representationData2D": image, "imageInformation2DBlock": info}
    if device is not None:
        block["captureDevice2DBlock"] = device
    rep = {"representationId": rep_id,
           "imageRepresentation": ("base", ("imageRepresentation2DBlock", block))}
    if meta is not None:
        rep["identityMetadataBlock"] = meta
    return rep


def ext(name):
    return ("extensionBlock", {"fallback": name})


def code(name):
    return ("code", name)


JPEG = h("ffd8ffe000104a46494600010100000100010000aabbccddffd9")
CODESTREAM = h("ff4fff51aabbccffd9")
JP2 = h("0000000c6a5020200d0a870a00000014667479706a70322000000000"
        "6a703220000000106a70326301020304050607080000000c75756964deadbeef")
JP2_TRIMMED = JP2[:-12]
EXIF = h("ffd8ffe10010457869660102ffd9")


def cases():
    ap, iso = schemas()

    def fidb(schema, reps):
        return schema.encode("FaceImageDataBlock",
                             {"versionBlock": VERSION, "representationBlocks": reps})

    def ok(name, schema, reps, image_out, fmt, *, info_cases=None, bdb_tag=0x7F2E):
        block = fidb(schema, reps)
        data = dg2_file(bdb_tag, envelope(block)).hex()
        decoded = schema.decode("FaceImageDataBlock", block)
        rows = [{
            "name": f"39794-5 {name} (dart-only, python-oracle)",
            "op": "dg2.parse", "runners": ["dart"], "input": {"data": data},
            "expect": {"out": expected_fields(decoded, image_out)},
        }, {
            "name": f"39794-5 {name}: detected format (dart-only, python-oracle)",
            "op": "dg2.faceImageFormat", "runners": ["dart"],
            "input": {"data": data}, "expect": {"out": {"format": fmt}},
        }, {
            "name": f"39794-5 {name}: encoding (dart-only, python-oracle)",
            "op": "dg2.encoding", "runners": ["dart"],
            "input": {"data": data}, "expect": {"out": {"encoding": "iso39794"}},
        }]
        if info_cases is not None:
            rows.append({
                "name": f"39794-5 {name}: FaceImageInfo (dart-only, python-oracle)",
                "op": "faceImageInfo.from", "runners": ["dart"],
                "input": {"data": data}, "expect": {"out": info_cases},
            })
        return rows

    def err(name, bdb_value, code_, *, bdb_tag=0x7F2E):
        return [{
            "name": f"39794-5 {name} -> {code_} (dart-only, python-oracle)",
            "op": "dg2.parse", "runners": ["dart"],
            "input": {"data": dg2_file(bdb_tag, bdb_value).hex()},
            "expect": {"error": code_},
        }]

    jpeg_info = {"imageDataFormat": code("jpeg")}
    full_info = {
        "imageDataFormat": code("jpeg2000Lossless"),
        "faceImageKind2D": ext("mrtd"),
        "imageSizeBlock": {"width": 90, "height": 120},
        "imageColourSpace": ext("rgb24Bit"),
    }
    full_device = {"captureDeviceTechnologyId2D":
                   ext("staticPhotographFromDigitalStillImageCamera")}
    full_meta = {
        "gender": ext("female"),
        "eyeColour": ext("blue"),
        "hairColour": ext("blonde"),
        "propertiesBlock": {"glasses": True, "moustache": False, "beard": False},
        "expressionBlock": {"neutral": True, "smile": False},
        "poseAngleBlock": {"yawAngleBlock": {"angleValue": -2, "angleUncertainty": 1}},
    }
    code_info = {
        "imageDataFormat": code("jpeg2000Lossless"),
        "faceImageKind2D": code("mrtd"),
        "imageSizeBlock": {"width": 90, "height": 120},
        "imageColourSpace": code("rgb24Bit"),
    }
    code_device = {"captureDeviceTechnologyId2D":
                   code("staticPhotographFromDigitalStillImageCamera")}
    code_meta = dict(full_meta, gender=code("female"), eyeColour=code("blue"),
                     hairColour=code("blonde"))

    rows = []
    rows += ok("mandatory fields only, JPEG", ap, [rep2d(JPEG, jpeg_info)],
               JPEG, "jpeg", info_cases={
                   "expression": "unspecified", "eyeColor": "unspecified",
                   "faceImageType": None, "features": [],
                   "hairColor": "unspecified", "imageColorSpace": "unspecified",
                   "imageDataType": "jpeg", "sourceType": "unspecified"})
    rows += ok("every mapped field, profile encoding, JP2", ap,
               [rep2d(JP2, full_info, device=full_device, meta=full_meta)],
               JP2_TRIMMED, "jp2", info_cases={
                   "expression": "neutral", "eyeColor": "blue",
                   "faceImageType": None,
                   "features": ["featuresAreSpecified", "glasses"],
                   "hairColor": "blonde", "imageColorSpace": "rgb24",
                   "imageDataType": "jpeg2000",
                   "sourceType": "staticPhotoDigitalCam"})
    rows += ok("base-standard [0] code form of every enum", iso,
               [rep2d(JP2, code_info, device=code_device, meta=code_meta)],
               JP2_TRIMMED, "jp2")
    rows += ok("bare JPEG 2000 codestream, lossy", ap,
               [rep2d(CODESTREAM, {"imageDataFormat": code("jpeg2000Lossy")})],
               CODESTREAM, "jpeg2000Codestream")
    rows += ok("unmappable codes read as 0", ap,
               [rep2d(JPEG, dict(jpeg_info, imageColourSpace=ext("greyscale16Bit")),
                      device={"captureDeviceTechnologyId2D": ext("unknown")},
                      meta={"eyeColour": ext("hazel"),
                            "hairColour": ext("knownColoured"),
                            "propertiesBlock": {"pupilOrIrisNotVisible": True,
                                                "biometricAbsent": True,
                                                "headCoveringsPresent": True},
                            "expressionBlock": {"smile": True}})],
               JPEG, "jpeg")
    rows += ok("unknown eye and hair colour, two expression flags", ap,
               [rep2d(JPEG, jpeg_info,
                      meta={"eyeColour": ext("unknown"),
                            "hairColour": ext("unknown"),
                            "expressionBlock": {"neutral": True, "squinting": True}})],
               JPEG, "jpeg")
    rows += ok("two representations, the first is read", iso,
               [rep2d(JPEG, jpeg_info), rep2d(CODESTREAM, {"imageDataFormat": code("jpeg2000Lossy")}, rep_id=1)],
               JPEG, "jpeg")
    rows += ok("envelope under 5F2E is dispatched on content", ap,
               [rep2d(JPEG, jpeg_info)], JPEG, "jpeg", bdb_tag=0x5F2E)

    # Outside the ICAO profile: no face image the DataGroup2 surface can carry.
    rows += err("no representation",
                envelope(iso.encode("FaceImageDataBlock",
                                    {"versionBlock": VERSION, "representationBlocks": []})),
                "NotYetSupported")
    shape3d = iso.encode("FaceImageDataBlock", {
        "versionBlock": VERSION,
        "representationBlocks": [{
            "representationId": 0,
            "imageRepresentation": ("base", ("shapeRepresentation3DBlock", {
                "representationData3D": b"\x01\x02",
                "imageInformation3DBlock": {
                    "representationKind3D": ("base", ("vertex3DBlock", {})),
                    "coordinateSystem3D": code("cartesianCoordinateSystem3D"),
                    "cartesianScalesAndOffsets3DBlock": {
                        "scaleX": 1.0, "scaleY": 1.0, "scaleZ": 1.0,
                        "offsetX": 0.0, "offsetY": 0.0, "offsetZ": 0.0},
                }})),
        }]})
    rows += err("3D shape representation", envelope(shape3d), "NotYetSupported")
    rows += err("image representation extension block",
                envelope(tlv(0x65, tlv(0xA0, h("800103 810207e3")) + tlv(0xA1, tlv(0x30,
                    tlv(0x80, b"\x00") + tlv(0xA1, tlv(0xA1, b"")))))),
                "NotYetSupported")
    rows += err("PNG image data format",
                envelope(fidb(iso, [rep2d(JPEG, {"imageDataFormat": code("png")})])),
                "NotYetSupported")
    rows += err("image data format extension block",
                envelope(tlv(0x65, tlv(0xA0, h("800103 810207e3")) + tlv(0xA1, tlv(0x30,
                    tlv(0x80, b"\x00") + tlv(0xA1, tlv(0xA0, tlv(0xA0,
                        tlv(0x80, JPEG) + tlv(0xA1, tlv(0xA0, tlv(0xA1, b"")))))))))),
                "NotYetSupported")
    rows += err("empty image data",
                envelope(fidb(ap, [rep2d(b"", jpeg_info)])), "NotYetSupported")

    # Malformed: InvalidDataPassed.
    rows += err("FaceImageDataBlock that is not TLV (the former 39794-5 detection bytes)",
                h("a1056503010203"), "InvalidDataPassed")
    rows += err("no representation blocks element",
                envelope(tlv(0x65, tlv(0xA0, h("800103 810207e3")))), "InvalidDataPassed")
    rows += err("no image information block",
                envelope(tlv(0x65, tlv(0xA0, h("800103 810207e3")) + tlv(0xA1, tlv(0x30,
                    tlv(0x80, b"\x00") + tlv(0xA1, tlv(0xA0, tlv(0xA0, tlv(0x80, JPEG)))))))),
                "InvalidDataPassed")
    rows += err("no image data format",
                envelope(tlv(0x65, tlv(0xA0, h("800103 810207e3")) + tlv(0xA1, tlv(0x30,
                    tlv(0x80, b"\x00") + tlv(0xA1, tlv(0xA0, tlv(0xA0,
                        tlv(0x80, JPEG) + tlv(0xA1, tlv(0xA7, h("80015a 810178")))))))))),
                "InvalidDataPassed")
    # The shared image rules apply to the 39794-5 image unchanged.
    rows += err("Exif JPEG image",
                envelope(fidb(ap, [rep2d(EXIF, jpeg_info)])), "UnknownImageFormat")
    return rows


def verify():
    ap, iso = schemas()
    for name in ("silver-mandatory.dat", "silver-all.dat"):
        with open(fetch(name), "rb") as f:
            dg2 = f.read()
        tag, body, _ = read_tlv(dg2, 0)
        assert tag == 0x75
        tag, group, _ = read_tlv(body, 0)
        assert tag == 0x7F61
        i = 0
        while True:
            tag, value, i = read_tlv(group, i)
            if tag == 0x7F60:
                break
        tag, bht, j = read_tlv(value, 0)
        assert tag == 0xA1 and h("88 02 002a") in bht
        tag, template, _ = read_tlv(value, j)
        assert tag == 0x7F2E
        tag, a1, _ = read_tlv(template, 0)
        assert tag == 0xA1
        decoded = ap.decode("FaceImageDataBlock", a1)
        assert ap.encode("FaceImageDataBlock", decoded) == a1, name
        rep = decoded["representationBlocks"][0]
        _, (_, block) = rep["imageRepresentation"]
        image = block["representationData2D"]
        assert len(image) == 15000 and image[:12] == h("0000000c6a5020200d0a870a")
        assert block["imageInformation2DBlock"]["imageDataFormat"] == ("code", "jpeg2000Lossy")
        fields = expected_fields(decoded, image)
        print(name, len(dg2), json.dumps(fields, sort_keys=True))
    with open(fetch("iso-sample.der"), "rb") as f:
        sample = f.read()
    decoded = iso.decode("FaceImageDataBlock", sample)
    assert iso.encode("FaceImageDataBlock", decoded) == sample
    _, (_, block) = decoded["representationBlocks"][0]["imageRepresentation"]
    image = block["representationData2D"]
    assert image[:4] == h("ffd8ffe0")
    fields = expected_fields(decoded, image)
    print("iso-sample.der", len(sample), json.dumps(fields, sort_keys=True))
    print("verify: ok")


def main():
    if sys.argv[1:] == ["verify"]:
        verify()
    elif sys.argv[1:] == ["emit"]:
        print(json.dumps(cases(), indent=2))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
