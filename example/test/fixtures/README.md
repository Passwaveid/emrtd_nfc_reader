# JPEG 2000 test fixtures

`synthetic_face.jp2` and `synthetic_face.j2k` are the same 96×128 RGB test
pattern in the two forms an eMRTD DG2 can carry: the boxed JP2 container and
the bare codestream. They were encoded with OpenJPEG's `opj_compress` from a
generated PPM.

They are **synthetic**. No personal data, no biometric data, no passport
provenance; nothing here came off a chip or a person. They exist so
`face_pixels_test.dart` can prove the decode path end to end without a real
document, and the padding/truncation variants the tests exercise are built
from these two files at run time.
