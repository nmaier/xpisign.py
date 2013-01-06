from zipfile import ZIP_DEFLATED as DEFLATED

from xpisign.compat import BytesIO, ZipFile
from xpisign.context import *

from helper import *


def test_StreamPositionRestore():
    """StreamPositionRestore actually restores streams."""
    with BytesIO() as bi:
        assert bi.tell() == 0
        with StreamPositionRestore(bi):
            bi.write("test")
            assert bi.tell() == 4
            with StreamPositionRestore(bi):
                bi.write("test")
                assert bi.tell() == 8
            assert bi.tell() == 4
        assert bi.tell() == 0


def test_ZipFileMinorCompression():
    """ZipFileMinorCompression has a (deterministic) effect."""
    with BytesIO() as bi:
        with ZipFile(bi, "w", DEFLATED) as zp:
            zp.writestr("test.txt", "sttesttesttesttest" * 10000)
        len1 = len(bi.getvalue())
    with BytesIO() as bi:
        with ZipFile(bi, "w", DEFLATED) as zp:
            zp.writestr("test.txt", "sttesttesttesttest" * 10000)
        len2 = len(bi.getvalue())
    assert len1 == len2
    with BytesIO() as bi:
        with ZipFile(bi, "w", DEFLATED) as zp:
            with ZipFileMinorCompression(zp):
                zp.writestr("test.txt", "sttesttesttesttest" * 10000)
        len2 = len(bi.getvalue())
    assert len1 != len2
