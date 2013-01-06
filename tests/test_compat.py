from tempfile import NamedTemporaryFile

from xpisign.compat import BytesIO, ZipFile

from helper import *


def test_BytesIO():
    """BytesIO works."""
    with BytesIO() as b:
        b.write("test")
        assert b.getvalue() == "test"
        b.write("test")
        assert b.getvalue() == "testtest"
        assert b.read() == ""
        b.seek(0, 0)
        assert b.read() == "testtest"
        b.seek(0, 2)
        assert b.read() == ""


def test_ZipFile_read():
    """ZipFiles can be read."""
    with ZipFile(relfile("addon.xpi"), "r") as zp:
        assert zp.read("test.txt") == "testfile\n"


def test_ZipFile_write():
    """ZipFiles can be written."""
    with NamedTemporaryFile() as tmp:
        with ZipFile(tmp.name, "w") as zp:
            zp.writestr("test.txt", "testfile\n")
        with ZipFile(tmp.name, "r") as zp:
            assert zp.read("test.txt") == "testfile\n"
