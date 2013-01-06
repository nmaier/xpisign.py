import zipfile

try:
    import io
    BytesIO = io.BytesIO
except ImportError:
    _BytesIO = None
    try:
        import cStringIO
        _BytesIO = cStringIO.cStringIO
    except ImportError:
        import StringIO
        _BytesIO = StringIO.StringIO

    class BytesIO(_BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, type, value, traceback):
            self.close()

if hasattr(zipfile.ZipFile, "__enter__"):
    ZipFile = zipfile.ZipFile
else:
    # Make compatible with "with_statement"
    # and also implement compression argument
    class ZipFile(zipfile.ZipFile):
        def __enter__(self):
            return self

        def __exit__(self, type, value, traceback):
            self.close()

        def writestr(self, info, bytes, compression=None):
            if compression is not None:
                _compression = self.compression
                self.compression = compression
            try:
                zipfile.ZipFile.writestr(self, info, bytes)
            finally:
                if compression is not None:
                    self.compression = _compression

__all__ = ["BytesIO", "ZipFile"]
