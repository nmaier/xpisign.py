#!/usr/bin/env python

"""
XP-Install (xpi) code singing.

Module Usage:
    xpisign("addon.xpi", "cert.pem", "addon.signed.xpi")

    open("addon.signed.xpi", "wb").write(
        xpisign("addon.xpi", "cert.pem").read()
        )

    with open("addon.xpi", "wb") as ifp:
        with open("addon.signed.xpi") ofp:
            xpisign(ifp, "cert.pem", ofp)

This module can be used stand-alone as a command line program.

Program usage:
    ./xpisign.py -k cert.pem addon.xpi addon.signed.xpi
    python xpisign.py -k cert.pem addon.xpi addon.signed.xpi
    python -m xpisign -k cert.pem addon.xpi addon.signed.xpi

    python xpisign.py --help

Authors:
    Nils Maier <maierman@web.de>
    Wladimir Palant <https://adblockplus.org/blog/signing-firefox-extensions-with-python-and-m2crypto>

License:
    To the extent possible under law, Nils Maier has waived all copyright
    and related or neighboring rights to this work.
"""

import io
import os
import re
import zipfile
import zlib

from base64 import b64encode as base64
from hashlib import md5, sha1

try:
    import M2Crypto.SMIME as M2S
    import M2Crypto.X509 as M2X509
    from M2Crypto.BIO import MemoryBuffer as M2Buffer
    from M2Crypto.EVP import EVPError as M2EVPError
except ImportError:
    if __name__ == '__main__':
        import sys
        print >>sys.stderr, "Failed to load M2Crypto"
        sys.exit(1)

    # not standalone, re-raise
    raise


__all__ = ["xpisign"]
__version__ = "1.4"

RE_ALREADY_COMPRESSED = re.compile(".(png|xpt)$", re.I)
RE_ARCHIVES = re.compile("\.(jar|zip)$", re.I)
RE_CERTS = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                      re.S
                      )
RE_DIRECTORY = re.compile(r"[\\/]$")
RE_META = re.compile("META-INF/")

def filekeyfun(name):
    '''
    Sort keys for xpi files
    @param name: name of the file to generate the sort key from
    '''

    prio = 4

    if name == 'install.rdf':
        prio = 1
    elif name in ["chrome.manifest", "icon.png", "icon64.png"]:
        prio = 2
    elif name in ["MPL", "GPL", "LGPL", "COPYING", "LICENSE", "license.txt"]:
        prio = 5
    parts = [prio] + list(os.path.split(name.lower()))
    return "%d-%s-%s" % tuple(parts)

class StreamPositionRestore(object):
    def __init__(self, stream):
        self.stream = stream
    def __enter__(self):
        self.__pos = None
        try:
            self.__pos = self.stream.tell()
        except:
            pass
        return self
    def __exit__(self, type, value, traceback):
        if self.__pos is not None:
            try:
                self.stream.seek(self.__pos, 0)
            except:
                pass
        return self

orig_compressobj = zlib.compressobj
def minor_compressobj(compression, type, hint):
    # always use a compression level of 2 for xpi optimized compression
    return orig_compressobj(2, type, hint)

class ZipFileMinorCompression(object):
    def __init__(self, minor_compression=True):
        self.__minor_compression = minor_compression
    def __enter__(self):
        if self.__minor_compression:
            zlib.compressobj = minor_compressobj
        return self
    def __exit__(self, type, value, traceback):
        if self.__minor_compression:
            zlib.compressobj = orig_compressobj
        return self

class Digests(object):
    def __init__(self, algos=["MD5", "SHA1"]):
        if not all(x in self.__algos for x in algos):
            raise ValueError("Not all specified algorithms are known")

        self.algos = algos
        self.manifests = []
        self.signatures = []

        self._add(self.__manifest_version, self.__signature_version)

    __manifest_version = "Manifest-Version: 1.0\nCreated-By: xpisign.py (version: %s)\n" % __version__
    __signature_version = "Signature-Version: 1.0\nCreated-By: xpisign.py (version: %s)\n" % __version__

    __algos = {"MD5": md5, "SHA1": sha1}

    def digest(self, content):
        '''
        Generate an ascii content digest according to signtool rules
        @param content
        '''

        def digestline(a):
            hash = base64(self.__algos[a](content).digest())
            return "%s-Digest: %s\n" % (a, hash)

        rv = []
        if len(self.algos) > 1:
            rv += "Digest-Algorithms: %s\n" % " ".join(self.algos),
        rv += [digestline(a) for a in self.algos]
        return "".join(rv)

    def _add(self, manifest, signature):
        self.manifests += manifest,
        self.signatures += signature + self.digest(manifest),

    def add(self, name, content):
        self._add("Name: %s\n%s" % (name, self.digest(content)),
                  "Name: %s\n" % name
                  )

    def _get_manifest(self):
        return "\n".join(self.manifests)
    manifest = property(_get_manifest)

    def _get_signature(self):
        return "\n".join(self.signatures)
    signature = property(_get_signature)

def maybe_optimize_inner_archive(name, content):
    if not RE_ARCHIVES.search(name):
        return name, content

    with io.BytesIO(content) as cp, zipfile.ZipFile(cp, "r") as zp:
        files = [maybe_optimize_inner_archive(n, zp.read(n))
                 for n in sorted(zp.namelist())
                 if not RE_DIRECTORY.search(n)
                 ]
    rv = io.BytesIO()
    with StreamPositionRestore(rv):
        with zipfile.ZipFile(rv, "w", zipfile.ZIP_STORED) as zp:
            for i,c in files:
                zp.writestr(i, c)
    return name, rv.read()

def xpisign(xpifile,
            keyfile,
            outfile=None,
            optimize_signatures=False,
            optimize_compression=False
            ):
    '''
    Sign an XP-Install (XPI file)

    xpifile and outfile might be either strings pointing to the corresponding
    file or file-like-objects.
    keyfile is expected to be a string containing a path.

    The file in question will be signed using the key as provided in key file.

    If no outfile is provided then the function will return a file-like object
    containing the result. Else outfile is returned.

    Note: optimize_compression will temporarily override zlib.compressobj to
    always use another compression. It is therefore a bad idea to use this
    feature while (implicitly) using compressobj in parallel in the same
    process.
    (This limitation arises because of the zipfile implementation not enabling
    users to specify another compression rate. If you know a better solution,
    then please let me know.)

    @param xpifile: file to sign
    @param keyfile: key to sign with
    @param outfile: (optional) file to write the signed result to
    @param optimize_signatures: (optional) optimize signature hash selection
    @param optimize_compression: (optional) optimize compression level
    @return: signed result file name or buffer
    '''

    if isinstance(xpifile, basestring):
        with open(xpifile, "rb") as zp:
            return xpisign(zp, keyfile, outfile)

    if outfile and isinstance(outfile, basestring):
        with open(outfile, "wb") as op:
            xpisign(zp, keyfile, op)
            return outfile

    if not outfile:
        outfile = io.BytesIO()

    # read file list and contents, skipping any existing meta files
    with StreamPositionRestore(xpifile), zipfile.ZipFile(xpifile, "r") as xp:
        files = [maybe_optimize_inner_archive(n, xp.read(n))
                 for n in sorted(xp.namelist(), key=filekeyfun)
                 if not RE_META.match(n) and not RE_DIRECTORY.search(n)
                 ]

    # generate all digests
    if optimize_signatures:
        digests = Digests(algos=["SHA1"])
    else:
        digests = Digests()
    for name, content in files:
        digests.add(name, content)

    # generate the detached signature
    try:
        # load intermediate certs if any
        stack = M2X509.X509_Stack()
        with open(keyfile, "rb") as kf:
            keydata = kf.read()
        certificates = RE_CERTS.finditer(keydata)

        # the first certificate is assumed to be the cs certificate
        certificates.next()
        for c in certificates:
            cert = M2X509.load_cert_string(c.group(0))
            # skip the main CA cert, as this must be built-in anyway
            if (cert.check_ca()
                and str(cert.get_issuer()) == str(cert.get_subject())):
                continue
            stack.push(cert)

        # actual signing
        smime = M2S.SMIME()
        smime.load_key(keyfile)
        smime.set_x509_stack(stack)

        pkcs7 = M2Buffer()
        smime.sign(M2Buffer(digests.signature),
                   M2S.PKCS7_DETACHED | M2S.PKCS7_BINARY
                   ).write_der(pkcs7)
    except M2EVPError, ex:
        if re.search("ANY PRIVATE KEY", ex.message):
            raise ValueError("Key file does not contain a private key")
        raise ValueError("Signing failed. Wrong password?")

    # add the meta signing files
    # needs to be the first file
    files.insert(0, ["META-INF/zigbert.rsa", pkcs7.read()])
    # usually, or even expected to be the last files of the archive
    files += ["META-INF/manifest.mf", digests.manifest],
    files += ["META-INF/zigbert.sf", digests.signature],

    # write stuff
    with StreamPositionRestore(outfile), ZipFileMinorCompression(optimize_compression):
        with zipfile.ZipFile(outfile, "w", zipfile.ZIP_DEFLATED) as zp:
            for name, content in files:
                if RE_ALREADY_COMPRESSED.search(name):
                    zp.writestr(name, content, zipfile.ZIP_STORED)
                else:
                    zp.writestr(name, content, zipfile.ZIP_DEFLATED)

    return outfile

if __name__ == "__main__":
    import sys
    from optparse import OptionParser

    def main(args):
        optparse = OptionParser(usage="Usage: %prog [options] xpifile outfile")
        optparse.add_option("-k",
                            "--keyfile",
                            dest="keyfile",
                            default="sign.pem",
                            help="Key file to get the certificate from"
                            )
        optparse.add_option("-f",
                            "--force",
                            dest="force",
                            action="store_true",
                            default=False,
                            help="Force signing, i.e. overwrite outfile if it already exists"
                            )
        optparse.add_option("-o",
                            "--optimize",
                            dest="optimize",
                            action="store_true",
                            default=False,
                            help="Optimize signatures, avoiding inclusion of weak hashes. Also optimize the compression level."
                            )
        options, args = optparse.parse_args(args)
        try:
            xpifile, outfile = args
        except ValueError:
            optparse.error("Need to specify xpifile and outfile!")

        if not options.force and os.path.exists(outfile):
            optparse.error("outfile %s already exists" % outfile)

        keyfile = options.keyfile
        if not os.path.exists(keyfile):
            optparse.error("keyfile %s cannot be found" % keyfile)

        optimize = options.optimize

        try:
            # buffer stuff, in case xpifile == outfile
            with open(xpifile, "rb") as tp:
                xp = io.BytesIO(tp.read())
            with xp:
                try:
                    with open(outfile, "wb") as op:
                        try:
                            xpisign(xpifile=xp,
                                    keyfile=keyfile,
                                    outfile=op,
                                    optimize_signatures=optimize,
                                    optimize_compression=optimize
                                    )
                        except ValueError, ex:
                            optparse.error(ex.message)
                except IOError:
                    optparse.error("Failed to open outfile %s" % outfile)
        except IOError:
            optparse.error("Failed to open xpifile %s" % xpifile)

        return 0

    sys.exit(main(sys.argv[1:]))
