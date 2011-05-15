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

from base64 import b64encode as base64
from hashlib import md5, sha1

try:
    import xpi_zipfile as zipfile
except ImportError:
    import zipfile

try:
    import M2Crypto
except ImportError:
    if __name__ == '__main__':
        import sys
        print >>sys.stderr, "Failed to load M2Crypto"
        sys.exit(1)

    # not standalone, re-raise
    raise

__all__ = ['xpisign']
__version__ = "1.0"

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

class Digests(object):
    def __init__(self):
        self.manifests = []
        self.signatures = []

        self._add(self.__manifest_version, self.__signature_version)

    __manifest_version = "Manifest-Version: 1.0\nCreated-By: xpisign.py (version: %s)\n" % __version__
    __signature_version = "Signature-Version: 1.0\nCreated-By: xpisign.py (version: %s)\n" % __version__

    __algos = [["MD5", md5], ["SHA1", sha1]]

    @classmethod
    def digest(cls, content):
        '''
        Generate an ascii content digest according to signtool rules
        @param content
        '''

        rv = "Digest-Algorithms: %s\n" % " ".join(a for a,d in cls.__algos)
        for a,f in cls.__algos:
            rv += "%s-Digest: %s\n" % (a, base64(f(content).digest()))
        return rv

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

def xpisign(xpifile, keyfile, outfile=None):
    '''
    Sign an XP-Install (XPI file)

    xpifile and outfile might be either strings pointing to the corresponding
    file or file-like-objects.
    keyfile is expected to be a string containing a path.

    The file in question will be signed using the key as provided in key file.

    If no outfile is provided then the function will return a file-like object
    containing the result. Else outfile is returned.

    @param xpifile: file to sign
    @param keyfile: key to sign with
    @param outfile: (optional) file to write the signed result to
    @return: signed result file name or buffer
    '''

    if isinstance(xpifile, basestring):
        with open(xpifile, "rb") as zp:
            return xpisign(zp, keyfile, outfile)

    if outfile and isinstance(outfile, basestring):
        with open(outfile, "w") as op:
            xpisign(zp, keyfile, op)
            return outfile

    if not outfile:
        outfile = io.BytesIO()

    # read file list and contents, skipping any existing meta files
    try:
        inpos = xpifile.tell()
    except:
        pass
    with zipfile.ZipFile(xpifile, "r") as xp:
        files = [(n, xp.read(n))
                 for n in sorted(xp.namelist(), key=filekeyfun)
                 if not re.match("META-INF/", n)
                 ]
    try:
        inpos = xpifile.seek(inpos, 0)
    except:
        pass

    # generate all digests
    digests = Digests()
    for name, content in files:
        digests.add(name, content)

    # generate the detached signature
    smime = M2Crypto.SMIME.SMIME()
    smime.load_key(keyfile, certfile=keyfile)

    pkcs7 = M2Crypto.BIO.MemoryBuffer()
    smime.sign(M2Crypto.BIO.MemoryBuffer(digests.signature),
               M2Crypto.SMIME.PKCS7_DETACHED | M2Crypto.SMIME.PKCS7_BINARY
               ).write_der(pkcs7)

    # add the meta signing files
    # needs to be the first file
    files.insert(0, ["META-INF/zigbert.rsa", pkcs7.read()])
    # usually, or even expected to be the last files of the archive
    files += ["META-INF/manifest.mf", digests.manifest],
    files += ["META-INF/zigbert.sf", digests.signature],

    # store the current position, so that it can be restored later
    try:
        outpos = outfile.tell()
    except:
        pass

    # write stuff
    with zipfile.ZipFile(outfile, "w", zipfile.ZIP_DEFLATED) as zp:
        for name, content in files:
            if re.search(".(png|xpt)$", name):
                zp.writestr(name, content, zipfile.ZIP_STORED)
            else:
                zp.writestr(name, content, zipfile.ZIP_DEFLATED)

    # need to restore the stream position
    try:
        outfile.seek(outpos, 0)
    except:
        pass

    return outfile

if __name__ == "__main__":
    import sys
    from optparse import OptionParser

    def main(args):
        op = OptionParser(usage="Usage: %prog [options] xpifile outfile")
        op.add_option(
                      "-k",
                       "--keyfile",
                        dest="keyfile",
                        default="sign.pem",
                        help="Key file to get the certificate from"
                        )
        op.add_option(
                      "-f",
                       "--force",
                        dest="force",
                        action="store_true",
                        default=False,
                        help="Force signing, i.e. overwrite outfile if it already exists"
                        )
        options, args = op.parse_args(args)
        try:
            xpifile, outfile = args
        except ValueError:
            op.error("Need to specify xpifile and outfile!")

        if not options.force and os.path.exists(outfile):
            op.error("outfile %s already exists" % outfile)

        keyfile = options.keyfile
        if not os.path.exists(keyfile):
            op.error("keyfile %s cannot be found" % keyfile)

        try:
            with open(xpifile, "rb") as xp:
                try:
                    with open(outfile, "wb") as op:
                        xpisign(xp, keyfile, op)
                except IOError:
                    op.error("Failed to open outfile %s" % outfile)
        except IOError:
            op.error("Failed to open xpifile %s" % xpifile)

        return 0

    sys.exit(main(sys.argv[1:]))
