#!/usr/bin/env python

"""
XP-Install (xpi) code signing.

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
    xpisign.py -k cert.pem addon.xpi addon.signed.xpi
    xpisign.py --help

Authors:
    Nils Maier <maierman@web.de>
    Wladimir Palant <https://adblockplus.org/blog/signing-firefox-extensions-with-python-and-m2crypto>

License:
    To the extent possible under law, Nils Maier has waived all copyright
    and related or neighboring rights to this work.
"""

from __future__ import with_statement

import os
import re

from base64 import b64encode as base64
from hashlib import md5, sha1
from zipfile import ZIP_DEFLATED, ZIP_STORED

from .compat import BytesIO, ZipFile
from .context import StreamPositionRestore, ZipFileMinorCompression
from .crypto import sign, sign_m2, sign_openssl


__all__ = ["xpisign", "__version__"]
__version__ = "2.0.2"
__website__ = "https://github.com/nmaier/xpisign.py"
__versioninfo__ = "xpisign.py (version: %s; %s)" % (__version__, __website__)

RE_ALREADY_COMPRESSED = re.compile(".(png|xpt)$", re.I)
RE_ARCHIVES = re.compile("\.(jar|zip)$", re.I)
RE_DIRECTORY = re.compile(r"[\\/]$")
RE_META = re.compile("META-INF/")


class Digests(object):
    '''Digest generator helper'''

    __algos = {"MD5": md5, "SHA1": sha1}

    @property
    def __manifest_version(self):
        vals = __versioninfo__, self.signer.generator
        return "Manifest-Version: 1.0\nCreated-By: %s; %s\n" % vals

    @property
    def __signature_version(self):
        vals = __versioninfo__, self.signer.generator
        return "Signature-Version: 1.0\nCreated-By: %s; %s\n" % vals

    def __init__(self, signer, keyfile, algos=["MD5", "SHA1"]):
        self.signer = signer
        self.keyfile = keyfile

        if not all(x in self.__algos for x in algos):
            raise ValueError("Not all specified algorithms are known")

        self.algos = algos
        self.manifests = []
        self.signatures = []

        self._add(self.__manifest_version, self.__signature_version)

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
        ''' Add a manifest resource '''
        self._add("Name: %s\n%s" % (name, self.digest(content)),
                  "Name: %s\n" % name
                  )

    @property
    def manifest(self):
        return "\n".join(self.manifests)

    @property
    def signature(self):
        return "\n".join(self.signatures)

    @property
    def signed(self):
        return self.signer(self.keyfile, self.signature)


def file_key(name):
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


def maybe_optimize_inner_archive(name, content):
    '''Recursivly recompress content if it is an archive'''

    if not RE_ARCHIVES.search(name):
        return name, content

    with BytesIO(content) as cp:
        with ZipFile(cp, "r") as zp:
            files = [maybe_optimize_inner_archive(n, zp.read(n))
                     for n in sorted(zp.namelist())
                     if not RE_DIRECTORY.search(n)
                     ]
    rv = BytesIO()
    with StreamPositionRestore(rv):
        with ZipFile(rv, "w", ZIP_STORED) as zp:
            for i, c in files:
                zp.writestr(i, c)
    return name, rv.read()


def xpisign(xpifile,
            keyfile,
            outfile=None,
            optimize_signatures=True,
            optimize_compression=True,
            signer=None
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
    @param signer: (optional) sign implementation to use (in: m2, openssl)
    @return: signed result file name or buffer
    '''

    if isinstance(xpifile, basestring):
        with open(xpifile, "rb") as zp:
            return xpisign(zp,
                           keyfile,
                           outfile,
                           optimize_signatures,
                           optimize_compression,
                           signer
                           )

    if outfile and isinstance(outfile, basestring):
        with open(outfile, "wb") as op:
            xpisign(zp,
                    keyfile,
                    op,
                    optimize_signatures,
                    optimize_compression,
                    signer
                    )
            return outfile

    if not outfile:
        outfile = BytesIO()

    if not signer:
        signer = sign
    elif signer == "m2":
        signer = sign_m2
    elif signer == "openssl":
        signer = sign_openssl
    else:
        raise ValueError("Invalid signing algorithm")
    if not signer:
        raise RuntimeError("Signing algorithm is not available on this system")

    # read file list and contents, skipping any existing meta files
    with StreamPositionRestore(xpifile):
        with ZipFile(xpifile, "r") as xp:
            files = [maybe_optimize_inner_archive(n, xp.read(n))
                     for n in sorted(xp.namelist(), key=file_key)
                     if not RE_META.match(n) and not RE_DIRECTORY.search(n)
                     ]

    # generate all digests
    dkw = {"signer": signer,
           "keyfile": keyfile
           }
    if optimize_signatures:
        dkw["algos"] = "SHA1",
    digests = Digests(**dkw)
    for name, content in files:
        digests.add(name, content)

    # add the meta signing files
    # needs to be the first file
    files.insert(0, ["META-INF/zigbert.rsa", digests.signed])
    # usually, or even expected to be the last files of the archive
    files += ["META-INF/manifest.mf", digests.manifest],
    files += ["META-INF/zigbert.sf", digests.signature],

    # write stuff
    with StreamPositionRestore(outfile):
        with ZipFileMinorCompression(optimize_compression):
            with ZipFile(outfile, "w", ZIP_DEFLATED) as zp:
                for name, content in files:
                    if RE_ALREADY_COMPRESSED.search(name):
                        zp.writestr(name, content, ZIP_STORED)
                    else:
                        zp.writestr(name, content, ZIP_DEFLATED)

    return outfile
