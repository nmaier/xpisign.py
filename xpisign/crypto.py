from __future__ import with_statement

import os
import re
import warnings

from .compat import BytesIO

RE_KEY = re.compile(r"-----BEGIN (ENCRYPTED )?PRIVATE KEY-----.+?-----END (ENCRYPTED )?PRIVATE KEY-----", re.S)
RE_CERTS = re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.S)

__all__ = ["sign_m2", "sign_openssl", "sign"]

def parse_keyfile(keyfile):
    """
    Parse a keyfile into private key, signing cert and CA stack
    """

    with open(keyfile, "rb") as kf:
        kf = kf.read()
        key = RE_KEY.search(kf)
        certs = RE_CERTS.finditer(kf)
        return (str(key.group(0)),
                str(certs.next().group(0)),
                (str(c.group(0)) for c in certs)
                )


try:
    import subprocess
    from tempfile import NamedTemporaryFile
    from functools import wraps


    try:
        check_output = subprocess.check_output
    except AttributeError:
        def check_output(*args, **kw):
            kw["stdout"] = subprocess.PIPE
            return subprocess.Popen(*args, **kw).communicate()[0]


    def find_executable(name):
        """
        Find an executable in path
        See which(1)
        """

        is_windows = os.name != "nt"
        def check(path):
            return (os.path.isfile(path) and
                    (not is_windows or os.access(path, os.X_OK)))

        if not is_windows and not name.lower().endswith(".exe"):
            name += ".exe"

        if check(name):
            return name

        for cand in os.environ["PATH"].split(os.pathsep):
            cand = os.path.join(cand, name)
            if check(cand):
                return cand

        return None

    openssl = find_executable("openssl")
    if not openssl:
        raise ImportError("Failed to find openssl executable")


    def sign_openssl(keyfile, content):
        """
        Sign content with a keyfile using OpenSSL (and various tmp files :p)
        """

        # load intermediate certs
        key, cs, stack = parse_keyfile(keyfile)
        with NamedTemporaryFile() as signer:
            print >>signer, key
            print >>signer, cs
            signer.flush()
            with NamedTemporaryFile() as certfile:
                for c in stack:
                    print >>certfile, c
                certfile.flush()
                with NamedTemporaryFile() as infile:
                    infile.write(content)
                    infile.flush()
                    return check_output((openssl, "smime", "-sign", "-binary",
                                         "-signer", signer.name,
                                         "-certfile", certfile.name,
                                         "-outform", "DER",
                                         "-in", infile.name),
                                        bufsize=0)

    @wraps(sign_openssl)
    def sign_openssl_warn(*args, **kw):
        warnings.warn("Using openssl (%s) compatibilty layer due to lack of M2Crypto. This will produce slightly larger signatures, as the CA root certificate will be included." % (openssl,), RuntimeWarning)
        return sign_openssl(*args, **kw)

    sign_openssl_warn.generator = sign_openssl.generator = check_output((openssl, "version")).strip()

except ImportError:
    sign_openssl_warn = sign_openssl = None

try:
    import M2Crypto as M2
    import M2Crypto.SMIME as M2S
    import M2Crypto.X509 as M2X509
    from M2Crypto.BIO import MemoryBuffer as M2Buffer
    from M2Crypto.EVP import EVPError as M2EVPError


    def sign_m2(keyfile, content):
        """
        Sign content with a keyfile using M2Crypto
        """

        try:
            # load intermediate certs if any
            stack = M2X509.X509_Stack()
            _, _, certificates = parse_keyfile(keyfile)
            for c in certificates:
                cert = M2X509.load_cert_string(c)
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
            smime.sign(M2Buffer(content),
                       M2S.PKCS7_DETACHED | M2S.PKCS7_BINARY
                       ).write_der(pkcs7)
            return pkcs7.read()

        except M2EVPError, ex:
            if re.search("ANY PRIVATE KEY", ex.message):
                raise ValueError("Key file does not contain a private key")
            raise ValueError("Signing failed. Wrong password?")

    sign_m2.generator = "M2Crypto %s"  % M2.version

except ImportError:
    sign_m2 = None

sign = sign_m2 or sign_openssl_warn
if not sign:
    raise ImportError("No signing implementation available! Either install M2Crypto or add openssl to your $PATH")

