XP-Install (xpi) code signing.
===

Requirements
---

* Recent Python (2.5+)
* [M2Crypto](http://pypi.python.org/pypi/M2Crypto) (recommended)
  `easy_install -Z M2Crypto`
   * Windows users must also install valid OpenSSL binaries into their (Python) path. Copying files to the corresponding M2Crypto directory under Python\libs\site-packages will also do the trick
* OR openssl binary within the path

Usage
---
`python xpisign.py -k cert.pem addon.xpi addon.signed.xpi`

Credits
---
Thanks to Wladimir Palant for initially researching this stuff!
