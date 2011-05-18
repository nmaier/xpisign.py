XP-Install (xpi) code singing.
===

Requirements
---

* Recent Python (2.5+)
* [M2Crypto](http://pypi.python.org/pypi/M2Crypto)
  `easy_install -Z M2Crypto`
* Windows users must also install valid OpenSSL binaries into their (Python) path. Copying files to the corresponding M2Crypto directory under Python\libs\site-packages will also do the trick

Usage
---
`python xpisign.py -k cert.pem addon.xpi addon.signed.xpi`

Credits
---
Thanks to Wladimir Palant for researching this stuff!
