#!/usr/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import xpisign.api as xpisign

classifiers = ["Development Status :: 5 - Production/Stable",
               "Intended Audience :: Developers",
               "License :: Public Domain",
               "Operating System :: OS Independent",
               "Programming Language :: Python",
               "Topic :: Software Development :: Build Tools",
               ]

docstrings = xpisign.__doc__.split("\n")

setup(name="xpisign",
      version=xpisign.__version__,

      author="Nils Maier",
      author_email="maierman@web.de",
      license="Public Domain",
      url="https://github.com/nmaier/xpisign.py",
      classifiers=classifiers,
      description=docstrings[0],
      long_description="\n".join(docstrings[1:]).strip(),

      platforms=["any"],
      scripts=["scripts/xpisign"],
      packages=["xpisign"],

      )
