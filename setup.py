# Copyright (c) 2015 Codenomicon Ltd.
# License: MIT

from codecs import open
from setuptools import setup, find_packages

from protecodesc import __version__ as version

with open('README.md', encoding='ascii') as f:
    long_description = f.read()

setup(name='protecodesc',
      description="Protecode SC command line tools and API client",
      long_description=long_description,
      author='Antti Hayrynen',
      author_email='hayrynen@synopsys.com',
      version=version,
      packages=find_packages(exclude=['tests']),
      zip_safe=False,
      install_requires=['click', 'requests', 'keyring'],
      entry_points="""
          [console_scripts]
          protecodesc = protecodesc.cli:main
      """,
      classifiers=[
          "Development Status :: 4 - Beta",
          "Environment :: Console",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.5",
          "Topic :: Security",
          "Topic :: Software Development",
          "Topic :: Software Development :: Libraries",
          "Topic :: Utilities",
      ],
      )
