Protecode SC commandline and API client
=======================================

Note, this is an unofficial tool for Protecode SC service.

Installation and requirements
-----------------------------

To install, you need to have:

  * A valid subscription for Protecode SC service
  * Python 2.7.x or 3.5.x (https://www.python.org)
  * pip (included with latest Python, or python-pip package)


Installation::

    $ python setup.py install

Basic usage::


    $ protecodesc

    Usage: protecodesc [OPTIONS] COMMAND [ARGS]...

      Protecode SC commandline tools. To use this tool you need to have an
      account on the service.

    Options:
      --help  Show this message and exit.

    Commands:
      delete  Delete scan result
      groups  List groups
      list    List apps
      login   Save username/password and configure server...
      logout  Forget saved username and password
      rescan  Request rescan of existing result
      result  Get scan result
      scan    Analyze a file or directory.

To analyze files, you can scan one or more files
easily. Directories are automatically compressed to a ZIP archive
and uploaded as one object.

Scanning applications::

    $ protecodesc scan MyApp.exe FirmwareUpdate.bin /Applications/Calculator.app

Configuration files
-------------------

Username is stored to a file .appcheck in user home directory.

Password is saved in operating system specific keyring
using the `Python keyring package <https://pypi.python.org/pypi/keyring>`_.