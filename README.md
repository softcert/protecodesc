Codenomicon AppCheck commandline and API client
===============================================

Note, this is an unofficial tool for Codenomicon AppCheck service.

Installation and requirements
-----------------------------

To install, you need to have:

  * A valid subscription for Codenomicon AppCheck service
  * Python 2.7.x or 3.5.x (https://www.python.org)
  * pip (included with latest Python, or python-pip package)


Installation::

    $ pip install appcheck

Basic usage::

    $ appcheck
    Usage: appcheck [OPTIONS] COMMAND [ARGS]...

      Appcheck commandline tools. To use this tool you need to have an account
      to Codenomicon Appcheck service.

    Options:
      --help  Show this message and exit.

    Commands:
      apps    List apps
      delete  Delete scan result
      groups  List groups
      result  Get scan result
      scan    Analyze a file or directory using Appcheck.

To analyze files with Appcheck, you can scan one or more files
easily. Directories are automatically compressed to a ZIP archive
and uploaded as one object.

Scanning applications::

    $ appcheck scan MyApp.exe FirmwareUpdate.bin /Applications/Calculator.app


Configuration files
-------------------

Username is stored to a file .appcheck in user home directory.

Password is saved in operating system specific keyring
using the `Python keyring package <https://pypi.python.org/pypi/keyring>`_.