# Copyright (c) 2015 Codenomicon Ltd.
# License: MIT

import keyring
import os.path

try:
    import configparser
except ImportError:  # Python 2
    import ConfigParser as configparser


# Where to store settings
USER_CONFIG_FILE = os.path.expanduser('~/.appcheck')
KEYRING_SERVICE = 'appcheck'
SECTION = 'appcheck'


class AppcheckClientConfig:

    def __init__(self, config_files=(USER_CONFIG_FILE,)):
        self._config = configparser.ConfigParser()

        # Read config files
        self._config.read(config_files)

    def credentials(self):
        """Get stored username and password"""
        try:
            username = self._config.get(SECTION, 'username')
            password = keyring.get_password(KEYRING_SERVICE, username)
        except configparser.NoSectionError:
            username, password = None, None
        return username, password

    def get_appcheck_host(self):
        """Return Appcheck alternate host address or None for default

        For example, https://appcheck.codenomicon.com
        """
        try:
            return self._config.get(SECTION, 'alternate_host')
        except configparser.NoSectionError:
            return None
        except configparser.NoOptionError:
            return None

    def set_appcheck_host(self, appcheck_uri):
        """Store AppCheck URI (e.g. AppCheck appliance)"""
        if not self._config.has_section(SECTION):
            self._config.add_section(SECTION)
        self._config.set(SECTION, 'alternate_host', appcheck_uri)
        self._config.write(open(USER_CONFIG_FILE, 'w'))

    def set_credentials(self, username, password):
        """Store username and password"""
        if not self._config.has_section(SECTION):
            self._config.add_section(SECTION)
        self._config.set(SECTION, 'username', username)
        self._config.write(open(USER_CONFIG_FILE, 'w'))
        keyring.set_password(KEYRING_SERVICE, username, password)

    def forget_credentials(self):
        """Forget saved credentials"""
        prev_username, prev_password = self.credentials()
        keyring.set_password(KEYRING_SERVICE, prev_username, '')
        self.set_credentials('', '')
