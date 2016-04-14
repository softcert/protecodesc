# Copyright (c) 2015 Codenomicon Ltd.
# License: MIT


class AppcheckException(Exception):
    """AppCheck interface exception"""


class ConnectionFailure(AppcheckException):
    """Connection to API failed"""


class OutOfRetriesError(ConnectionFailure):
    """Ran out of retries with a HTTP request"""


class ResultNotFound(AppcheckException):
    """Result for requested ID or SHA1 was not found"""


class InvalidLoginError(AppcheckException):
    """Login was rejected"""
