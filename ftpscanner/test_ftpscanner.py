"""Tests for the FTP scanner implementation.

"""

import unittest
import pytest

from ftpscannerlib import try_ftp_anonymous_login

class TestFtpScanner(unittest.TestCase):
    """FTP scanner tests.

    """

    def test_invalid_host(self):
        """Test try to connect to FTP when host is invalid.

        """

        with pytest.raises(ValueError):
            try_ftp_anonymous_login(None)

        with pytest.raises(ValueError):
            try_ftp_anonymous_login("")

        with pytest.raises(ValueError):
            try_ftp_anonymous_login(" ")

    def test_try_ftp_anonymous_login(self):
        """Test to try to connect to a given FTP using the anonymous login.

        """

        try_ftp_anonymous_login("127.0.0.1")

if __name__ == '__main__':
    unittest.main()
