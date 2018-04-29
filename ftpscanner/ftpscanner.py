"""FTP scanner for hosts with 'anonymous' login enabled.

Recommendation:
    - Ensure Anonymous and Basic Authentication are disabled. Note that these
    are disabled by default after installation on Windows.

"""

import ftplib

from ftplib import error_reply

def ftp_anonymous_login(host: str) -> bool:
    """Try to connect to a given FTP server using the 'anonymous' login
    that IT professionals may have left enabled.

    """
    if not host or host.isspace():
        raise ValueError("Host cannot be none, empty or whitespace.")

    try:
        with ftplib.FTP(host=host, user="anonymous", acct="a@a.com") as ftp:
            ftp.login()

        print(f"FTP anonymous login IS ENABLED for host '{host}'.")

        return True
    except ConnectionRefusedError as conn_refused_err:
        print(f"FTP anonymous login FAILED for host '{host}'. Exception: {conn_refused_err}.")
        return False

def main():
    """Entry point

    """
    ftp_anonymous_login("127.0.0.1")
