"""Entry point

"""

from ftpscannerlib import try_ftp_anonymous_login

def main():
    """Entry point function

    """
    try_ftp_anonymous_login("127.0.0.1")

if __name__ == "__main__":
    main()
