"""The entry point

"""

from scanner.port_scanner import scan

if __name__ == "__main__":
    scan("C:\\Temp\\scan", "www.google.com")
