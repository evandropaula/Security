"""
This script demonstrates the following:
    - How to scan a target host for known ports and other port ranges from 0 - 65536

My primary focus while coding this script is LEARN how to program in Python. It is NOT my intention
    to cause any harm to 3rd parties (people and/or organizations)

Example:
    python port_scanner

Attention:
    - This script has only being tested on a Windows development enviroment
        - OS = Windows 10 Home Edition (64-bit)
        - OS Version = Microsoft Windows [Version 10.0.16299.371]
        - Laptop = Dell XPS 15 9550
        - RAM = 16GB
        - Physical Cores = 4
        - Logical Cores = 8

    - It takes ~ 18 minutes to scan the ports for a given target host with current environment and settings
        - Increase the max_processes_factor_per_cpu to boost parallelism

"""


import multiprocessing
import os
import time
import uuid

from datetime import datetime
from socket import *
from typing import List


def get_max_degree_of_parallelism() -> int:
    """Returns the max degree of parallelism for resource governance purposes

    Returns:
        The max degree of parallelism.

    """

    logical_processor_count = os.cpu_count()

    # 1     = 100% of CPUs will be used in a given point in time (1 process per CPU)
    #           CAUTION: this setting may cause your CPU % to be 100% constantly until:
    #               a) the dictionaries are created.
    #               b) dictionary files are scanned to try to find the password.
    # 0.5   = 50% of CPUs will be used in a given point in time
    #           This may be useful to throttle CPU usage
    max_processes_factor_per_cpu = 8
    max_degree_of_parallelism = round((max_processes_factor_per_cpu * logical_processor_count), 0)

    return max_degree_of_parallelism


def start_process_for_range(output_directory: str,
                            target_host: str,
                            known_ports: List[int],
                            target_port_start: int,
                            target_port_end: int,
                            running_processes: List[multiprocessing.Process])\
        -> multiprocessing.Process:
    """Starts a new process to scan a port range for a given target host

    Args:
        output_directory: The output directory where opened ports will be written too.
        target_host: The target host (e.g. www.google.com)
        known_ports: The list of known ports (e.g. 80/HTTP, etc.).
        target_port_start: The target port range start number (e.g. 1).
        target_port_end: The target port range end number (e.g. 1000).
        running_processes: The list of processes currently running.

    Returns:
        The process that was just created and started.

     """

    current_process = multiprocessing.Process(
        target=try_connect_range,
        args=(output_directory, target_host, known_ports, target_port_start, target_port_end,))

    running_processes.append(current_process)

    current_process.start()

    return current_process


def throttle_process_start(start_time: datetime,
                           running_processes: List[multiprocessing.Process],
                           completed_processes: List[multiprocessing.Process],
                           max_degree_of_parallelism: int):
    """Throttles creating new processes for resource government purposes

    Args:
        start_time: The overall scan start date/time.
        running_processes: The running processes to be throttled.
        completed_processes: The processes that completed execution so far.
        max_degree_of_parallelism: The max degree of desired parallelism.

    """

    is_throttled = False

    while len(running_processes) >= max_degree_of_parallelism:
        is_throttled = True

        for current_process in running_processes:
            if not current_process.is_alive():
                completed_processes.append(current_process)
                running_processes.remove(current_process)

                if len(running_processes) < max_degree_of_parallelism:
                    break

            time.sleep(0.1)

    # Tracks running time so far if throttling was applied
    if is_throttled:
        end_time = datetime.now()
        print("\n--- Ranges => Completed = {0}; Running = {1}; Partial Elapsed Time = {2} ---"
              .format(len(completed_processes), len(running_processes), end_time - start_time))


def try_connect(target_host, target_port):
    """Return a bool indicating whether the connection was successfully established or not.

    Args:
        target_host (string): The target host to try to connect
        target_port (int): The target port to try to connect

    Returns:
        bool: True if the connection was successfully established to the target host and port.
            Otherwise, it returns False

    """

    try:
        # AF_INET -> Create sockets of the IPv4 address family.
        # Used to create connection-oriented sockets, which provide full error detection and
        #   correction facilities.
        with socket(AF_INET, SOCK_STREAM) as soc:
            # Sets timeout to 1 second
            soc.settimeout(1)

            # .connect (()) because address is a tuple
            # Connect to a TCP service listening on the Internet address (a 2-tuple (host, port)),
            #   and return the socket object
            soc.connect((target_host, target_port))

            print("\n***** Port '{0}' = OPEN *****".format(target_port))

            return True
    except:
        # Exception: timed out.
        return False


def try_connect_range(output_directory: str,
                      target_host: str,
                      known_ports: List[multiprocessing.Process],
                      target_port_start: int,
                      target_port_end: int):
    """ Tries to connect to a range of ports one at a time. If connection is successful, an entry
    will be added to a file ({UUID}_open_ports.txt) in the output directory

    Args:
        output_directory: The output directory where opened ports will be written too.
        target_host: The target host (e.g. www.google.com)
        known_ports: The list of known ports (e.g. 80/HTTP, etc.).
        target_port_start: The target port range start number (e.g. 1).
        target_port_end: The target port range end number (e.g. 1000).

    """

    current_process = multiprocessing.current_process()
    random_uuid = uuid.uuid4()
    process_open_port_file_name = "{0}_open_ports.txt".format(random_uuid)
    process_open_port_file_path = os.path.join(output_directory, process_open_port_file_name)

    # Scans target host for high ports
    print("\n[PID {0}] Scanning host '{1}' ports from '{2}' to '{3}'"
          .format(current_process.pid, target_host, target_port_start, target_port_end))

    for target_port in range(target_port_start, target_port_end):
        if target_port not in known_ports:
            if try_connect(target_host, target_port):
                # Write opened ports to an output file named with UUID created above
                with open(process_open_port_file_path, "a") as process_open_port_file:
                    process_open_port_file.write("{0}\n".format(target_port))


def try_get_ipv4(target_host: str) -> object:
    """Returns target host IPv4 address

    Args:
        target_host (string): The target host to try to resolve the IPv4 address

    Returns:
        The IPv4 address of the target host, if it is able to resolve it. Otherwise, None.

    """

    try:
        target_ipv4 = gethostbyname(target_host)

        print("Host '{0}' IPv4 is '{1}'".format(target_host, target_ipv4))

        return target_ipv4
    except Exception as ex:
        print("Failed to resolve host '{0}' IPv4 address. Exception: {1}."
              .format(target_host, ex))

        return None


def try_get_hostname(target_ipv4: object):
    """Return target host name based on the IPv4 address

    Args:
        target_ipv4: The target host IPv4 address.

    Returns:
        str: The target host IPv4 address if it was resolved properly.
        None: If target host IPv4 address if it was not resolved.

    """

    try:
        target_name_tuple = gethostbyaddr(target_ipv4)

        # Returns a three-item tuple of the form (hostname, aliaslist, ipaddrlist)
        print("Name is '{0}' for IPv4 '{1}'.".format(target_name_tuple, target_ipv4))

        # Returns the hostname only
        return target_name_tuple[0]
    except Exception as ex:
        print("Failed to resolve name for IPv4 address '{0}'. Exception: {1}."
              .format(target_ipv4, ex))

        return None


def scan(output_directory: str,
         target_host: str):
    """Scans target host for opened ports using known ports as well as a broader ranges of ports

    Returns:
        True: The connection was successfully established to the target host and port
        False: The connection was not successfully established to the target host and port
    """

    if not output_directory or output_directory.isspace():
        raise ValueError("Output directory host cannot be none, empty or whitespace.")

    if not os.path.exists(output_directory):
        raise IOError("Output directory '{0}' was not found.".format(output_directory))

    if not target_host or target_host.isspace():
        raise ValueError("Target host cannot be none, empty or whitespace.")

    start_time = datetime.now()

    # Ensures IPv4 can be resolved
    target_ipv4 = try_get_ipv4(target_host)

    if not target_ipv4:
        return

    # Ensures name can be resolved
    if not try_get_hostname(target_ipv4):
        return

    # Scans target host for common ports
    print("\n***** Scanning host '{0}' COMMON ports (e.g. FTP, HTTP, etc.) *****"
          .format(target_host))

    known_ports = [
        21,     # FTP
        23,     # Telnet
        25,     # SMTP
        67,     # DHCP Client
        68,     # DHCP Server
        80,     # HTTP
        110,    # POP3
        135,    # RPC
        139,    # Common Internet File System (CIFS)
        143,    # IMAP
        1433,   # MS SQL Server
        1521,   # Oracle Database Server
        1723,   # VPN (PPTP)
        3306,   # MySQL
        3389,   # RPD (Windows)
    ]

    for target_port in known_ports:
        if target_port < 1:
            raise ValueError("Target must be greater than 0.")

        try_connect(target_host, target_port)

    # Max degree of parallelism for resource governance purposes
    max_degree_of_parallelism = get_max_degree_of_parallelism()

    # Scans target host for high ports
    print("\n***** Scanning host '{0}' OTHER port ranges (Max Degree of Parallelism = {1}) *****"
          .format(target_host, max_degree_of_parallelism))

    # List of processes that will run to scan different port ranges
    running_processes = []
    completed_processes = []

    target_port_start = 1
    max_port_number = 65536  # (Exclusive)
    range_step = 100

    for target_port_end in range(range_step, max_port_number, range_step):
        start_process_for_range(output_directory, target_host, known_ports, target_port_start,
                                target_port_end, running_processes)

        target_port_start = target_port_end

        throttle_process_start(start_time, running_processes, completed_processes,
                               max_degree_of_parallelism)

    # Run the remaining port range
    start_process_for_range(output_directory, target_host, known_ports, target_port_start,
                            target_port_end, running_processes)

    for process in running_processes:
        process.join()

    end_time = datetime.now()

    print("\n***** Completed scanning (Elapsed Time => {0}) *****".format(end_time - start_time))


if __name__ == "__main__":
    scan("C:\\Temp\\scan", "www.google.com")
