"""
This script demonstrates the following:
    - How to generate a list of password files based on a base string (ASCII 33 - 126) permutation
        with a target number of slots (4).
    - How to crack a ZIP file secured with password through brute force approach based on password
        files created by the previous step.

My primary focus while coding this script is LEARN how to program in Python. It is NOT my intention
    to cause any harm to 3rd parties (people and/or organizations)

However, here are some considerations if I were to build a production serviec for crack ZIP file
    passwords:
    - Increase the character set to be more diverse, including chars with accents such as {á,ã,ú,ü}
        commonly used in languages like Portuguese-Brazil (pt-br). Moreover, include unicode
        characters as well.
    - Generate dictionaries with larger permutations (24-long) to increase coverage.
    - Decrease the amount of lines (e.g. 1024) created per dictionary to enable faster
        distributed search.
    - Distribute the dictionary files across more folder considering there is limit of files per
        directory.
    - Launch cracking processes across multiple nodes to speed up overall processing time.
    - Keep a list of most used passwords and instruct people and organizations not to use those
        (e.g. p@$$w0rd).

Example:
    python zip-file-password-cracker.py

Attention:
    - This script has only being tested on a Windows development enviroment

Attention - Dictionary:
    - The max slots defines the length of the passwords resulted from the permutation operation.
        Therefore, the default slot configured in this script is 4, which generates 319 text files.
    - CAUTION: increasing the slots may fill up your disk space.
    - The default maximum number of rows per file is 250K.
    - It takes ~2 minutes to generate these password files under the following conditions:
        - OS = Windows 10 Home Edition (64-bit)
        - Laptop = Dell XPS 15 9550
        - RAM = 16GB
        - Physical Cores = 4
        - Logical Cores = 8
        - Disk = SSD NVMe THNSN5512GPUK NV
        - Number of Slots for Permutation = 4

Attention - Password Cracking:
    - The execution is throttled based on the number of logical cores available and a % factor to
        make sure the script won't consume 100% of CPU.

"""

import itertools
import multiprocessing
import os
import time
import zipfile

from datetime import datetime
from zipfile import BadZipFile


def __get_max_degree_of_parallelism():
    """Returns the max degree of parallelism for resource governance purposes

    Returns:
         int: The max degree of parallelism.
    """
    logical_processor_count = os.cpu_count()

    # 1     = 100% of CPUs will be used in a given point in time (1 process per CPU)
    #           CAUTION: this setting may cause your CPU % to be 100% constantly until:
    #               a) the dictionaries are created.
    #               b) dictionary files are scanned to try to find the password.
    # 0.5   = 50% of CPUs will be used in a given point in time
    #           This may be useful to throttle CPU usage
    max_processes_factor_per_cpu = 0.5
    max_degree_of_parallelism = round((max_processes_factor_per_cpu * logical_processor_count), 0)

    return max_degree_of_parallelism


def create_dictionary_if_not_exists(output_directory, permutation_slots):
    """Creates a new file of possible passwords if does not exist yet

    Args:
        output_directory (string): Output directory where the dictionary files will be written to
            (e.g. c:\temp).
        permutation_slots (int): The target slots to generated password permutations.

    """

    # Input validation
    if not output_directory or output_directory.isspace():
        raise ValueError("Directory cannot be none, empty or whitespace.")

    if permutation_slots < 1:
        raise ValueError("Max permutation slots must to be greater than 0.")

    # Remove this validation in order to proceed generating longer password permutations
    if permutation_slots > 4:
        raise ValueError("Max permutation slots is high. Remove this validation from the script, "
                         "which was added to prevent you filling up your disk by accident.")

    # Ensures the output directory EXISTS
    # This is intentional to make whoever runs this script is aware of the destination directory
    #   considering it potentially can fill up the disk
    if not os.path.exists(output_directory):
        raise IOError("Directory '{0}' does not exist.".format(output_directory))

    start = datetime.now()

    # Current process
    current_process = multiprocessing.process.current_process()

    # ASCII table
    ascii_chars = []

    # ASCII table char range to generate permutations
    ascii_start_index = 33  # ! (Inclusive)
    ascii_end_index = 127   # ~ (Exclusive)

    # Generates passwords using characters from the ASCII table
    for i in range(ascii_start_index, ascii_end_index):
        ascii_chars.append(chr(i))

    # File rollover settings
    max_lines_per_file = 250000
    current_line_number = 0
    current_file_number = 0

    # File with possible passwords
    file = None
    file_path = None

    try:
        for password in itertools.product(ascii_chars, repeat=permutation_slots):
            # Rollover file if max number of rows is reached
            if current_line_number % max_lines_per_file == 0:
                file_name = "dictionary_{0}_{1}.txt".format(permutation_slots, current_file_number)
                file_path = os.path.join(output_directory, file_name)

                if os.path.isfile(file_path):
                    print("\nFile '{0}' already exists. Skipping it...".format(file_path))
                    return
                else:
                    print("\nCreating file '{0}' with passwords...".format(file_path))

                # Open a new file if max lines per file has been reached
                file = open(file_path, "w")

                current_file_number = current_file_number + 1
                current_line_number = 0

            # Write password to file
            file.write("{0}\n".format("".join(password)))

            current_line_number = current_line_number + 1
    finally:
        if file and not file.closed:
            file.close()
    
    end = datetime.now()

    print("\n[PID={0}] Dictionary file '{1}' created successfully (Elapsed Time => {2})"
          .format(current_process.pid, file_path, (end - start)))


def create_dictionaries(output_directory):
    """Coordinates multiple processes to create files with passwords

    Args:
        output_directory (string): Output directory where the dictionary files will be written to
            (e.g. c:\temp).

    TODO:
        Implement max degree of parallelism
    """

    start = datetime.now()

    # Target slot to generate password permutations
    permutations_slots = 4

    processes = []

    total_files_created = 0

    for i in range(1, permutations_slots + 1):
        current_process = multiprocessing.Process(
            target=create_dictionary_if_not_exists,
            args=(output_directory, i,))
        processes.append(current_process)
        current_process.start()
        total_files_created = total_files_created + 1

    for current_process in processes:
        current_process.join()

    end = datetime.now()

    print("\n***** [Dictionary] {0} dictionaries created successfully (Elapsed Time => {1}) *****"
          .format(total_files_created, (end - start)))


def try_crack_zip_file_password(zip_file_path, output_directory, password):
    """Tries to crack ZIP file with password

    Args;
        zip_file_path (string): ZIP file path (e.g. c:\temp\file.zip).
        output_directory (string): Output directory where the password will be written to along
            with uncompressed version of the file(e.g. c:\temp\cracked).
        password (string): The password to try it out
    """

    if not password or password.isspace():
        raise ValueError("Password cannot be none, empty or whitespace.")

    zip_file = zipfile.ZipFile(zip_file_path)

    try:
        # Tries to extract the file with password
        zip_file.extractall(path=output_directory, pwd=password.encode())

        # Password FOUND, displaying it on the console and saving it to a file
        print("------------------------------------------------------------------------->")
        print("> Password FOUND -> '{0}'".format(password))

        password_file_path = os.path.join(output_directory, "password.txt")

        print("> Writing password to file '{0}'...".format(password_file_path))
        print("------------------------------------------------------------------------->")

        with open(password_file_path, 'w') as password_file:
            password_file.write("{0}\n".format(password))

        return True

    except RuntimeError:
        # Swallow runtime exception because the password is wrong
        # RuntimeError: Bad password for file
        #   <ZipInfo filename='raw.txt' external_attr=0x20 file_size=12 compress_size=24>
        return False

    except BadZipFile:
        # Swallow the bad zip file exception
        # zipfile.BadZipFile: Bad CRC-32 for file 'raw.txt'
        return False


def crack_zip_file_with_dictionary(
        zip_file_path,
        output_directory,
        dictionary_file_path,
        return_dictionary):
    """Cracks ZIP file based on words defined in various dictionaries.

    Args:
        zip_file_path (string): ZIP file path (e.g. c:\temp\file.zip).
        output_directory (string): Output directory where the password will be written to
            along with uncompressed version of the file(e.g. c:\temp\cracked).
        dictionary_file_path (string): The current file with password being processed by
            this process (c:\temp\dic\dictionary_1_0.txt).
        return_dictionary (dict): The dictionary to enable sharing state accross the main
            process and children ones.
    """

    current_process = multiprocessing.process.current_process()

    return_dictionary[current_process.pid] = False

    with open(dictionary_file_path, "r") as dictionary_file:
        for line in dictionary_file.readlines():
            password = line.strip("\n")
            found = try_crack_zip_file_password(zip_file_path, output_directory, password)
            if found:
                print(">>> setting return to true = {0}".format(found))
                return_dictionary[current_process.pid] = True

                # Password FOUND, stop execution
                return

    print("\n[PID={0}] Done trying passwords in file '{1}'"
          .format(current_process.pid, dictionary_file_path))


def crack_zip_file(zip_file_path, output_directory, dictionary_directory):
    """Cracks ZIP file based on words defined in various dictionaries.

    Args:
        zip_file_path (string): ZIP file path (e.g. c:\temp\file.zip).
        output_directory (string): Output directory where the password will be written to along
            with uncompressed version of the file(e.g. c:\temp\cracked).
        dictionary_directory (string): The directory where to find the files with possible passwords
    """

    # Input validation
    if not zip_file_path or zip_file_path.isspace():
        raise ValueError("Zip file path cannot be none, empty or whitespace.")

    if not output_directory or output_directory.isspace():
        raise ValueError("Output file path cannot be none, empty or whitespace.")

    # Ensures the ZIP file EXISTS
    if not os.path.isfile(zip_file_path):
        raise IOError("Zip file '{0}' was not found.".format(zip_file_path))

    # Ensures the output directory EXISTS
    if not os.path.exists(output_directory):
        raise IOError("Output directory '{0}' was not found.".format(output_directory))

    # Ensures the dictionary directory EXISTS
    if not os.path.exists(dictionary_directory):
        raise IOError("Dictionary directory '{0}' was not found.".format(dictionary_directory))

    start = datetime.now()

    # Max degree of parallelism for resource governance purposes
    max_degree_of_parallelism = __get_max_degree_of_parallelism()
    processes = []

    print("***** [CrackingPassword] Max degree of parallelism = {0} *****"
          .format(max_degree_of_parallelism))

    # Shared state to enable determining when the password was found and stop processing
    manager = multiprocessing.Manager()
    return_dictionary = manager.dict()
    is_password_cracked = False

    total_files_processed = 0

    for dictionary_file_name in os.listdir(dictionary_directory):
        if is_password_cracked:
            break

        dictionary_file_path = os.path.join(dictionary_directory, dictionary_file_name)

        current_process = multiprocessing.Process(
            target=crack_zip_file_with_dictionary,
            args=(zip_file_path, output_directory, dictionary_file_path, return_dictionary,))

        processes.append(current_process)
        current_process.start()

        print("\n[PID={0}] Start trying to crack ZIP file '{1}' with passwords in file '{2}'"
              .format(current_process.pid, zip_file_path, dictionary_file_path))

        # Resource governance
        while len(processes) >= max_degree_of_parallelism:
            if is_password_cracked:
                break

            for current_process in processes:
                if not current_process.is_alive():
                    processes.remove(current_process)

                    total_files_processed = total_files_processed + 1

                    print("\n***** Dictionary files processed = {0} *****"
                          .format(total_files_processed))

                    if return_dictionary.get(current_process.pid, False):
                        is_password_cracked = True
                        break 

                    if len(processes) < max_degree_of_parallelism:
                        break
            
                time.sleep(0.1)

    # Wait on remaining processes to finish executing
    for current_process in processes:
        if is_password_cracked:
            print("\nTerminating process '{0}'...".format(current_process.pid))
            current_process.terminate()
        else:
            print("\nWaiting on process '{0}' to complete...".format(current_process.pid))
            current_process.join()

    end = datetime.now()

    if is_password_cracked:
        print("\n***** [CrackingPassword] Password CRACKED successfully (Elapsed Time => {0}) *****"
              .format((end - start)))
    else:
        print("\n***** [CrackingPassword] Password NOT FOUND (Elapsed Time => {0}) *****"
              .format((end - start)))


def main():
    """Entry point

    TODO:
        - Implement support to take arguments via command line
    """

    # Adjust the following variable and run the script
    dictionary_directory = "C:\\Temp\\CrackZip\\dic"
    zip_file_path = "C:\\Temp\\CrackZip\\raw.zip"
    output_directory = "C:\\Temp\\CrackZip\\cracked"

    # create_dictionaries(dictionary_directory)

    # crack_zip_file(zip_file_path, output_directory, dictionary_directory)


if __name__ == "__main__":
    main()
