import os
import re
import codecs
import logging

# Log file setup
logging.basicConfig(
    filename="blacklist_update.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

USAGE = """\
Usage: python dns_blacklists.py blacklist_directory check_directory

blacklist_directory - directory containing the blacklist files
check_directory     - directory containing the files to check against the blacklists
"""

# Helper functions
def parse_file(filename):
    """
    Parses a file to extract IPs and hostnames.
    Returns a set of entries found in the file.
    """
    ipv4_cidr_regex = re.compile(r"""(
        (
            (
                [0-9]
                |[1-9][0-9]
                |1[0-9]{2}
                |2[0-4][0-9]
                |25[0-5]
            )
            \.
        ){3}
        (
            25[0-5]
            |2[0-4][0-9]
            |1[0-9]{2}
            |[1-9][0-9]
            |[0-9]
        )
        (/(3[012]|[12]\d|\d))?
    )
    \D""", re.VERBOSE)

    hostname_regex = re.compile(r"""(
        (
            (
                [a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]|
                [a-zA-Z0-9]
            )
            \.
        )+
        (
            [A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]|
            [A-Za-z0-9]
        )
    )""", re.VERBOSE)

    entries = set()
    try:
        with codecs.open(filename, encoding='utf-8') as inf:
            for line in inf:
                for ip in ipv4_cidr_regex.finditer(line):
                    entries.add(ip.group(1))
                for hostname in hostname_regex.finditer(line):
                    entries.add(hostname.group(1))
    except Exception as e:
        logging.error(f"Error parsing file {filename}: {e}")
    return entries

if __name__ == "__main__":
    if len(os.sys.argv) != 3:
        print(USAGE)
        os.sys.exit(1)

    blacklist_dir = os.sys.argv[1]
    check_dir = os.sys.argv[2]

    print("Starting blacklist check...")
    logging.info("Starting blacklist check.")

    # Parse blacklist files into a dictionary mapping entries to their source files
    blacklist_map = {}
    print('Parsing blacklist files...')
    for filename in os.listdir(blacklist_dir):
        filepath = os.path.join(blacklist_dir, filename)
        if not os.path.isfile(filepath):
            continue
        print(f"Parsing {filename}")
        blacklist_entries = parse_file(filepath)
        for entry in blacklist_entries:
            blacklist_map[entry] = filename

    # Parse check files and cross-reference with blacklist entries
    print('Parsing check files...')
    matches = []
    for filename in os.listdir(check_dir):
        filepath = os.path.join(check_dir, filename)
        if not os.path.isfile(filepath):
            continue
        print(f"Parsing {filename}")
        check_entries = parse_file(filepath)
        for entry in check_entries:
            if entry in blacklist_map:
                matches.append((entry, blacklist_map[entry]))

    # Output matches
    print()
    print('=' * 80)
    print('The following hostnames and IPs were found in the blacklists:')
    print('=' * 80)
    for entry, source_file in matches:
        print(f"{entry} - {source_file}")
        logging.info(f"Match found: {entry} in {source_file}")

    print("Blacklist check complete.")
    logging.info("Blacklist check complete.")
