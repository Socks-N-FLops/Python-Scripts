import os
import requests
import logging
from datetime import datetime
import codecs
import re
import socket

# Log file setup
logging.basicConfig(
    filename="blacklist_update.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Configurations for blacklists
BLACKLIST_URLS = {
    #"example_blacklist1": "http://example.com/blacklist1.txt",
    #"example_blacklist2": "http://example.com/blacklist2.txt",
    "blacklist_abuse_SSLBL_Botnet_c2" : "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "blacklist_abuse_SSLBL_Botnet_c2_aggresive" : "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt",
    "IPSum_Level_1" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "IPSum_Level_2" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "IPSum_Level_3" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "IPSum_Level_4" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
    "IPSum_Level_5" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
    "IPSum_Level_6" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
    "IPSum_Level_7" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
    "IPSum_Level_8" : "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt",
    "Mirai_Sec" : "https://mirai.security.gives/data/ip_list.txt",
    "greensnow" : "https://blocklist.greensnow.co/greensnow.txt"


}
BLACKLIST_DIRECTORY = r"C:\Users\username\Desktop\Network Analysis\bad_lists"

# Helper functions
def download_blacklist(name, url, directory):
    """
    Downloads a blacklist file from a URL and saves it to the directory.
    """
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        file_path = os.path.join(directory, f"{name}.txt")
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(response.text)
        logging.info(f"Successfully updated blacklist: {name}")
    except Exception as e:
        logging.error(f"Failed to download {name} from {url}: {e}")

def update_blacklists(urls, directory):
    """
    Updates all blacklists in the specified directory.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    for name, url in urls.items():
        logging.info(f"Updating blacklist: {name} from {url}")
        download_blacklist(name, url, directory)

def parse_file(filename):
    """
    Parse file content to extract IPs and hostnames.
    """
    ipv4_cidr_regex = re.compile(r"""...""", re.VERBOSE)  # Use the regex from your script
    ipv6_regex = re.compile(r"""...""", re.VERBOSE)
    hostname_regex = re.compile(r"""...""", re.VERBOSE)

    ip_set = set()
    hostname_set = set()
    try:
        with codecs.open(filename, encoding='utf-8') as inf:
            for line in inf:
                for ip in ipv6_regex.finditer(line):
                    ip_set.add(ip.group(1))
                for ip in ipv4_cidr_regex.finditer(line):
                    ip_set.add(ip.group(1))
                for hostname in hostname_regex.finditer(line):
                    hostname_set.add(hostname.group(1))
    except Exception as e:
        logging.error(f"Error parsing file {filename}: {e}")
    return (hostname_set, ip_set)

# Main function
if __name__ == "__main__":
    print("Starting blacklist update...")
    logging.info("Starting blacklist update.")

    # Update blacklists
    update_blacklists(BLACKLIST_URLS, BLACKLIST_DIRECTORY)

    print("Parsing updated blacklist files...")
    logging.info("Parsing updated blacklist files.")

    # Parse files in the blacklist directory
    blacklist_sets = (set(), set())
    for filename in os.listdir(BLACKLIST_DIRECTORY):
        filepath = os.path.join(BLACKLIST_DIRECTORY, filename)
        if not os.path.isfile(filepath):
            continue
        print(f"Parsing {filename}")
        blacklist = parse_file(filepath)
        blacklist_sets[0].update(blacklist[0])
        blacklist_sets[1].update(blacklist[1])

    print("Blacklist update and parsing complete.")
    logging.info("Blacklist update and parsing complete.")
