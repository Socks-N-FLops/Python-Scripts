There are two scripts to run and you can take them as is or edit them to your liking.

The first script to run is "import_blacklists.py" - this script pulls threatfeeds based on URL and saves them as txt to a directory
Example:

BLACKLIST_URLS = {
    #"example_blacklist1": "http://example.com/blacklist1.txt",
    #"example_blacklist2": "http://example.com/blacklist2.txt"
    }
BLACKLIST_DIRECTORY = r"C:\Users\username\Desktop\Network Analysis\bad_lists"

Once you have a decent threatfeed directory of your liking move on to the second script "dns_blacklists.py"
This script will compare what is listed in the bad_lists directory against your text file of IPs and/or domains that need to be checked.

Example: I want to check if there's a data transfer/connection from a host to a malicious IP or domain. I would create a text file with all of the IPs and/or domains seen and
name it something like "sus.txt" in a directory named "check_lists"

The input could look something like this:

python .\dns_blacklists.py .\bad_lists .\check_lists
