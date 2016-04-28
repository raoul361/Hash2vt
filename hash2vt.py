#!/usr/bin/env python

import virustotal
import argparse
import re
from time import sleep

__author__ = "Raoul Endresl"
__copyright__ = "Copyright 2016"
__license__ = "BSD"
__version__ = "0.1"
__status__ = "Prototype"

# Get of my damn API_KEY. Free API, register at virustotal.com
API_KEY = "[KEY GOES HERE]"

parser = argparse.ArgumentParser(description='Searches a given file for hashes and checks these against VirusTotal.')
parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true", default=False)
parser.add_argument("filename", type=argparse.FileType('r'), help="file to search for MD5 hashes")

args = parser.parse_args()

v = virustotal.VirusTotal(API_KEY,0)

if args.verbose:
    print """
   _  _  ________          __   
__| || |_\_____  \___  ___/  |_ 
\   __   //  ____/\  \/ /\   __\\
 |  ||  |/       \ \   /  |  |  
/_  ~~  _\_______ \ \_/   |__|  
  |_||_|         \/             

"""

    print "[+] parsing " + args.filename.name

data = args.filename.read()

# Find hashes in the stream of data...
md5hashes = re.findall(r"\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{32}|[A-F\d]{32})\b", data)
sha1hashes = re.findall(r"\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{40}|[A-F\d]{40})\b", data)
sha256hashes = re.findall(r"\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{64}|[A-F\d]{64})\b", data)

if args.verbose:
    print "[+] MD5 hashes    " + str(len(md5hashes))
    print "[+] SHA1 hashes   " + str(len(sha1hashes))
    print "[+] SHA256 hashes " + str(len(sha256hashes))

hashes =  sha1hashes + sha256hashes + md5hashes
print "[+] Adding " + str(len(hashes)) + " hashes. Expected " + str(len(hashes)/4) + " minutes"

for hash in hashes:
	report = v.get( hash )	
	if report.done:
		if report.positives > 0:
			print "[*] match: " + hash + " - VirusTotal score: ", report.positives
		elif args.verbose:
			print "[-] clean: " + hash
	sleep(15) # max 4 calls per minute on the private API