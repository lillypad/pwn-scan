#!/usr/bin/python
# Author: Arc Network Security
# Depends On: 
# sudo pip install TermColor
# sudo pip install ArgParse
# sudo pip install requests

import sys
try:
	import argparse
except ImportError:
	print "ArgParse not Installed"
	print "Hint: sudo pip install ArgParse"
	sys.exit()
try:
	import requests
except ImportError:
	print "Requests not Installed"
	print "Hint: sudo pip install requests"
import textwrap
import json
import re
try:
	from termcolor import colored
except ImportError:
	print "TermColor not Installed"
	print "Hint: sudo pip install TermColor"
import fileinput

# Strip Html Tags
def striphtml(data):
    p = re.compile(r'<.*?>')
    return p.sub('', data)

parser = argparse.ArgumentParser(description = "Pwn Scanner v1.0 by Arc Network Security", epilog = "Website: http://www.arcnetworksecurity.com")
parser.add_argument('-v', '--version', action='version', version='v1.0')
parser.add_argument('-e', type = str, help="Scan Single Email", required = False)
parser.add_argument('-i', type = str, help="Scan Email List / CSV (one email per line)", required = False)
parser.add_argument('-l', type = str, help="Output to log", required = False)
cmdargs = parser.parse_args()

if cmdargs.e and cmdargs.i:
	print "Please use -e or -i not both"
	sys.exit()

# Enable Logging
if cmdargs.l:
	sys.stdout = open(cmdargs.l, 'w')

# Main Class
class pwn:
	def __int__():
		email = "example@example.com"
		data  = "example"
	def pwncheck(self, email):
		url = "https://haveibeenpwned.com/api/v2/breachedaccount/" + email
		r = requests.get(url)
		try:
			parsed = json.loads(r.content)
		except ValueError, e:
			print colored(email + ' OK', 'green')
			return False
		print colored("--- BREACH FOUND FOR " + email + " ---", 'red')
		print "Accounts pwned: " + str(len(parsed))
		for item in parsed:
			print "---BEGIN " + item.get('Domain') + "---"
			if item.get('IsSensitive') == False:
				print colored('BREACH NOT SENSITIVE', 'green')
			if item.get('IsSensitive') == True:
				print colored('BREACH IS SENSITIVE', 'red')
			print "Breach Date: " + item.get('BreachDate')
			print "Added Date: " + item.get('AddedDate')
			print "Total Records: " + str(len(item.get('DataClasses')))
			print "---BEGIN DESCRIPTION---"
			descParagraph = textwrap.dedent(striphtml(item.get('Description'))).strip()
			for width in [ 60 ]:
				print textwrap.fill(descParagraph, width=width)
			print "--END DESCRIPTION--"
			print "---BEGIN DATA CLASSES---"
			LDataClasses = item.get('DataClasses')
			for i in range(len(LDataClasses)):
				print LDataClasses[i]
			print "---END DATA CLASSES---"
			print "---END " + item.get('Domain') + "---"
		return True
# Create Object
x = pwn()

# Single Email
if cmdargs.e:
	x.email = cmdargs.e
	x.pwncheck(x.email)
# Email List
if cmdargs.i:
	for line in fileinput.input([cmdargs.i]):
		x.email = line.strip('\n')
		x.pwncheck(x.email)
