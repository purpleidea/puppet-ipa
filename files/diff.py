#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (C) 2012-2013+ James Shubin
# Written by James Shubin <james@shubin.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# NOTE: this script should always be called from puppet, it's useless by itself
# NOTE: for manual command line viewing of data you can use:
#	$ ipa host-show 'foo.example.com' --all --raw | cut -b 3-
#
# EXAMPLE:
#	$ ./diff.py ${valid_hostname} ${args} && echo TRUE || echo FALSE
#
# where ${} are puppet variables...
#
# NOTE: this is a particularly finicky piece of code. edit at your own risk...
# the reason it is so tricky, is because it has to cater to ipa's intricacies!

import sys
import argparse
import ipalib
from ipapython.ssh import SSHPublicKey

ipalib.api.bootstrap()
ipalib.api.load_plugins()
ipalib.api.finalize()
ipalib.api.Backend.xmlclient.connect()

def unicodeize(x):
	if type(x) == type([]):
		return [unicode(i) if isinstance(i, basestring) else i for i in sorted(x)]
	elif type(x) == type(()):
		return tuple([unicode(i) if isinstance(i, basestring) else i for i in sorted(x)])
	elif isinstance(x, basestring):
		return unicode(x)
	else:
		return x

# verify each of these keys matches
verify = [
	'macaddress',
	'sshpubkeyfp',
	'l',
	'nshostlocation',
	'nshardwareplatform',
	'nsosversion',
	'description',
]

def process_macaddress(x):
	if x is None: return None	# pass through the none's
	if x == []: return None		# empties show up as 'None' in freeipa
	return x

def process_sshpubkeyfp(x):
	# in comes a list of ssh keys. we need to process each one into the
	# format as returned by freeipa. freeipa returns a tuple of strings
	# eg:
	# (u'AB:98:62:82:C0:74:47:5E:FC:36:F7:5A:D7:8F:8E:FF (ssh-dss)',
	# u'62:6D:8B:7B:3F:E3:EA:4C:50:4D:86:AA:BF:17:9D:8B (ssh-rsa)')
	if x is None: return None	# pass through the none's
	if x == []: return None		# empties show up as 'None' in freeipa
	if x == ['']: return None	# this is the empty --sshpubkey=
	result = []
	for i in x:
		# this code is the algorithm used in: ipalib/util.py
		pubkey = SSHPublicKey(i)
		fp = pubkey.fingerprint_hex_md5()
		comment = pubkey.comment()
		if comment: fp = u'%s %s' % (fp, comment)
		fp = u'%s (%s)' % (fp, pubkey.keytype())
		result.append(fp)

	return result

# "adjust" each of these keys somehow...
process = {
	# NOTE: all the list types need a process function to noneify empties
	'macaddress': process_macaddress,
	'sshpubkeyfp': process_sshpubkeyfp,
}

parser = argparse.ArgumentParser()

parser.add_argument('hostname', action='store')	# positional arg
parser.add_argument('--debug', dest='debug', action='store_true', default=False)
parser.add_argument('--not', dest='n', action='store_true', default=False)

# this is a mapping with dest being the --raw key to look for the data!
parser.add_argument('--macaddress', dest='macaddress', action='append', default=[])	# list
# this is actually part of DNS, ignore it...
#parser.add_argument('--ip-address', dest='ip?', action='store')

parser.add_argument('--sshpubkey', dest='sshpubkeyfp', action='append', default=[])	# list

parser.add_argument('--locality', dest='l', action='store')
parser.add_argument('--location', dest='nshostlocation', action='store')
parser.add_argument('--platform', dest='nshardwareplatform', action='store')
parser.add_argument('--os', dest='nsosversion', action='store')
parser.add_argument('--desc', dest='description', action='store')

args = parser.parse_args()

try:
	#output = ipalib.api.Command.host_show(fqdn=unicode(args.hostname))
	output = ipalib.api.Command.host_show(unicode(args.hostname))
except ipalib.errors.NotFound, e:
	if args.debug:
		print >> sys.stderr, 'Not found'
	# NOTE: if we exit here, it's a bug in the puppet module because puppet
	# should only be running this script for hosts that it believe exist...
	sys.exit(2)

result = output.get('result', {})	# the freeipa api returns a result key!
if args.debug:
	print args
	print result

# NOTE: a lot of places you'll see [0] because everything is wrapped in tuples!
x = unicode(args.hostname.lower())
y = unicode(result.get('fqdn', '')[0].lower())
assert x == y, "FQDN does not match!"	# verify we got the right fqdn
# loop through all the keys to validate
for i in verify:
	#print i, getattr(args, i)
	#if i in process.keys():
	f = process.get(i, lambda x: x)	# function
	#v = getattr(args, i)	# value
	v = f(getattr(args, i))	# value after processing
	if v is not None:
		# a is the value we got from the api lookup
		# b is the processed value we got from the command line
		# convert our lists to tuples...
		a = result.get(i, None)	# should already be unicode...
		b = v
		if type(b) == type([]):
			if a is None:
				# value is empty, ideally it should return (,)
				sys.exit(1)
			assert type(a) == type(()), ('Expected tuple on: %s' % i)
			a = unicodeize(a)	# also sorts...
			b = tuple(unicodeize(b))	# both must be tuples!
		elif type(b) == type(''):
			a = a[0]	# unwrap the string from the tuple!
			b = unicodeize(v)
		else:
			# TODO: add support for any other types if we need them
			assert False, ("Unknown datatype: %s" % type(b))

		#print i, a, b
		if a != b:
			if args.debug:
				print >> sys.stderr, ('Unmatched on %s between %s and %s' % (i, a, b))
			if args.n:
				sys.exit(0)
			else:
				sys.exit(1)
if args.n:
	sys.exit(1)
else:
	sys.exit(0)	# everything matches

