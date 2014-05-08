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
#	$ ./diff.py host ${valid_hostname} ${args} && echo TRUE || echo FALSE
#	$ ./diff.py service ${valid_service} ${args} && echo TRUE || echo FALSE
#	$ ./diff.py user ${valid_login} ${args} && echo TRUE || echo FALSE
#
# where ${} are puppet variables...
#
# NOTE: this is a particularly finicky piece of code. edit at your own risk...
# the reason it is so tricky, is because it has to cater to ipa's intricacies!

import sys
import argparse
import ipalib
from ipapython.ssh import SSHPublicKey

#
#	helper functions
#
def p(x, f=lambda x: x):
	"""Pass None values through, otherwise apply function."""
	if x is None: return None
	return f(x)

def get(value, default):
	if value is None: return default
	else: return value

# NOTE: a lot of places you'll see [0] because everything is wrapped in tuples!
# IPA does this for some reason, feel free to use the @left(untuple) decorator!
def untuple(x):
	"""Untuple a single value that was wrapped in a tuple."""
	assert type(x) == type(()), 'Expected tuple.'	# safety check
	assert len(x) == 1, 'Expected tuple singleton.'	# safety check
	return x[0]

def listclean(x):
	"""Clean empty value lists to match puppets 'manage', but empty."""
	# NOTE: 0 length list values in ipa are None, ideally they should be (,)
	# TODO: uncomment this first condition as well if it is ever needed...
	#if x == []: return None	# empties show up as 'None' in freeipa
	if x == ['']: return None	# this is the empty: --argument-value=
	return x

def lowerize(x):
	"""Transform input value into upper, recursively."""
	# TODO: dict ?
	if type(x) == type([]):
		return [lowerize(i) for i in x]			# recurse
	elif type(x) == type(()):
		return tuple([lowerize(i) for i in x])		# recurse
	elif isinstance(x, basestring):
		return x.lower()				# don't recurse
	else:
		return x					# int's, etc...

def upperize(x):
	"""Transform input value into upper, recursively."""
	# TODO: dict ?
	if type(x) == type([]):
		return [upperize(i) for i in x]			# recurse
	elif type(x) == type(()):
		return tuple([upperize(i) for i in x])		# recurse
	elif isinstance(x, basestring):
		return x.upper()				# don't recurse
	else:
		return x					# int's, etc...

def unicodeize(x):
	"""Transform input value into unicode, recursively."""
	# TODO: dict ?
	if type(x) == type([]):
		return [unicodeize(i) for i in x]		# recurse
	elif type(x) == type(()):
		return tuple([unicodeize(i) for i in x])	# recurse
	elif isinstance(x, basestring):
		return unicode(x)				# don't recurse
	else:
		return x					# int's, etc...

def sshfp(x):
	"""Transform a public ssh key into the ipa style fingerprint."""
	if type(x) == type([]):
		return [sshfp(i) for i in x]			# recurse

	# this code is the algorithm used in: ipalib/util.py
	pubkey = SSHPublicKey(x)
	fp = pubkey.fingerprint_hex_md5()
	comment = pubkey.comment()
	if comment: fp = u'%s %s' % (fp, comment)
	fp = u'%s (%s)' % (fp, pubkey.keytype())
	return fp

def sshdsp(x):
	"""Transform a public ssh key into the ipa style display."""
	if type(x) == type([]):
		return [sshdsp(i) for i in x]			# recurse

	# this code is the algorithm used in: ipalib/util.py
	return SSHPublicKey(x).openssh()	# normalize_sshpubkey

#
#	function decorators to wrap cmp functions
#
def debug(f):
	"""Function decorator to help debug cmp values."""
	def r(x, y):
		if args.debug:
			# NOTE: f.func_name works if it is closest to function!
			print 'f:', f.func_name, 'x:', x, 'y:', y
		return f(x, y)

	return r	# we're a function decorator

def lower(f):
	"""Function decorator to lower case x and y inputs."""
	# NOTE: this shows the longer versions of the decorator...
	#def r(x, y):
	#	#_x = None if x is None else lowerize(x)
	#	#_y = None if y is None else lowerize(y)
	#	#return f(_x, _y)
	#	return f(p(x, lowerize), p(y, lowerize))
	#return r
	return lambda x, y: f(p(x, lowerize), p(y, lowerize))

def upper(f):
	"""Function decorator to upper case x and y inputs."""
	return lambda x, y: f(p(x, upperize), p(y, upperize))

# TODO: is this unused because of @left(list) ?
def lists(f):
	"""Function decorator to ensure both inputs are lists."""
	return lambda x, y: f(p(x, list), p(y, list))

def sort(f):
	"""Function decorator to sort x and y inputs."""
	return lambda x, y: f(p(x, sorted), p(y, sorted))

def unique(f):
	"""Function decorator to remove duplicates in x and y inputs."""
	d = lambda z: list(set(z))	# remove duplicates
	return lambda x, y: f(p(x, d), p(y, d))

def unicoded(f):
	"""Function decorator to unicode x and y inputs including lists, and
	tuples. Recurses into compound types like lists."""
	return lambda x, y: f(p(x, unicodeize), p(y, unicodeize))

def left(l=lambda z: z):
	"""Return a function decorator using a lambda l for the left only."""
	def inner_left(f):
		"""Function decorator to ensure l is applied on the left."""
		return lambda x, y: f(p(x, l), y)
	return inner_left

def right(l=lambda z: z):
	"""Return a function decorator using a lambda l for the right only."""
	def inner_right(f):
		"""Function decorator to ensure l is applied on the right."""
		return lambda x, y: f(x, p(y, l))
	return inner_right

# NOTE: we could rewrite lower,upper,lists,sort,unique and etc in terms of this
def both(l=lambda z: z):
	"""Return a function decorator using a lambda l for both x and y."""
	def inner_both(f):
		"""Function decorator to ensure l is applied to both x and y."""
		return lambda x, y: f(p(x, l), p(y, l))
	return inner_both

#
#	composed decorators
#
# http://docs.python.org/2/reference/compound_stmts.html#grammar-token-decorated
def ipalist(f):
	# equivalent to decorating with:
	# @left(list)
	# @right(listclean)
	# @unicoded
	return left(list)(right(listclean)(unicoded(f)))

def ipastr(f):
	# @left(untuple)
	# @unicoded
	return left(untuple)(unicoded(f))

#
#	cmp functions
#
@unicoded
def cmp_default(x, y):
	return x == y

#
#	host cmp functions
#
@left(untuple)
@lower		# TODO: should we drop the @lower ?
@unicoded
def cmp_host_primarykey(x, y):
	return x == y

@left(list)
@right(listclean)
@sort
@upper		# ipa expects uppercase mac addresses
@unicoded
def cmp_host_macaddress(x, y):
	return x == y

#@left(list)
#@right(listclean)
#@right(sshfp)
#@unicoded
#@debug		# should usually be closest to the cmp function
#def cmp_host_sshpubkeyfp(x, y):
#	# in comes lists of ssh keys. we need to transform each one into the
#	# format as returned by freeipa. freeipa returns a tuple of strings!
#	# eg x is usually something like:
#	# (u'AB:98:62:82:C0:74:47:5E:FC:36:F7:5A:D7:8F:8E:FF (ssh-dss)',
#	# u'62:6D:8B:7B:3F:E3:EA:4C:50:4D:86:AA:BF:17:9D:8B (ssh-rsa)')
#	return x == y

@left(list)
@right(listclean)
@right(sshdsp)
@unicoded
@debug		# should usually be closest to the cmp function
def cmp_host_ipasshpubkey(x, y):
	# this is only seen when using all=True
	return x == y

@ipastr
def cmp_host_l(x, y):
	return x == y

@ipastr
def cmp_host_nshostlocation(x, y):
	return x == y

@ipastr
def cmp_host_nshardwareplatform(x, y):
	return x == y

@ipastr
def cmp_host_nsosversion(x, y):
	return x == y

@ipastr
def cmp_host_description(x, y):
	return x == y

#
#	service cmp functions
#
@left(untuple)
@unicoded
def cmp_service_primarykey(x, y):
	return x == y

@left(list)
@unicoded
def cmp_service_ipakrbauthzdata(x, y):
	# TODO: is it possible that instead of (u'NONE',) some return None ?
	return x == y

#
#	user cmp functions
#
@left(untuple)
@unicoded
def cmp_user_primarykey(x, y):
	return x == y

@ipastr
def cmp_user_givenname(x, y):
	return x == y

@ipastr
def cmp_user_sn(x, y):
	return x == y

@ipastr
def cmp_user_cn(x, y):
	return x == y

@ipastr
def cmp_user_displayname(x, y):
	return x == y

@ipastr
def cmp_user_initials(x, y):
	return x == y

@ipastr
def cmp_user_krbprincipalname(x, y):
	return x == y

@ipalist
def cmp_user_mail(x, y):
	return x == y

@ipastr
def cmp_user_gecos(x, y):
	return x == y

@ipastr
def cmp_user_uidnumber(x, y):
	return x == y

@ipastr
def cmp_user_gidnumber(x, y):
	return x == y

@ipastr
def cmp_user_loginshell(x, y):
	return x == y

@ipastr
def cmp_user_homedirectory(x, y):
	return x == y

@left(list)
@right(listclean)
@right(sshdsp)
@unicoded
def cmp_user_ipasshpubkey(x, y):
	return x == y

@ipastr
def cmp_user_street(x, y):
	return x == y

@ipastr
def cmp_user_l(x, y):
	return x == y

@ipastr
def cmp_user_st(x, y):
	return x == y

@ipastr
def cmp_user_postalcode(x, y):
	return x == y

@ipalist
def cmp_user_telephonenumber(x, y):
	return x == y

@ipalist
def cmp_user_mobile(x, y):
	return x == y

@ipalist
def cmp_user_pager(x, y):
	return x == y

@ipalist
def cmp_user_facsimiletelephonenumber(x, y):
	return x == y

@ipastr
def cmp_user_title(x, y):
	return x == y

@ipastr
def cmp_user_ou(x, y):
	return x == y

@ipastr
def cmp_user_manager(x, y):
	return x == y

@ipastr
def cmp_user_carlicense(x, y):
	return x == y

#
#	initialize ipa
#
ipalib.api.bootstrap()
ipalib.api.load_plugins()
ipalib.api.finalize()
ipalib.api.Backend.xmlclient.connect()

#
#	parser to match ipa arguments
#
parser = argparse.ArgumentParser(description='ipa difference engine')

parser.add_argument('--debug', dest='debug', action='store_true', default=False)
parser.add_argument('--not', dest='n', action='store_true', default=False)

subparsers = parser.add_subparsers(dest='subparser_name')

# parent parser (contains common subparser arguments)
parent_parser = argparse.ArgumentParser(add_help=False)
parent_parser.add_argument('primarykey', action='store')	# positional arg

# NOTE: this is a mapping with dest being the --raw key to look for the data in
# NOTE: this --raw key to dest values can be seen by looking in the ipa API.txt

#
#	'host' parser
#
parser_host = subparsers.add_parser('host', parents=[parent_parser])
parser_host.add_argument('--macaddress', dest='macaddress', action='append')	# list
# this is actually part of DNS, ignore it...
#parser_host.add_argument('--ip-address', dest='ip?', action='store')
#parser_host.add_argument('--sshpubkey', dest='sshpubkeyfp', action='append')
parser_host.add_argument('--sshpubkey', dest='ipasshpubkey', action='append')
parser_host.add_argument('--locality', dest='l', action='store')
parser_host.add_argument('--location', dest='nshostlocation', action='store')
parser_host.add_argument('--platform', dest='nshardwareplatform', action='store')
parser_host.add_argument('--os', dest='nsosversion', action='store')
parser_host.add_argument('--desc', dest='description', action='store')

#
#	'service' parser
#
parser_service = subparsers.add_parser('service', parents=[parent_parser])
parser_service.add_argument('--pac-type', dest='ipakrbauthzdata', action='append')

#
#	'user' parser
#
parser_user = subparsers.add_parser('user', parents=[parent_parser])
parser_user.add_argument('--first', dest='givenname', action='store')
parser_user.add_argument('--last', dest='sn', action='store')
parser_user.add_argument('--cn', dest='cn', action='store')
parser_user.add_argument('--displayname', dest='displayname', action='store')
parser_user.add_argument('--initials', dest='initials', action='store')
parser_user.add_argument('--principal', dest='krbprincipalname', action='store')
parser_user.add_argument('--email', dest='mail', action='append')
parser_user.add_argument('--gecos', dest='gecos', action='store')
parser_user.add_argument('--uid', dest='uidnumber', action='store')
parser_user.add_argument('--gidnumber', dest='gidnumber', action='store')
parser_user.add_argument('--shell', dest='loginshell', action='store')
parser_user.add_argument('--homedir', dest='homedirectory', action='store')
parser_user.add_argument('--sshpubkey', dest='ipasshpubkey', action='append')
parser_user.add_argument('--street', dest='street', action='store')
parser_user.add_argument('--city', dest='l', action='store')
parser_user.add_argument('--state', dest='st', action='store')
parser_user.add_argument('--postalcode', dest='postalcode', action='store')
parser_user.add_argument('--phone', dest='telephonenumber', action='append')
parser_user.add_argument('--mobile', dest='mobile', action='append')
parser_user.add_argument('--pager', dest='pager', action='append')
parser_user.add_argument('--fax', dest='facsimiletelephonenumber', action='append')
parser_user.add_argument('--title', dest='title', action='store')
parser_user.add_argument('--orgunit', dest='ou', action='store')
parser_user.add_argument('--manager', dest='manager', action='store')
parser_user.add_argument('--carlicense', dest='carlicense', action='store')

args = parser.parse_args()

# TODO: the process dictionaries could probably be generated by argparse data
if args.subparser_name == 'host':
	process = {
		'macaddress': cmp_host_macaddress,
		#'sshpubkeyfp': cmp_host_sshpubkeyfp,
		'ipasshpubkey': cmp_host_ipasshpubkey,	# only seen with --all
		'l': cmp_host_l,
		'nshostlocation': cmp_host_nshostlocation,
		'nshardwareplatform': cmp_host_nshardwareplatform,
		'nsosversion': cmp_host_nsosversion,
		'description': cmp_host_description,
	}

elif args.subparser_name == 'service':
	process = {
		'ipakrbauthzdata': cmp_service_ipakrbauthzdata,
	}

elif args.subparser_name == 'user':
	process = {
		'givenname': cmp_user_givenname,
		'sn': cmp_user_sn,
		'cn': cmp_user_cn,
		'displayname': cmp_user_displayname,
		'initials': cmp_user_initials,
		'krbprincipalname': cmp_user_krbprincipalname,
		'mail': cmp_user_mail,
		'gecos': cmp_user_gecos,
		'uidnumber': cmp_user_uidnumber,
		'gidnumber': cmp_user_gidnumber,
		'loginshell': cmp_user_loginshell,
		'homedirectory': cmp_user_homedirectory,
		'ipasshpubkey': cmp_user_ipasshpubkey,
		'street': cmp_user_street,
		'l': cmp_user_l,
		'st': cmp_user_st,
		'postalcode': cmp_user_postalcode,
		'telephonenumber': cmp_user_telephonenumber,
		'mobile': cmp_user_mobile,
		'pager': cmp_user_pager,
		'facsimiletelephonenumber': cmp_user_facsimiletelephonenumber,
		'title': cmp_user_title,
		'ou': cmp_user_ou,
		'manager': cmp_user_manager,
		'carlicense': cmp_user_carlicense,
	}

try:
	#output = ipalib.api.Command.host_show(fqdn=unicode(args.hostname))
	if args.subparser_name == 'host':
		output = ipalib.api.Command.host_show(unicode(args.primarykey), all=True)
	elif args.subparser_name == 'service':
		output = ipalib.api.Command.service_show(unicode(args.primarykey), all=True)
	elif args.subparser_name == 'user':
		output = ipalib.api.Command.user_show(unicode(args.primarykey), all=True)

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

if args.subparser_name == 'host':
	compare = cmp_host_primarykey
	pk = result.get('fqdn', '')
elif args.subparser_name == 'service':
	compare = cmp_service_primarykey
	pk = result.get('krbprincipalname', '')
elif args.subparser_name == 'user':
	compare = cmp_user_primarykey
	pk = result.get('uid', '')

# the pk gets untuples by the @left(untuple) compare decorators
assert compare(pk, args.primarykey), 'Primary key does not match!'

#
#	loop through all the keys to validate
#
for i in process.keys():

	a = result.get(i, None)			# value from ipa (in unicode)
	b = getattr(args, i)			# value from command line arg

	compare = process.get(i, cmp_default)	# cmp function
	compare = get(compare, cmp_default)	# default None

	# NOTE: the a value (left) must always be the ipa data
	# the b value (right) must correspond to the arg value
	watch = (b is not None)	# values of None are unmanaged
	if watch and not(compare(a, b)):	# run the cmp!
		if args.debug:
			# TODO: compare could return the post decorated x and y
			# which we're actually comparing and print them here...
			# this would give us more information about the unmatch
			print >> sys.stderr, ('Unmatched on %s between %s and %s' % (i, a, b))
		if args.n:
			sys.exit(0)
		else:
			sys.exit(1)

if args.n:
	sys.exit(1)
else:
	sys.exit(0)	# everything matches

