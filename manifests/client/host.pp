# FreeIPA templating module by James
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

define ipa::client::host(
	# NOTE: this should be a copy of most of the params from ipa::client
	$domain = '',
	$realm = '',
	$server = '',
	$password = '',
	$admin = false,
	$ssh = false,
	$sshd = false,
	$ntp = false,
	$ntp_server = '',
	$shorewall = false,
	$zone = 'net',
	$allow = 'all',
	$debug = false,
	$ensure = present	# TODO
) {
	# $name should be a fqdn, split it into the $hostname and $domain args!
	# NOTE: a regexp wizard could possibly write something to match better!
	#$r = '^([a-z][a-z0-9\-]*)\.([a-z0-9\.\-]*)$'
	$r = '^([a-z][a-z0-9\-]*)(\.{0,1})([a-z0-9\.\-]*)$'
	$h = regsubst("${name}", $r, '\1')
	$x = regsubst("${name}", $r, '\2')	# the dot
	$d = regsubst("${name}", $r, '\3')

	$valid_hostname = "${h}"
	$valid_domain = "${d}" ? {
		'' => "${domain}" ? {
			'' => "${::domain}",
			default => "${domain}",
		},
		default => "${d}" ? {	# we need to check this matches $domain
			"${domain}" => "${d}",		# they match, okay phew
			default => '',	# no match, set '' to trigger an error!
		},
	}
	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('A $domain inconsistency was found.')
	}

	class { '::ipa::client':
		# NOTE: this should transfer most of the params from ipa::client
		name => $name,		# often the fqdn, but necessarily
		hostname => $valid_hostname,
		domain => $valid_domain,
		realm => $realm,
		server => $server,
		password => $password,
		admin => $admin,
		ssh => $ssh,
		sshd => $sshd,
		ntp => $ntp,
		ntp_server => $ntp_server,
		shorewall => $shorewall,
		zone => $zone,
		allow => $allow,
		debug => $debug,
		ensure => $ensure,
	}
}

# vim: ts=8
