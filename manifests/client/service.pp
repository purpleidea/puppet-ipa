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

# FIXME: if this resource is removed, how do we revoke the key from the keytab?
# FIXME: it seems that after a kdestroy/kinit cycle happens, it is then revoked
# FIXME: a freeipa expert should verify and confirm that it's safe/ok this way!
# this runs ipa-getkeytab magic, to setup the keytab, for a service on a client
define ipa::client::service(
	$service = '',		# nfs, HTTP, ldap
	$host = '',		# should match $name of ipa::client::host
	$domain = '',		# must be the empty string by default
	$realm = '',
	$principal = '',	# after all that, you can override principal...
	$server = '',		# where the client will find the ipa server...
	$keytab = '',		# defaults to /etc/krb5.keytab
	$comment = '',
	$debug = false,
	$ensure = present
) {
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# NOTE: much of the following code is almost identical to that up above
	# TODO: a better regexp magician could probably do a better job :)
	# nfs/nfs.example.com@EXAMPLE.COM
	$r = '^([a-zA-Z][a-zA-Z0-9]*)(/([a-z][a-z\.\-]*)(@([A-Z][A-Z\.\-]*)){0,1}){0,1}$'

	$a = regsubst("${name}", $r, '\1')	# service (nfs)
	$b = regsubst("${name}", $r, '\3')	# fqdn (nfs.example.com)
	$c = regsubst("${name}", $r, '\5')	# realm (EXAMPLE.COM)

	# service: first try to get value from arg, then fall back to $a (name)
	$valid_service = "${service}" ? {
		'' => "${a}",				# get from $name regexp
		default => "${service}",
	}
	if "${valid_service}" == '' {
		# NOTE: if we see this message it might be a regexp pattern bug
		fail('The $service must be specified.')
	}

	# host: first try to get value from arg, then fall back to $b
	# this is not necessarily the fqdn, but it could be. both are possible!
	$valid_host = "${host}" ? {
		'' => "${b}",				# get from $name regexp
		default => "${host}",
	}
	# this error will probably prevent a later error in $valid_domain
	if "${valid_host}" == '' {
		fail('The $host must be specified.')
	}

	# parse the fqdn from $valid_host
	$r2 = '^([a-z][a-z0-9\-]*)(\.{0,1})([a-z0-9\.\-]*)$'
	#$h = regsubst("${valid_host}", $r2, '\1')	# hostname
	$d = regsubst("${valid_host}", $r2, '\3')	# domain

	$valid_domain = delete("${valid_host}", '.') ? {
		"${valid_host}" => "${domain}" ? {	# no dots, not an fqdn!
			'' => "${ipa::client::domain}" ? {	# NOTE: client!
				'' => "${::domain}",	# default to global val
				default => "${ipa::client::domain}",	# main!
			},
			default => "${domain}",
		},
		default => "${domain}" ? {		# dots, it's an fqdn...
			'' => "${d}",	# okay, used parsed value, it had dots!
			"${d}" => "${domain}",		# they match, okay phew
			default => '',	# no match, set '' to trigger an error!
		},
	}

	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('The $domain must be specified.')
	}

	$valid_fqdn = delete("${valid_host}", '.') ? {	# does it have any dots
		"${valid_host}" => "${valid_host}.${valid_domain}",
		default => "${valid_host}",		# it had dot(s) present
	}

	$valid_realm = "${realm}" ? {
		'' => "${c}" ? {			# get from $name regexp
			'' => upcase($valid_domain),	# a backup plan default
			default => "${c}",		# got from $name regexp
		},
		default => "${realm}",
	}

	# sanity checking, this should probably not happen
	if "${valid_realm}" == '' {
		fail('The $realm must be specified.')
	}

	$valid_server = "${server}" ? {
		'' => "${ipa::client::valid_server}",
		default => "${server}",
	}

	# sanity checking, this should probably not happen
	if "${valid_server}" == '' {
		fail('The $server must be specified.')
	}

	$valid_principal = "${principal}" ? {
		'' => "${valid_service}/${valid_fqdn}@${valid_realm}",
		default => "${principal}",		# just do what you want
	}

	$valid_keytab = "${keytab}" ? {			# TODO: validate
		'' => '/etc/krb5.keytab',
		default => "${keytab}",
	}

	if $debug {
		notify { "ipa-client-service-${name}":
			message => "Service: '${name}', principal: '${valid_principal}'",
		}
	}

	# TODO: it would be great to put this kinit code into a single class to
	# be used by each service, but it's not easily possible if puppet stops
	# us from declaring identical class objects when they're seen as dupes!
	# there is ensure_resource, but it's a hack and class might not work...
	# NOTE: i added a lifetime of 1 hour... no sense needing any longer
	$rr = "krbtgt/${valid_realm}@${valid_realm}"
	$tl = '900'	# 60*15 => 15 minutes
	$admin = "host/${valid_fqdn}@${valid_realm}"	# use this principal...
	exec { "/usr/bin/kinit -k -t '${valid_keytab}' ${admin} -l 1h":
		logoutput => on_failure,
		#unless => "/usr/bin/klist -s",	# is there a credential cache
		# NOTE: we need to check if the ticket has at least a certain
		# amount of time left. if not, it could expire mid execution!
		# this should definitely get patched, but in the meantime, we
		# check that the current time is greater than the valid start
		# time (in seconds) and that we have within $tl seconds left!
		unless => "/usr/bin/klist -s && /usr/bin/test \$(( `/bin/date +%s` - `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$1\" \"\$2}' | /bin/date --file=- +%s` )) -gt 0 && /usr/bin/test \$(( `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$3\" \"\$4}' | /bin/date --file=- +%s` - `/bin/date +%s` )) -gt ${tl}",
		require => [
			Package['ipa-client'],
			Exec['ipa-install'],
			Ipa::Client::Host["${valid_host}"],
		],
		alias => "ipa-client-service-kinit-${name}",
	}

	$args01 = "--server='${valid_server}'"	# contact this KDC server (ipa)
	$args02 = "--principal='${valid_principal}'"	# the service principal
	$args03 = "--keytab='${valid_keytab}'"

	$arglist = ["${args01}", "${args02}", "${args03}"]
	$args = join(delete($arglist, ''), ' ')

	$kvno_bool = "/usr/bin/kvno -q '${valid_principal}'"
	exec { "/usr/sbin/ipa-getkeytab ${args}":
		logoutput => on_failure,
			# check that the KDC has a valid ticket available there
			# check that the ticket version no. matches our keytab!
		unless => "${kvno_bool} && /usr/bin/klist -k -t '${valid_keytab}' | /bin/awk '{print \$4\": kvno = \"\$1}' | /bin/sort | /usr/bin/uniq | /bin/grep -F '${valid_principal}' | /bin/grep -qxF \"`/usr/bin/kvno '${valid_principal}'`\"",
		require => [
			# these deps are done in the kinit
			#Package['ipa-client'],
			#Exec['ipa-install'],
			#Ipa::Client::Host["${valid_host}"],
			Exec["ipa-client-service-kinit-${name}"],
		],
		#alias => "ipa-getkeytab-${name}",
	}
}

# vim: ts=8
