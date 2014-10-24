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

define ipa::server::service(
	$service = '',		# nfs, HTTP, ldap
	$host = '',		# should match $name of ipa::server::host
	$domain = '',		# must be the empty string by default
	$realm = '',
	$principal = '',	# after all that, you can override principal...
	$server = '',		# where the client will find the ipa server...

	# args
	$pactype = [],		# bad values are silently discarded, [] is NONE

	#$hosts = [],		# TODO: add hosts managed by support

	# special parameters...
	$watch = true,	# manage all changes to this resource, reverting others
	$modify = true,	# modify this resource on puppet changes or not ?
	$comment = '',
	$ensure = present	# TODO
) {
	include ipa::server
	include ipa::server::service::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$dns = $ipa::server::dns			# boolean from main obj

	# TODO: a better regexp magician could probably do a better job :)
	# nfs/nfs.example.com@EXAMPLE.COM
	$r = '^([a-zA-Z][a-zA-Z0-9]*)(/([a-z0-9][a-z0-9\.\-]*)(@([A-Z][A-Z\.\-]*)){0,1}){0,1}$'

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
			'' => "${ipa::server::domain}" ? {	# NOTE: server!
				'' => "${::domain}",	# default to global val
				default => "${ipa::server::domain}",	# main!
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
		'' => "${::hostname}.${::domain}",
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

	if $watch and (! $modify) {
		fail('You must be able to $modify to be able to $watch.')
	}

	$pactype_valid = ['MS-PAC', 'PAD']	# or 'NONE'
	$pactype_array = type($pactype) ? {
		'array' => $pactype,
		'string' => ["${pactype}"],
		default => [],			# will become 'NONE'
	}
	$valid_pactype = split(inline_template('<%= ((pactype_array.delete_if {|x| not pactype_valid.include?(x)}.length == 0) ? ["NONE"] : pactype_array.delete_if {|x| not pactype_valid.include?(x)}).join("#") %>'), '#')

	$args01 = sprintf("--pac-type='%s'", join($valid_pactype, ','))

	$arglist = ["${args01}"]	# future expansion available :)
	$args = join(delete($arglist, ''), ' ')

	# switch the slashes for a file name friendly character
	$valid_principal_file = regsubst("${valid_principal}", '/', '-', 'G')
	file { "${vardir}/services/${valid_principal_file}.service":
		content => "${valid_principal}\n${args}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/services/"],
		ensure => present,
	}

	$exists = "/usr/bin/ipa service-show '${valid_principal}' > /dev/null 2>&1"
	$force = "${args}" ? {			# if args is empty
		'' => '--force',		# we have no args!
		default => "${args} --force",	# pixel perfect...
	}
	$fargs = $dns ? {			# without the dns,
		true => "${force}",		# we don't need to
		default => "${args}",		# force everything
	}
	# NOTE: this runs when no service is present...
	exec { "ipa-server-service-add-${name}":	# alias
		# this has to be here because the command string gets too long
		# for a puppet $name var and strange things start to happen...
		command => "/usr/bin/ipa service-add '${valid_principal}' ${fargs}",
		logoutput => on_failure,
		unless => "${exists}",
		require => $dns ? {
			true => [
				Exec['ipa-server-kinit'],
			],
			default => [
				Exec['ipa-dns-check'],	# avoid --force errors!
				Exec['ipa-server-kinit'],
			],
		},
	}

	# NOTE: this runs when we detect that the attributes don't match (diff)
	if $modify and ("${args}" != '') {	# if there are changes to do...
		#exec { "/usr/bin/ipa service-mod '${valid_principal}' ${args}":
		exec { "ipa-server-service-mod-${name}":
			command => "/usr/bin/ipa service-mod '${valid_principal}' ${args}",
			logoutput => on_failure,
			refreshonly => $watch ? {
				false => true,		# when not watching, we
				default => undef,	# refreshonly to change
			},
			subscribe => $watch ? {
				false => File["${vardir}/services/${valid_principal_file}.service"],
				default => undef,
			},
			onlyif => "${exists}",
			unless => $watch ? {
				false => undef,	# don't run the diff checker...
				default => "${exists} && ${vardir}/diff.py service '${valid_principal}' ${args}",
			},
			require => [
				File["${vardir}/diff.py"],
				Exec['ipa-server-kinit'],
				Exec["ipa-server-service-add-${name}"],
			],
			#alias => "ipa-server-service-mod-${name}",
		}
	}

	@@ipa::client::service { "${name}":	# this is usually the principal
		# NOTE: this should set all the client args it can safely assume
		service => "${valid_service}",
		host => "${valid_host}",	# this value is used to collect
		domain => "${valid_domain}",
		realm => "${valid_realm}",
		principal => "${valid_principal}",
		server => "${valid_server}",
		comment => "${comment}",
		ensure => $ensure,
		require => Ipa::Client::Host["${name}"],	# should match!
# TODO: Tag names should match the following regular expression: \A[a-z0-9_][a-z0-9_:\.\-]*\Z
# This tag is useless if we have name for example in format of ${service}/${fqdn}@${domain}
#		tag => "${name}",					# bonus
	}
}

# vim: ts=8
