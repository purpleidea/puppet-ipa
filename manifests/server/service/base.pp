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

class ipa::server::service::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# by default, the following services get installed with freeipa:
	# DNS/ipa.example.com@EXAMPLE.COM
	# dogtagldap/ipa.example.com@EXAMPLE.COM
	# HTTP/ipa.example.com@EXAMPLE.COM
	# ldap/ipa.example.com@EXAMPLE.COM
	# since we don't want to purge them, we need to exclude them...
	$prefix = ['DNS', 'dogtagldap', 'HTTP', 'ldap']
	$valid_hostname = $ipa::server::valid_hostname
	$valid_domain = $ipa::server::valid_domain
	$valid_realm = $ipa::server::valid_realm
	$append = "/${valid_hostname}.${valid_domain}@${valid_realm}"
	$service_always_ignore = suffix($prefix, $append)

	$service_excludes = $ipa::server::service_excludes
	$valid_service_excludes = type($service_excludes) ? {
		'string' => [$service_excludes],
		'array' => $service_excludes,
		'boolean' => $service_excludes ? {
			# TODO: there's probably a better fqdn match expression
			# this is an expression to prevent all fqdn deletion...
			#true => ['^[a-zA-Z0-9\.\-]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]-.]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_service_excludes) != 'array' {
		fail('The $service_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/services/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-services'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'services'
	$ls_cmd = '/usr/bin/ipa service-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep -i "^krbprincipalname:" | /bin/cut -b 18-'	# show ipa services
	$rm_cmd = '/usr/bin/ipa service-del '	# delete ipa services
	$fs_chr = ' '
	$suffix = '.service'
	$regexp = $valid_service_excludes
	$ignore = $service_always_ignore

	# build the clean script
	file { "${vardir}/clean-services.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-services.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-services.sh"],
		],
		alias => 'ipa-clean-services',
	}
}

# vim: ts=8
