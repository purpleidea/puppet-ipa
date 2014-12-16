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

class ipa::server::host::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# we don't want to purge the freeipa entry, so we need to exclude it...
	$valid_hostname = $ipa::server::valid_hostname
	$valid_domain = $ipa::server::valid_domain
	$host_always_ignore = ["${valid_hostname}.${valid_domain}"]
	$host_excludes = $ipa::server::host_excludes
	$valid_host_excludes = type($host_excludes) ? {
		'string' => [$host_excludes],
		'array' => $host_excludes,
		'boolean' => $host_excludes ? {
			# TODO: there's probably a better fqdn match expression
			# this is an expression to prevent all fqdn deletion...
			#true => ['^[a-zA-Z0-9\.\-]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]-.]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_host_excludes) != 'array' {
		fail('The $host_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/hosts/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-hosts'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'hosts'
	$ls_cmd = '/usr/bin/ipa host-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep -i "^fqdn:" | /bin/cut -b 6-'	# show ipa hosts
	# TODO: i don't understand all the implications of the --updatedns arg!
	# we should probably change the dns arg based on if dns is on or not...
	$rm_cmd = $dns ? {	# delete ipa hosts
		true => '/usr/bin/ipa host-del --updatedns ',
		default => '/usr/bin/ipa host-del ',
	}
	$fs_chr = ' '
	$suffix = '.host'
	$regexp = $valid_host_excludes
	$ignore = $host_always_ignore

	# build the clean script
	file { "${vardir}/clean-hosts.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-hosts.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-hosts.sh"],
		],
		alias => 'ipa-clean-hosts',
	}

	# NOTE: it doesn't cause a problem that this dir is inside the hosts dir
	file { "${vardir}/hosts/passwords/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/hosts/"],
	}

	file { "${vardir}/hosts/sshpubkeys/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/hosts/"],
	}
}

# vim: ts=8
