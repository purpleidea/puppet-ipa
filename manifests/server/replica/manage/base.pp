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

class ipa::server::replica::manage::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# TODO: do we need this extra nesting here, or should we use it below ?
	file { "${vardir}/replica/manage/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/replica/"],
	}

	# since we don't want to purge them, we need to exclude them...
	$peer_always_ignore = ["${::fqdn}"]	# never try and purge yourself!
	$peer_excludes = $ipa::server::peer_excludes
	$valid_peer_excludes = type($peer_excludes) ? {
		'string' => [$peer_excludes],
		'array' => $peer_excludes,
		'boolean' => $peer_excludes ? {
			# TODO: there's probably a better peer match expression
			# this is an expression to prevent all peer deletion...
			#true => ['^[a-zA-Z0-9]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_peer_excludes) != 'array' {
		fail('The $peer_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/replica/manage/peers/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-peers'],
		require => File["${vardir}/replica/manage/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'replica/manage/peers'
	$ls_cmd = "/usr/sbin/ipa-replica-manage list '${::fqdn}'"		# show ipa peers
	$rm_cmd = "/usr/sbin/ipa-replica-manage disconnect '${::fqdn}' "	# disconnect ipa peers
	$fs_chr = ':'	# remove the ':replica' suffix
	$suffix = '.peer'
	$regexp = $valid_peer_excludes
	$ignore = $peer_always_ignore

	# build the clean script
	file { "${vardir}/clean-peers.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-peers.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-peers.sh"],
		],
		alias => 'ipa-clean-peers',
	}
}

# vim: ts=8
