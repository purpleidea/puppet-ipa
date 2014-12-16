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

class ipa::server::user::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# by default, the following users get installed with freeipa:
	# admin
	# since we don't want to purge them, we need to exclude them...
	$user_always_ignore = ['admin']
	$user_excludes = $ipa::server::user_excludes
	$valid_user_excludes = type($user_excludes) ? {
		'string' => [$user_excludes],
		'array' => $user_excludes,
		'boolean' => $user_excludes ? {
			# TODO: there's probably a better user match expression
			# this is an expression to prevent all user deletion...
			#true => ['^[a-zA-Z0-9]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_user_excludes) != 'array' {
		fail('The $user_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/users/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-users'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'users'
	$ls_cmd = '/usr/bin/ipa user-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep -i "^uid:" | /bin/cut -b 5-'	# show ipa users
	$rm_cmd = '/usr/bin/ipa user-del '	# delete ipa users
	$fs_chr = ' '
	$suffix = '.user'
	$regexp = $valid_user_excludes
	$ignore = $user_always_ignore

	# build the clean script
	file { "${vardir}/clean-users.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-users.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-users.sh"],
		],
		alias => 'ipa-clean-users',
	}

	file { "${vardir}/users/passwords/":	# for storing random passwords
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/users/"],
	}
}

# vim: ts=8
