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

class ipa::params(
	# packages...
	$package_ipa_server = 'ipa-server',
	$package_ipa_client = 'ipa-client',
	$package_ipa_admintools = 'ipa-admintools',
	$package_pwgen = 'pwgen',
	$package_bind = ['bind', 'bind-dyndb-ldap'],
	$package_python_argparse = 'python-argparse',

# XXX
#	# programs...
#	$program_ipa_server_install = '/usr/sbin/ipa-server-install',

# XXX
#	# services...
#	$service_XXX = 'XXX',
# XXX

# XXX
#	# external modules...
#	$include_puppet_facter = true,
# XXX

	# misc...
	$misc_XXX = 'XXX',

	# comment...
	$comment = ''
) {
	if "${comment}" == '' {
		warning('Unable to load yaml data/ directory!')
	}

# XXX
#	$valid_include_puppet_facter = $include_puppet_facter ? {
#		true => true,
#		false => false,
#		'true' => true,
#		'false' => false,
#		default => true,
#	}
#
#	if $valid_include_puppet_facter {
#		include puppet::facter
#		$factbase = "${::puppet::facter::base}"
#		$hash = {
#			'ipa_program_ipa' => $program_ipa,
#		}
#		# create a custom external fact!
#		file { "${factbase}ipa_program.yaml":
#			content => inline_template('<%= @hash.to_yaml %>'),
#			owner => root,
#			group => root,
#			mode => 644,		# u=rw,go=r
#			ensure => present,
#		}
#	}
# XXX
}

# vim: ts=8
