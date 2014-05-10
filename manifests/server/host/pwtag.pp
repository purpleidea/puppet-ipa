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

# NOTE: this should only be used by a freeipa client and as an exported resource
define ipa::server::host::pwtag() {
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# the existence of this file means that an ipa client has exported it,
	# and that the ipa server collected it and it means that a provisioned
	# ipa client host is notifying the server that a new one time password
	# does not need to be generated at this time. to reprovision the host,
	# you must erase the exported resource that is sending this file here,
	# or rather, in doing so, the ipa server will generate a new password!
	file { "${vardir}/hosts/passwords/${name}.pwtag":
		content => "# This is a password tag for: ${name}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		before => Exec["ipa-host-verify-password-exists-${name}"],
		require => File["${vardir}/hosts/passwords/"],
		ensure => present,
	}
}

# vim: ts=8
