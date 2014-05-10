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
# NOTE: this is called by ipa::client internally and shouldn't be used manually

define ipa::server::host::sshpubkeys(	# $name matches ipa::server::host $name
	$rsa = '',
	$dsa = ''
) {
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# FIXME: if i really cared, i would just have one argument, an array of
	# keys, and i would loop through them creating each file... tempting...
	if "${rsa}" != '' {
		file { "${vardir}/hosts/sshpubkeys/${name}/rsa.pub":
			content => "${rsa}\n",
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			# this before is essential, and it implies that it will also go
			# before the "ipa-server-host-mod-${name}" exec, because of the
			# relationship between those two types. mod might not always be
			# present (if $modify is false) so don't directly reference it.
			before => Exec["ipa-server-host-add-${name}"],
			require => File["${vardir}/hosts/sshpubkeys/${name}/"],
			ensure => present,
		}
	}
	if "${dsa}" != '' {
		file { "${vardir}/hosts/sshpubkeys/${name}/dsa.pub":
			content => "${dsa}\n",
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			# this before is essential, and it implies that it will also go
			# before the "ipa-server-host-mod-${name}" exec, because of the
			# relationship between those two types. mod might not always be
			# present (if $modify is false) so don't directly reference it.
			before => Exec["ipa-server-host-add-${name}"],
			require => File["${vardir}/hosts/sshpubkeys/${name}/"],
			ensure => present,
		}
	}
}

# vim: ts=8
