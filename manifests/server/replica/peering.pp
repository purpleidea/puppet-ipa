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

class ipa::server::replica::peering(
	# NOTE: these are *time* based uuid's, eg as generated with: uuidgen -t
	$uuid = '',	# if empty, puppet will attempt to use the uuidgen fact
) {

	include ipa::server::replica::peering::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	if ("${uuid}" != '') and (! ("${uuid}" =~ /^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$/)) {
		fail("The chosen UUID: '${uuid}' is not valid.")
	}

	# if we manually *pick* a uuid, then store it too, so that it
	# sticks if we ever go back to using automatic uuids. this is
	# useful if a user wants to initially import uuids by picking
	# them manually, and then letting puppet take over afterwards
	file { "${vardir}/replica/peering/uuid":
		# this file object needs to always exist to avoid us purging...
		content => "${uuid}" ? {
			'' => undef,
			default => "${uuid}\n",
		},
		owner => root,
		group => nobody,
		mode => 600,	# might as well...
		ensure => present,
		require => File["${vardir}/replica/peering/"],
	}

	$valid_uuid = "${uuid}" ? {
		# fact from data generated in: ${vardir}/replica/peering/uuid
		'' => "${::ipa_server_replica_uuid}",
		default => "${uuid}",
	}

	@@file { "${vardir}/replica/peering/peer_${::fqdn}":
		content => "${valid_uuid}\n",
		tag => 'ipa-server-replica-peering',
		owner => root,
		group => nobody,
		mode => 600,
		ensure => present,
	}

	# collect to make facts
	File <<| tag == 'ipa-server-replica-peering' |>> {
	}
}

# vim: ts=8
