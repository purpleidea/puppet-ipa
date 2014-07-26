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

class ipa::server::replica::master(
) {

	include ipa::server::replica::master::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# fact from data in: ${vardir}/ipa_server_replica_master
	$valid_master = "${::ipa_server_replica_master}"

	@@file { "${vardir}/replica/master/master_${::fqdn}":
		content => "${valid_master}\n",
		tag => 'ipa-server-replica-master',
		owner => root,
		group => nobody,
		mode => 600,
		ensure => present,
	}

	# collect to make facts
	File <<| tag == 'ipa-server-replica-master' |>> {
	}
}

# vim: ts=8
