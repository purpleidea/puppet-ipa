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

# NOTE: all replication agreements are bi-directional for now due to FreeIPA...
# NOTE: in the future, it would be quite cool to allow uni-directional replicas
# NOTE: this type has been engineered to fit easily with the topology datatype:
#	$ring = {	# example flat topology as expressed in the std. format
#		'fqdn1': ['fqdn2', 'fqdn3'],
#		'fqdn2': ['fqdn3', 'fqdn1'],
#		'fqdn3': ['fqdn1', 'fqdn2'],
#	}
#
#	ipa::server::replica::manage { $ring["${::fqdn}"]:	# all automatic
#		peer => "${::fqdn}",
#	}
define ipa::server::replica::manage(	# to
	$peer = ''			# from
) {
	# TODO: this type could grow fancy name parsing to specify: to and from

	include ipa::server::replica::manage::base
	include ipa::common
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# NOTE: the peer vs. valid_peer names are by convention (but confusing)
	$args = "${peer}"		# from (a)
	$valid_peer = "${name}"		# to (b)

	# switch bad characters for file name friendly characters (unused atm!)
	# this could be useful if we allow peers's with $ and others in them...
	$valid_peer_file = regsubst("${valid_peer}", '\$', '-', 'G')
	file { "${vardir}/replica/manage/peers/${valid_peer_file}.peer":
		content => "${valid_peer}\n${args}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/replica/manage/peers/"],
		ensure => present,
	}

	# NOTE: this shouldn't depend on the VIP because it runs on each host...
	exec { "/usr/sbin/ipa-replica-manage connect '${peer}' '${valid_peer}'":
		logoutput => on_failure,
		onlyif => [
			"${::ipa::common::ipa_installed}",	# i am ready
			# this check is used to see if my peer is "ready" to
			# accept any ipa-replica-manage connect commands. if
			# it is, then it must mean that ipa is installed and
			# running, even though this check tool isn't exactly
			# designed for this particular type of check case...
			# NOTE: this avoids unnecessary 'ipa-replica-manage'
			# calls which would error in 3.0.0 with the message:
			# You cannot connect to a previously deleted master.
			# INFO: https://fedorahosted.org/freeipa/ticket/3105
			"/usr/sbin/ipa-replica-conncheck -R '${valid_peer}'",
		],
		unless => "/usr/sbin/ipa-replica-manage list '${peer}' | /bin/awk -F ':' '{print \$1}' | /bin/grep -qxF '${valid_peer}'",
		timeout => 900,		# hope it doesn't take more than 15 min
		before => Exec['ipa-clean-peers'],	# try to connect first!
		require => [
			Exec['ipa-install'],		# show for readability!
			Exec['ipa-server-kinit'],	# needs auth to work...
		],
		# NOTE: these two aliases can be used to prevent reverse dupes!
		# NOTE: remove these if FreeIPA ever supports unidirectionality
		alias => [
			"${peer} -> ${valid_peer}",
			"${valid_peer} -> ${peer}",
		],
	}
}

# vim: ts=8
