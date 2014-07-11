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

# NOTE: this has to be a singleton (eg: class) because we can only install one!
# NOTE: topology connections and peering information can be non-singleton types TODO
class ipa::server::replica::install(
	$peers = {}
) {

	include ipa::server::replica::install::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# process possible replica masters that are available...
	$replica_fqdns_fact = "${::ipa_replica_prepared_fqdns}"	# fact!
	$replica_fqdns = split($replica_fqdns_fact, ',')	# list!

	# peering is always bidirectional for now :)
	# $peers is a hash of fqdn1 => fqdn2 pairs...

	#if has_key($peers, "${::fqdn}") and member($replica_fqdns, $peers["${::fqdn}"]) {
	#	$valid_fqdn = $peers["${::fqdn}"]
	if has_key($peers, "${::fqdn}") {
		$intersection = intersection($replica_fqdns, $peers["${::fqdn}"])
		# NOTE use empty() because 'if []' returns true!
		if empty($intersection) {
			$valid_fqdn = ''
		} else {
			# pick the first in the list if there is more than one!
			$valid_fqdn = pick($intersection, '')	# first
		}
	} else {
		$valid_fqdn = ''
	}

	if "${ipa_server_installed}" != 'true' {
		if "${valid_fqdn}" == '' {
			warning("The requested peer: '${valid_fqdn}', isn't ready yet.")
		} else {
			info("The requested peer is: '${valid_fqdn}'.")
		}
	}

	$filename = "replica-info-${valid_fqdn}.gpg"
	$filefrom = "replica-info-${::fqdn}.gpg"	# name it with our fqdn
	$valid_file = "${vardir}/replica/install/${filename}"
	$valid_from = "${vardir}/replica/prepare/${filefrom}"

	# send to all prepared hosts, so the keys don't flip flop if vip moves!
	ssh::send { $replica_fqdns:	# fqdn of where i got this from...

	}

	# TODO: tag can be used as grouping
	# NOTE: this could pull down multiple files...
	# NOTE: this also matches against the file parameter from the exporting
	# side. we do this so that we only pull in what is intended for us, and
	# as a result, this avoids real duplicate resource conflicts. but NOTE:
	# this currently depends on all hosts sharing the same value of $vardir
	Ssh::File::Pull <<| tag == 'ipa-replica-prepare' and file == "${valid_from}" |>> {
		path => "${vardir}/replica/install/",
		verify => false,		# rely on mtime
		pair => false,			# do it now so it happens fast!
		# tag this file so it doesn't get purged
		ensure => present,
		owner => root,
		group => nobody,
		mode => 600,			# u=rw
		backup => false,		# don't backup to filebucket
		before => Exec['ipa-install'],
		require => File["${vardir}/replica/install/"],
	}

	# this exec is purposefully very similar to the ipa-server-install exec
	# NOTE: the --admin-password is only useful for the connection check...
	exec { "/usr/sbin/ipa-replica-install --password=`/bin/cat '${vardir}/dm.password'` --admin-password=`/bin/cat '${vardir}/admin.password'` --unattended ${valid_file}":
		logoutput => on_failure,
		onlyif => [
			"/usr/bin/test '${valid_fqdn}' != ''",	# bonus safety!
			"/usr/bin/test -s ${valid_file}",
		],
		unless => "${::ipa::common::ipa_installed}",	# can't install if installed...
		timeout => 3600,	# hope it doesn't take more than 1 hour
		require => [
			File["${vardir}/"],
			Package['ipa-server'],
		],
		alias => 'ipa-install',	# same alias as server to prevent both!
	}
}

# vim: ts=8
