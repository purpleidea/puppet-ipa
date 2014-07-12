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

class ipa::server::replica::firewall::base {
	include ipa::server

	$zone = $::ipa::server::zone				# firewall zone
	$shorewall = $::ipa::server::shorewall			# enable fw...?

	# open the firewall so that replicas can connect to what they will need
	Ipa::Rulewrapper <<| tag == 'ipa-server-replica' and match == "${::fqdn}" |>> {
	#Shorewall::Rule <<| tag == 'ipa-server-replica' and match == "${::fqdn}" |>> {
		source => "${zone}",	# use our source zone
		# TODO: this below before is basically untested for usefulness!
		before => Exec['ipa-install'],		# open bi-directional fw first!
		# TODO: the below require is basically untested for usefulness!
		require => Exec['ipa-clean-peers'],	# let the peers clean up first!
		ensure => $shorewall ? {
			absent => absent,
			'absent' => absent,
			present => present,
			'present' => present,
			default => present,
		},
	}
}

# vim: ts=8
