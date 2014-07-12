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
#	ipa::server::replica::firewall { $ring["${::fqdn}"]:	# all automatic
#		peer => "${::fqdn}",
#	}
define ipa::server::replica::firewall(	# to
	$peer = '',			# from (usually we run this on itself!)
	$ip = ''	# you can specify which ip address to use (if multiple)
) {

	include ipa::server::replica::firewall::base

	# NOTE: the peer vs. valid_peer names are by convention (but confusing)
	$self = "${peer}"		# from (a)
	if "${self}" != "${::fqdn}" {
		fail('Are you sure you want to run this on a different host ?')
	}
	$valid_peer = "${name}"		# to (b)

	$zone = $::ipa::server::zone				# firewall zone
	$valid_ip = "${ip}" ? {
		'' => "${::ipa_host_ip}" ? {			# smart fact...
			'' => "${::ipaddress}",			# puppet picks!
			default => "${::ipa_host_ip}",		# smart
		},
		default => "${ip}",				# user selected
	}
	if "${valid_ip}" == '' {
		fail('No valid IP exists!')
	}

	# NOTE: an exported resource here says: "i would like to connect to you"
	# this means the collector's (receiver) perspective source ip is *my* ip

	# NOTE: we need to add the $fqdn so that exported resources
	# don't conflict... I'm not sure they should anyways though

	# Directory Service: Unsecure port (389)
	@@ipa::rulewrapper { "ipa-server-replica-ldap-${name}-${::fqdn}":
		action => 'LDAP/ACCEPT',
		source => "${zone}",	# override this on collect...
		source_ips => ["${valid_ip}"],	# i am the source !
		dest => '$FW',
		#proto => 'tcp',
		#port => '',	# comma separated string or list
		comment => "Allow incoming tcp:389 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",	# used for collection
		ensure => present,
	}

	# Directory Service: Secure port (636)
	@@ipa::rulewrapper { "ipa-server-replica-ldaps-${name}-${::fqdn}":
		action => 'LDAPS/ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		comment => "Allow incoming tcp:636 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# TODO: this should work in a future version of shorewall...
	# Kerberos KDC: TCP (88) / Kerberos KDC: UDP (88)
	#@@ipa::rulewrapper { "ipa-server-replica-kerberos-${name}-${::fqdn}":
	#	action => 'Kerberos/ACCEPT',
	#	source => "${zone}",
	#	source_ips => ["${valid_ip}"],
	#	dest => '$FW',
	#	comment => "Allow incoming tcp/udp:88 from ${::fqdn}.",
	#	tag => 'ipa-server-replica',
	#	match => "${name}",
	#	ensure => present,
	#}

	# TODO: until the Kerberos macro exists in shorewall, we do it manually
	# Kerberos KDC: TCP (88)
	@@ipa::rulewrapper { "ipa-server-replica-kerberos-tcp-${name}-${::fqdn}":
		action => 'ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		proto => 'tcp',
		port => ['88'],
		comment => "Allow incoming tcp:88 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# Kerberos KDC: UDP (88)
	@@ipa::rulewrapper { "ipa-server-replica-kerberos-udp-${name}-${::fqdn}":
		action => 'ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		proto => 'udp',
		port => ['88'],
		comment => "Allow incoming udp:88 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# TODO: create a kpasswd macro, or use the 'macro.ActiveDir' one...
	# Kerberos Kpasswd: TCP (464)
	@@ipa::rulewrapper { "ipa-server-replica-kpasswd-tcp-${name}-${::fqdn}":
		action => 'ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		proto => 'tcp',
		port => ['464'],
		comment => "Allow incoming tcp:464 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# Kerberos Kpasswd: UDP (464)
	@@ipa::rulewrapper { "ipa-server-replica-kpasswd-udp-${name}-${::fqdn}":
		action => 'ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		proto => 'udp',
		port => ['464'],
		comment => "Allow incoming udp:464 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# HTTP Server: Unsecure port (80)
	@@ipa::rulewrapper { "ipa-server-replica-http-${name}-${::fqdn}":
		action => 'HTTP/ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		comment => "Allow incoming tcp:80 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# HTTP Server: Secure port (443)
	@@ipa::rulewrapper { "ipa-server-replica-https-${name}-${::fqdn}":
		action => 'HTTPS/ACCEPT',
		source => "${zone}",
		source_ips => ["${valid_ip}"],
		dest => '$FW',
		comment => "Allow incoming tcp:443 from ${::fqdn}.",
		tag => 'ipa-server-replica',
		match => "${name}",
		ensure => present,
	}

	# FIXME: are all the necessary ports for ipa replication include here ?
}

# vim: ts=8
