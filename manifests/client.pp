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

class ipa::client(
	$name = '',			# what define was called with...
	$hostname = $::hostname,
	$domain = $::domain,
	$realm = '',			# defaults to upcase($domain)
	$server = '',			# ipa server
	$password = '',			# seemingly no password restrictions...

	$admin = false,			# should we get admin tools installed ?
	$ssh = false,
	$sshd = false,
	$ntp = false,
	$ntp_server = '',

	$shorewall = false,		# TODO ?
	$zone = 'net',
	$allow = 'all',
	$debug = false,
	$ensure = present		# TODO: support uninstall with 'absent'
) {
	include ipa::params
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$valid_domain = downcase($domain)	# TODO: validate ?
	$valid_realm = $realm ? {
		'' => upcase($valid_domain),
		default => upcase($realm),
	}

	$valid_server = "${server}" ? {
		'' => "ipa.${valid_domain}",	# default if unspecified...
		default => "${server}",
	}

	if "${hostname}" != delete("${hostname}", '.') {
		fail('The $hostname value must not contain periods. It is not the FQDN.')
	}

	if "${valid_domain}" == '' {
		fail('A $domain value is required.')
	}

	$valid_name = "${name}" ? {
		'' => "${hostname}.${domain}",	# defaults to fqdn if empty...
		default => "${name}",		# this could be fqdn or not...
	}

	if $debug {
		# just used for debugging
		$valid_fqdn = "${hostname}.${valid_domain}"
		$valid_principal = "host/${valid_fqdn}@${valid_realm}"
		notify { "ipa-client-host-${name}":
			message => "Host: '${name}', principal: '${valid_principal}'",
		}
	}

	package { "${::ipa::params::package_ipa_client}":
		ensure => present,
	}

	# an administrator machine requires the ipa-admintools package as well:
	package { "${::ipa::params::package_ipa_admintools}":
		ensure => $admin ? {
			true => present,
			false => absent,
		},
		require => Package["${::ipa::params::package_ipa_client}"],
	}

	# store the passwords in text files instead of having them on cmd line!
	# TODO: storing plain text passwords is not good, so what should we do?
	file { "${vardir}/password":
		content => "${password}\n",		# temporarily secret...
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		require => File["${vardir}/"],
		ensure => present,
	}
	# these are the arguments to ipa-server-install in the prompted order
	$args01 = "--hostname='${hostname}.${valid_domain}'"
	$args02 = "--domain='${valid_domain}'"
	$args03 = "--realm='${valid_realm}'"
	$args04 = "--server='${valid_server}'"
	#$args05 = "--password='${password}'"	# password to join IPA realm
	$args05 = "--password=`/bin/cat '${vardir}/password'`"

	$args06 = $ssh ? {
		true => '',
		default => '--no-ssh',
	}

	$args07 = $sshd ? {
		true => '',
		default => '--no-sshd',
	}

	$args08 = $ntp ? {
		true => '',
		default => '--no-ntp',
	}

	$args09 = $ntp_server ? {
		'' => '',
		default => $ntp ? {
			true => "--ntp-server=${ntp_server}",
			default => '',
		},
	}

	$arglist = ["${args01}", "${args02}", "${args03}", "${args04}", "${args05}", "${args06}", "${args07}", "${args08}", "${args09}"]
	#$args = inline_template('<%= arglist.delete_if {|x| x.empty? }.join(" ") %>')
	$args = join(delete($arglist, ''), ' ')

	# this makes the install wait if a valid password hasn't been exported!
	# this happens because it takes a second run of the ipa puppet after it
	# has configured the host, because, on this second puppet run, the fact
	# will finally now see the password, and it can be properly exported...
	$has_auth = "${password}" ? {
		'' => 'false',
		default => 'true',
	}
	$onlyif = "/usr/bin/test '${has_auth}' = 'true'"
	$unless = "/usr/bin/python -c 'import sys,ipapython.sysrestore; sys.exit(0 if ipapython.sysrestore.FileStore(\"/var/lib/ipa-client/sysrestore\").has_files() else 1)'"
	exec { "/usr/sbin/ipa-client-install ${args} --unattended":
		logoutput => on_failure,
		onlyif => "${onlyif}",	# needs a password or authentication...
		unless => "${unless}",	# can't install if already installed...
		require => [
			Package["${::ipa::params::package_ipa_client}"],
			File["${vardir}/password"],
		],
		alias => 'ipa-install',	# same alias as server to prevent both!
	}

	# this file is a tag that lets nfs know that the ipa host is now ready!
	file { "${vardir}/ipa_client_installed":
		content => "true\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		require => [
			File["${vardir}/"],
			Exec['ipa-install'],
		],
		ensure => present,
	}

	# normally when this resource is created by collection, the password is
	# exported which allows the client to boostrap itself without a ticket.
	# once this host gets built, the password gets "used" on the ipa server
	# which causes it to show 'has_password: False', which would cause that
	# password to get regenerated, however this exported resource will stop
	# that from happening when it gets collected on the server as a tag. if
	# this client dissapears, then, the exported resource should eventually
	# get removed when a client runs puppet, which will cause a new pass to
	# be created for the new ipa client install if we happen to want one...
	#if "${password}" == '' {
	@@ipa::server::host::pwtag { "${valid_name}":
		tag => "${valid_name}",	# collection by name is buggy, use tag!
	}
	#}

	# send ssh keys back so that server updates its database if they change
	@@ipa::server::host::sshpubkeys { "${valid_name}":
		# FIXME: redo this resource so that we specify an array instead
		# this is needed in case we decide to export other keys perhaps
		# it's more important because static things aren't very elegant
		rsa => "${::sshrsakey}",	# built in fact
		dsa => "${::sshdsakey}",	# built in fact
		tag => "${valid_name}",		# same name as ipa::server::host
	}
}

# vim: ts=8
