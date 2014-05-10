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

class ipa::server(
	$hostname = $::hostname,
	$domain = $::domain,
	$realm = '',			# defaults to upcase($domain)

	# TODO: how can we hide these values ?
	# FIXME: maybe we could generate these passwords locally, and then save
	# them to a file to be read by the installer and then gpg encrypted and
	# emailed to a root email and then deleted from the file! this would
	# require an admin's public pgp key which would be a cool thing to have
	# TODO: error if these passwords aren't eight chars or more
	$dm_password = '',		# eight char minimum
	$admin_password = '',		# eight char minimum

	$idstart = '16777216',		# TODO: what is sensible? i picked 2^24
	$idmax = '',
	$email_domain = '',		# defaults to domain
	$shell = true,			# defaults to /bin/sh
	$homes = true,			# defaults to /home

	# packages products to install ?
	$ntp = false,			# opposite of ipa-server-install default
	$dns = false,			# must be set at install time to be used
	$dogtag = false,

	$email = '',			# defaults to root@domain, important...

	$shorewall = false,
	$zone = 'net',
	$allow = 'all',

	# special
	# NOTE: host_excludes is matched with bash regexp matching in: [[ =~ ]]
	# if the string regexp passed contains quotes, string matching is done:
	# $string='"hostname.example.com"' vs: $regexp='hostname.example.com' !
	# obviously, each pattern in the array is tried, and any match will do.
	# invalid expressions might cause breakage! use this at your own risk!!
	# remember that you are matching against the fqdn's, which have dots...
	# a value of true, will automatically add the * character to match all.
	$host_excludes = [],		# never purge these host excludes...
	$service_excludes = [],		# never purge these service excludes...
	$user_excludes = [],		# never purge these user excludes...
	$ensure = present		# TODO: support uninstall with 'absent'
) {
	$FW = '$FW'			# make using $FW in shorewall easier...

	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$valid_hostname = "${hostname}"		# TODO: validate ?
	$valid_domain = downcase($domain)	# TODO: validate ?
	$valid_realm = $realm ? {
		'' => upcase($valid_domain),
		default => upcase($realm),
	}

	$default_email_domain = "${email_domain}" ? {
		'' => "${valid_domain}",
		default => "${email_domain}",
	}
	ipa::server::config { 'emaildomain':
		value => "${default_email_domain}",
	}

	$default_shell = type($shell) ? {
		'boolean' => $shell ? {
			false => false,		# unmanaged
			default => '/bin/sh',	# the default
		},
		default => "${shell}",
	}
	# we don't manage if value is false, otherwise it's good to go!
	if ! (type($shell) == 'boolean' and (! $shell)) {
		ipa::server::config { 'shell':
			value => "${default_shell}",
		}
	}

	# TODO: the home stuff seems to not use trailing slashes. can i add it?
	$default_homes = type($homes) ? {
		'boolean' => $homes ? {
			false => false,		# unmanaged
			default => '/home',	# the default
		},
		default => "${homes}",
	}
	if ! (type($homes) == 'boolean' and (! $homes)) {
		ipa::server::config { 'homes':
			value => "${default_homes}",	# XXX: remove trailing slash if present ?
		}
	}

	$valid_email = $email ? {
		'' => "root@${default_email_domain}",
		default => "${email}",
	}

	if "${valid_hostname}" == '' {
		fail('A $hostname value is required.')
	}

	if "${valid_domain}" == '' {
		fail('A $domain value is required.')
	}

	if $dns {
		package { ['bind', 'bind-dyndb-ldap']:
			ensure => present,
			before => Package['ipa-server'],
		}
	}

	package { 'ipa-server':
		ensure => present,
	}

	package { 'python-argparse':		# used by diff.py
		ensure => present,
	}

	file { "${vardir}/diff.py":		# used by a few child classes
		source => 'puppet:///modules/ipa/diff.py',
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => [
			Package['ipa-server'],
			Package['python-argparse'],
			File["${vardir}/"],
		],
	}

	# store the passwords in text files instead of having them on cmd line!
	# TODO: storing plain text passwords is not good, so what should we do?
	file { "${vardir}/dm.password":
		content => "${dm_password}\n",		# top top secret!
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		require => File["${vardir}/"],
		ensure => present,
	}

	file { "${vardir}/admin.password":
		content => "${admin_password}\n",	# top secret!
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		require => File["${vardir}/"],
		ensure => present,
	}

	# these are the arguments to ipa-server-install in the prompted order
	$args01 = "--hostname='${valid_hostname}.${valid_domain}'"
	$args02 = "--domain='${valid_domain}'"
	$args03 = "--realm='${valid_realm}'"
	#$args04 = "--ds-password='${dm_password}'"	# Directory Manager
	$args04 = "--ds-password=`/bin/cat '${vardir}/dm.password'`"
	#$args05 = "--admin-password='${admin_password}'"	# IPA admin
	$args05 = "--admin-password=`/bin/cat '${vardir}/admin.password'`"
	# TODO: reconcile these options with the range settings: EXAMPLE.COM_id_range
	# if that range is changed, should we watch for it and reset? yes we should if we specified one here...
	$args06 = $idstart ? {
		'' => '',
		default => "--idstart=${idstart}",
	}
	$args07 = $idmax ? {
		'' => '',
		default => "--idmax=${idmax}",
	}

	$args08 = $ntp ? {
		true => '',				# create ntp server...
		default => '--no-ntp',
	}

	$args09 = $dns ? {
		true => '--setup-dns --no-forwarders',
		default => '',
	}

	$args10 = $dns ? {
		true => "--zonemgr=${valid_email}",
		default => '',
	}

	$arglist = ["${args01}", "${args02}", "${args03}", "${args04}", "${args05}", "${args06}", "${args07}", "${args08}", "${args09}", "${args10}"]
	#$args = inline_template('<%= arglist.delete_if {|x| x.empty? }.join(" ") %>')
	$args = join(delete($arglist, ''), ' ')

	$unless = "/usr/bin/python -c 'import sys,ipaserver.install.installutils; sys.exit(0 if ipaserver.install.installutils.is_ipa_configured() else 1)'"
	exec { "/usr/sbin/ipa-server-install ${args} --unattended":
		logoutput => on_failure,
		unless => "${unless}",	# can't install if already installed...
		require => [
			Package['ipa-server'],
			File["${vardir}/dm.password"],
			File["${vardir}/admin.password"],
		],
		alias => 'ipa-install',	# same alias as client to prevent both!
	}

	# check if we changed the dns state after initial install (unsupported)
	# this is needed, because if dns was once setup, but the param is false
	# then the host resource won't use --force and we'll get errors... this
	# happens because of bug#: https://fedorahosted.org/freeipa/ticket/3726
	if ! $dns {
		exec { '/bin/false':	# fail so that we know about the change
			logoutput => on_failure,
			# thanks to 'ab' in #freeipa for help with the ipa api!
			onlyif => "/usr/bin/python -c 'import sys,ipalib;ipalib.api.bootstrap_with_global_options(context=\"puppet\");ipalib.api.finalize();(ipalib.api.Backend.ldap2.connect(ccache=ipalib.api.Backend.krb.default_ccname()) if ipalib.api.env.in_server else ipalib.api.Backend.xmlclient.connect());sys.exit(0 if ipalib.api.Command.dns_is_enabled().get(\"result\") else 1)'",
			require => Package['ipa-server'],
			alias => 'ipa-dns-check',
		}
	}

	# TODO: add management of ipa services (ipa, httpd, krb5kdc, kadmin, etc...) run: ipactl status or service ipa status for more info
	# TODO: add management (augeas?) of /etc/ipa/default.conf

	# since we're on the kdc, we can use our root access to get a ticket...
	# < me> kaduk_: [...] is this an evil hack? [...]
	# < kaduk_> [...] It's not really a hack, but things running on the KDC
	#           are always a bit special.
	#exec { "/bin/cat '${vardir}/admin.password' | /usr/bin/kinit admin":
	# NOTE: i added a lifetime of 1 hour... no sense needing any longer
	$rr = "krbtgt/${valid_realm}@${valid_realm}"
	$tl = '900'	# 60*15 => 15 minutes
	exec { "/usr/bin/kinit -k -t KDB: admin -l 1h":	# thanks to: kaduk_
		logoutput => on_failure,
		#unless => "/usr/bin/klist -s",	# is there a credential cache
		# NOTE: we need to check if the ticket has at least a certain
		# amount of time left. if not, it could expire mid execution!
		# this should definitely get patched, but in the meantime, we
		# check that the current time is greater than the valid start
		# time (in seconds) and that we have within $tl seconds left!
		unless => "/usr/bin/klist -s && /usr/bin/test \$(( `/bin/date +%s` - `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$1\" \"\$2}' | /bin/date --file=- +%s` )) -gt 0 && /usr/bin/test \$(( `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$3\" \"\$4}' | /bin/date --file=- +%s` - `/bin/date +%s` )) -gt ${tl}",
		require => [
			Exec['ipa-install'],
			#File["${vardir}/admin.password"],
		],
		alias => 'ipa-server-kinit',
	}

	# FIXME: consider allowing only certain ip's to the ipa server
	# TODO: we could open ports per host when added with ipa::server::host
	if $shorewall {
		if $allow == 'all' or "${allow}" == '' {
			$net = "${zone}"
		} else {
			$net = is_array($allow) ? {
				true => sprintf("${zone}:%s", join($allow, ',')),
				default => "${zone}:${allow}",
			}
		}
		####################################################################
		#ACTION      SOURCE DEST                PROTO DEST  SOURCE  ORIGINAL
		#                                             PORT  PORT(S) DEST
		shorewall::rule { 'http': rule => "
		HTTP/ACCEPT  ${net}    $FW
		", comment => 'Allow HTTP for webui'}

		shorewall::rule { 'https': rule => "
		HTTPS/ACCEPT  ${net}    $FW
		", comment => 'Allow HTTPS for webui'}

		shorewall::rule { 'ldap': rule => "
		LDAP/ACCEPT  ${net}    $FW
		", comment => 'Allow LDAP for 389 server on tcp port 389.'}

		shorewall::rule { 'ldaps': rule => "
		LDAPS/ACCEPT  ${net}    $FW
		", comment => 'Allow LDAPS for 389 server on tcp port 636.'}

		shorewall::rule { 'kerberos': rule => "
		Kerberos/ACCEPT  ${net}    $FW
		", comment => 'Allow Kerberos for krb5 server on tcp/udp port 88.'}

		# TODO: should i propose this as a shorewall macro ?
		shorewall::rule { 'kpasswd': rule => "
		ACCEPT  ${net}    $FW    tcp  464
		ACCEPT  ${net}    $FW    udp  464
		", comment => 'Allow Kerberos for kpasswd on tcp/udp port 464.'}

		if $ntp {
			shorewall::rule { 'ntp': rule => "
			NTP/ACCEPT  ${net}    $FW
			", comment => 'Allow NTP on udp port 123.'}
		}

		if $dns {
			shorewall::rule { 'dns': rule => "
			DNS/ACCEPT  ${net}    $FW
			", comment => 'Allow DNS on tcp/udp port 53.'}
		}

		if $dogtag {
			shorewall::rule { 'dogtag': rule => "
			ACCEPT  ${net}    $FW    tcp  7389
			", comment => 'Allow dogtag certificate system on tcp port 7389.'}
		}
	}
}

# vim: ts=8
