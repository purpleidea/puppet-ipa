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

	# we generate these passwords locally to use for the install, but then
	# we gpg encrypt and store locally and/or email to the root user. this
	# requires an admin's public gpg key which is a sensible thing to have
	# thanks to Jpmh from #gnupg for helping me find things in the manual!
	$dm_password = '',		# eight char minimum or auto-generated
	$admin_password = '',		# eight char minimum or auto-generated

	# if one of the above passwords is blank, you must use: $gpg_recipient
	# with: $gpg_recipient, you must use: $gpg_publickey or $gpg_keyserver
	$gpg_recipient = '',		# must specify a valid -r value to use
	$gpg_publickey = '',		# can be the value or a puppet:/// uri
	$gpg_keyserver = '',		# use a uri like: hkp://keys.gnupg.net
	$gpg_sendemail = false,		# mail out the gpg encrypted password?

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

	$ipa_installed = "/usr/bin/python -c 'import sys,ipaserver.install.installutils; sys.exit(0 if ipaserver.install.installutils.is_ipa_configured() else 1)'"

	package { 'ipa-server':
		ensure => present,
	}

	package { 'python-argparse':		# used by diff.py
		ensure => present,
	}

	package { 'pwgen':			# used to generate passwords
		ensure => present,
		before => Exec['ipa-install'],
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

	if "${dm_password}" == '' and "${gpg_recipient}" == '' {
		fail('You must specify either a dm_password or a GPG id.')
	}

	if "${admin_password}" == '' and "${gpg_recipient}" == '' {
		fail('You must specify either an admin_password or a GPG id.')
	}

	if "${gpg_recipient}" != '' {
		if "${gpg_publickey}" == '' and "${gpg_keyserver}" == '' {
			fail('You must specify either a keyserver or a public key.')
		}

		if "${gpg_publickey}" != '' and "${gpg_keyserver}" != '' {
			fail('You cannot specify a keyserver and a public key.')
		}
	}

	if "${gpg_recipient}" != '' {
		file { "${vardir}/gpg/":
			ensure => directory,	# make sure this is a directory
			recurse => true,	# don't recurse into directory
			purge => true,		# don't purge unmanaged files
			force => true,		# don't purge subdirs and links
			# group and other must not have perms or gpg complains!
			mode => 600,		# u=rw,go=
			backup => false,
			require => File["${vardir}/"],
		}

		# tag
		$dm_password_filename = "${vardir}/gpg/dm_password.gpg"
		file { "${dm_password_filename}":
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/gpg/"],
			ensure => present,
		}

		# tag
		$admin_password_filename = "${vardir}/gpg/admin_password.gpg"
		file { "${admin_password_filename}":
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/gpg/"],
			ensure => present,
		}

		# tag
		file { "${vardir}/gpg/pubring.gpg":
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/gpg/"],
			ensure => present,
		}

		file { "${vardir}/gpg/secring.gpg":
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/gpg/"],
			ensure => present,
		}

		# tag this file too, because the gpg 'unless' commands cause it
		# get added when gpg sees that it's missing from the --homedir!
		file { "${vardir}/gpg/trustdb.gpg":
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/gpg/"],
			ensure => present,
		}
	}

	if "${gpg_publickey}" != '' {
		$gpg_source = inline_template('<%= @gpg_publickey.start_with?("puppet:///") ? "true":"false" %>')
		file { "${vardir}/gpg/pub.gpg":
			content => "${gpg_source}" ? {
				'true' => undef,
				default => "${gpg_publickey}",
			},
			source => "${gpg_source}" ? {
				'true' => "${gpg_publickey}",
				default => undef,
			},
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			before => Exec['ipa-gpg-import'],
			require => File["${vardir}/gpg/"],
			ensure => present,
		}
	}

	$gpg_cmd = "/usr/bin/gpg --homedir '${vardir}/gpg/'"	# base gpg cmd!

	$gpg_import = "${gpg_publickey}" ? {
		'' => "--keyserver '${gpg_keyserver}' --recv-keys '${gpg_recipient}'",
		default => "--import '${vardir}/gpg/pub.gpg'",
	}

	if "${gpg_recipient}" != '' {

		# check if key is already imported
		$gpg_unless = "${gpg_cmd} --with-colons --fast-list-mode --list-public-keys '${gpg_recipient}'"

		exec { "${gpg_cmd} ${gpg_import}":
			logoutput => on_failure,
			unless => $gpg_unless,
			before => Exec['ipa-install'],
			require => File["${vardir}/gpg/"],
			alias => 'ipa-gpg-import',
		}

		# TODO: add checks
		# * is key revoked ?
		# * other sanity checks ?

		if $gpg_sendemail {
			# if we email out the encrypted password, make sure its
			# public key has the correct email address to match it!
			$gpg_check_email = "${gpg_cmd} --with-colons --list-public-keys '${gpg_recipient}' | /bin/awk -F ':' '\$1 = /uid/ {print \$10}' | /bin/grep -qF '<${valid_email}>'"
			exec { "${gpg_check_email}":
				logoutput => on_failure,
				unless => $gpg_unless,
				before => Exec['ipa-install'],
				require => Exec['ipa-gpg-import'],
				alias => 'ipa-gpg-check',
			}
		}
	}

	$pwgen_cmd = "/usr/bin/pwgen 16 1"

	$valid_dm_password = "${dm_password}" ? {
		'' => "${pwgen_cmd}",
		default => "/bin/cat '${vardir}/dm.password'",
	}

	$valid_admin_password = "${admin_password}" ? {
		'' => "${pwgen_cmd}",
		default => "/bin/cat '${vardir}/admin.password'",
	}

	# NOTE: we have to use '--trust-model always' or it prompts with:
	# It is NOT certain that the key belongs to the person named
	# in the user ID.  If you *really* know what you are doing,
	# you may answer the next question with yes.
	$gpg_encrypt = "${gpg_cmd} --encrypt --trust-model always --recipient '${gpg_recipient}'"
	$mail_send = "/bin/mailx -s 'Password for: ${valid_hostname}.${valid_domain}' '${valid_email}'"

	$dm_password_file = "${gpg_recipient}" ? {
		'' => '/bin/cat',	# pass through, no gpg key exists...
		default => "/usr/bin/tee >( ${gpg_encrypt} > '${dm_password_filename}' )",
	}
	if "${gpg_recipient}" != '' and $gpg_sendemail {
		$dm_password_mail = "/usr/bin/tee >( ${gpg_encrypt} | (/bin/echo 'GPG(DM password):'; /bin/cat) | ${mail_send} > /dev/null )"
	} else {
		$dm_password_mail = '/bin/cat'
	}
	$dm_password_exec = "${valid_dm_password} | ${dm_password_file} | ${dm_password_mail} | /bin/cat"

	$admin_password_file = "${gpg_recipient}" ? {
		'' => '/bin/cat',
		default => "/usr/bin/tee >( ${gpg_encrypt} > '${admin_password_filename}' )",
	}
	if "${gpg_recipient}" != '' and $gpg_sendemail {
		$admin_password_mail = "/usr/bin/tee >( ${gpg_encrypt} | (/bin/echo 'GPG(admin password):'; /bin/cat) | ${mail_send} > /dev/null )"
	} else {
		$admin_password_mail = '/bin/cat'
	}
	$admin_password_exec = "${valid_admin_password} | ${admin_password_file} | ${admin_password_mail} | /bin/cat"

	# store the passwords in text files instead of having them on cmd line!
	# even better is to let them get automatically generated and encrypted!
	if "${dm_password}" != '' {
		$dm_bool = inline_template('<%= @dm_password.length < 8 ? "false":"true" %>')
		if "${dm_bool}" != 'true' {
			fail('The dm_password must be at least eight characters in length.')
		}
		file { "${vardir}/dm.password":
			content => "${dm_password}\n",		# top top secret!
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			before => Exec['ipa-install'],
			require => File["${vardir}/"],
			ensure => present,
		}
	}

	if "${admin_password}" != '' {
		$admin_bool = inline_template('<%= @admin_password.length < 8 ? "false":"true" %>')
		if "${admin_bool}" != 'true' {
			fail('The admin_password must be at least eight characters in length.')
		}
		file { "${vardir}/admin.password":
			content => "${admin_password}\n",	# top secret!
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			before => Exec['ipa-install'],
			require => File["${vardir}/"],
			ensure => present,
		}
	}

	# these are the arguments to ipa-server-install in the prompted order
	$args01 = "--hostname='${valid_hostname}.${valid_domain}'"
	$args02 = "--domain='${valid_domain}'"
	$args03 = "--realm='${valid_realm}'"
	$args04 = "--ds-password=`${dm_password_exec}`"	# Directory Manager
	$args05 = "--admin-password=`${admin_password_exec}`"	# IPA admin
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

	$versioncmp = versioncmp("${::ipa_version}", '3.2.0')
	$args11 = $dogtag ? {
		true => '',	# TODO: setup dogtag
		default => "${versioncmp}" ? {
			# pre 3.2.0, you have to disable dogtag manually
			'-1' => '--selfsign',		# disable dogtag
			# post 3.2.0, dogtag is not setup by default...!
			default => '',
		},
	}

	$arglist = [
		"${args01}",
		"${args02}",
		"${args03}",
		"${args04}",
		"${args05}",
		"${args06}",
		"${args07}",
		"${args08}",
		"${args09}",
		"${args10}",
		"${args11}",
	]
	#$args = inline_template('<%= arglist.delete_if {|x| x.empty? }.join(" ") %>')
	$args = join(delete($arglist, ''), ' ')

	# split ipa-server-install command into a separate file so that it runs
	# as bash, and also so that it's available to run manually and inspect!
	file { "${vardir}/ipa-server-install.sh":
		content => inline_template("#!/bin/bash\n/usr/sbin/ipa-server-install ${args} --unattended\n"),
		owner => root,
		group => root,
		mode => 700,
		ensure => present,
		require => File["${vardir}/"],
	}

	exec { "${vardir}/ipa-server-install.sh":
		logoutput => on_failure,
		unless => "${ipa_installed}",	# can't install if installed...
		timeout => 3600,	# hope it doesn't take more than 1 hour
		require => [
			Package['ipa-server'],
			File["${vardir}/ipa-server-install.sh"],
		],
		alias => 'ipa-install',	# same alias as client to prevent both!
	}

	# this file is a tag that lets notify know it only needs to run once...
	file { "${vardir}/ipa_server_installed":
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

	# this fact gets created once the installation is complete... the first
	# time that puppet runs, it won't be set. after installation it will :)
	# this mechanism provides a way to only run the 'helpful' notifies once
	if "${ipa_server_installed}" != 'true' {
		# notify about password locations to be helpful
		if "${gpg_recipient}" != '' {
			if "${dm_password}" == '' {
				$dm_password_msg = "The dm_password should be found in: ${dm_password_filename}."
				notice("${dm_password_msg}")
				notify {'ipa-notify-dm_password':
					message => "${dm_password_msg}",
					#stage => last,	# TODO
					require => Exec['ipa-install'],
				}
				if $gpg_sendemail {
					$dm_password_email_msg = "The dm_password should be emailed to: ${valid_email}."
					notice("${dm_password_email_msg}")
					notify {'ipa-notify-email-dm_password':
						message => "${dm_password_email_msg}",
						#stage => last,	# TODO
						require => Exec['ipa-install'],
					}
				}
			}

			if "${admin_password}" == '' {
				$admin_password_msg = "The admin_password should be found in: ${admin_password_filename}."
				notice("${admin_password_msg}")
				notify {'ipa-notify-admin_password':
					message => "${admin_password_msg}",
					#stage => last,	# TODO
					require => Exec['ipa-install'],
				}
				if $gpg_sendemail {
					$admin_password_email_msg = "The admin_password should be emailed to: ${valid_email}."
					notice("${admin_password_email_msg}")
					notify {'ipa-notify-email-admin_password':
						message => "${admin_password_email_msg}",
						#stage => last,	# TODO
						require => Exec['ipa-install'],
					}
				}
			}
		}
	}
}

# vim: ts=8
