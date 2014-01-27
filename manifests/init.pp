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

# README: this is a rather complicated module to understand. read the comments!

# NOTE: if you ever see a puppet error where an ipa exec returns with:
#	ipa: ERROR: no modifications to be performed
# then please report this as a bug. This puppet module is (supposed to be)
# smart enough to only run exec's when they are actually necessary.

# NOTE: to hack your way into the ipa web ui with ssh port forwarding, when the
# computer you are using is completely isolated from the actual ipa server, you
# could fake the dns entry in your /etc/hosts file by adding/ensuring the line:
#	127.0.0.1 ipa.example.com ipa localhost.localdomain localhost
# exists (replace example.com with your ipa domain of course) and then running:
#	sudo ssh root@ipa -L 80:localhost:80 443:localhost:443	# (as root!)
# to force forwarding on priviledged ports, and then point your web browser to:
#	https://ipa.example.com/ipa/ui/
# and then accept the certificate. but don't do any of this, it's an evil hack!

# NOTE: this expects mit kerberos: http://web.mit.edu/kerberos/krb5-latest/doc/

# NOTE: useful ipa docs at: https://access.redhat.com/site/documentation/en-US/
# Red_Hat_Enterprise_Linux/6/html-single/Identity_Management_Guide/index.html

# NOTE: if on client reinstall ipa-client-install complains with:
#	freeipa LDAP Error: Connect error: TLS error -8054: You are attempting
#	to import a cert with the same issuer/serial as an existing cert, but
#	that is not the same cert.
# just: 'rm /etc/ipa/ca.crt', bug: https://fedorahosted.org/freeipa/ticket/3537

# NOTE: if you wish to use the $dns option, it must be enabled at first install
# subsequent enabling/disabling is currently not supported. this is because of:
#	https://fedorahosted.org/freeipa/ticket/3726
#	(ipa-dns-install needs a --uninstall option)
# and also because the DM_PASSWORD might not be available if we gpg encrypt and
# email it out after randomly generating it. This is a security feature! (TODO) <- CHANGE TO (DONE) when finished!
# we could actually support install and uninstall if that bug was resolved, and
# if we either regenerated the password, or were able to circumvent it with our
# root powers somehow. this is actually quite plausible, but not worth the time

# TODO: maybe we could have an exported resource that creates a .k5login in the
# root home dirs of machines to give access to other admins with their tickets?

# TODO: a ...host::dns type or similar needs to be added to manage and host ips

class ipa::vardir {	# module vardir snippet
	if "${::puppet_vardirtmp}" == '' {
		if "${::puppet_vardir}" == '' {
			# here, we require that the puppetlabs fact exist!
			fail('Fact: $puppet_vardir is missing!')
		}
		$tmp = sprintf("%s/tmp/", regsubst($::puppet_vardir, '\/$', ''))
		# base directory where puppet modules can work and namespace in
		file { "${tmp}":
			ensure => directory,	# make sure this is a directory
			recurse => false,	# don't recurse into directory
			purge => true,		# purge all unmanaged files
			force => true,		# also purge subdirs and links
			owner => root,
			group => nobody,
			mode => 600,
			backup => false,	# don't backup to filebucket
			#before => File["${module_vardir}"],	# redundant
			#require => Package['puppet'],	# no puppet module seen
		}
	} else {
		$tmp = sprintf("%s/", regsubst($::puppet_vardirtmp, '\/$', ''))
	}
	$module_vardir = sprintf("%s/ipa/", regsubst($tmp, '\/$', ''))
	file { "${module_vardir}":		# /var/lib/puppet/tmp/ipa/
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${tmp}"],	# File['/var/lib/puppet/tmp/']
	}
}

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

# FIXME: some values have not been filled in yet. some are missing: --arguments
define ipa::server::config(
	$value
) {
	$key = "${name}"

	$etype = "${key}" ? {	# expected type
		#'?' => '',			# FIXME: dn
		#'?' => '',			# --maxusername
		'homes' => 'string',
		'shell' => 'string',
		#'?' => '',			# --defaultgroup
		'emaildomain' => 'string',
		#'?' => '',			# --searchtimelimit
		#'?' => '',			# --searchrecordslimit
		'usersearch' => 'array',
		'groupsearch' => 'array',
		'migration' => 'boolean',
		#'?' => '',			# FIXME: ipacertificatesubjectbase
		#'?' => '',			# --groupobjectclasses
		#'?' => '',			# --userobjectclasses
		#'?' => '',			# --pwdexpnotify
		#'?' => '',			# --ipaconfigstring
		#'?' => '',			# --ipaselinuxusermaporder
		#'?' => '',			# --ipaselinuxusermapdefault
		#'?' => '',			# --pac-type
		#'?' => '',			# FIXME: cn
		#'?' => '',			# FIXME: objectclass
		default => '',	# missing
	}

	$option = "${key}" ? {
		#'?' => 'dn',				FIXME
		#'?' => '--maxusername=',
		'homes' => '--homedirectory=',
		'shell' => '--defaultshell=',
		#'?' => '--defaultgroup=',
		'emaildomain' => '--emaildomain=',
		#'?' => '--searchtimelimit=',
		#'?' => '--searchrecordslimit=',
		'usersearch' => '--usersearch=',
		'groupsearch' => '--groupsearch=',
		'migration' => '--enable-migration=',
		#'?' => 'ipacertificatesubjectbase',	FIXME
		#'?' => '--groupobjectclasses=',
		#'?' => '--userobjectclasses=',
		#'?' => '--pwdexpnotify=',
		#'?' => '--ipaconfigstring=',
		#'?' => '--ipaselinuxusermaporder=',
		#'?' => '--ipaselinuxusermapdefault=',
		#'?' => '--pac-type=',
		#'?' => 'cn',				FIXME
		#'?' => 'objectclass',			FIXME
		default => '',	# missing
	}

	$rawkey = "${key}" ? {
		#'?' => 'dn',
		#'?' => 'ipamaxusernamelength',
		'homes' => 'ipahomesrootdir',
		'shell' => 'ipadefaultloginshell',
		#'?' => 'ipadefaultprimarygroup',
		'emaildomain' => 'ipadefaultemaildomain',
		#'?' => 'ipasearchtimelimit',
		#'?' => 'ipasearchrecordslimit',
		'usersearch' => 'ipausersearchfields',
		'groupsearch' => 'ipagroupsearchfields',
		'migration' => 'ipamigrationenabled',
		#'?' => 'ipacertificatesubjectbase',
		#'?' => 'ipagroupobjectclasses',
		#'?' => 'ipauserobjectclasses',
		#'?' => 'ipapwdexpadvnotify',
		#'?' => 'ipaconfigstring',
		#'?' => 'ipaselinuxusermaporder',
		#'?' => 'ipaselinuxusermapdefault',
		#'?' => 'ipakrbauthzdata',
		#'?' => 'cn',
		#'?' => 'objectclass',
		default => '',	# missing
	}

	if "${option}" == '' or "${etype}" == '' or "${rawkey}" == '' {
		fail("Key '${key}' is invalid.")
	}

	if type($value) != "${etype}" {
		fail("Ipa::Server::Config[${key}] must be type: ${etype}.")
	}

	# convert to correct type
	if "${etype}" == 'string' {
		$safe_value = shellquote($value)	# TODO: is this right ?
		$jchar = ''	# pass through the paste binary
	} elsif "${etype}" == 'array' {
		$jchar = "${key}" ? {	# join char
			'usersearch' => ',',
			'groupsearch' => ',',
			default => '',
		}
		$safe_value = inline_template('<%= value.join(jchar) %>')
	} elsif "${etype}" == 'boolean' {
		$safe_value = $value ? {
			true => 'TRUE',
			default => 'FALSE',
		}
		$jchar = ''	# pass through the paste binary
	} else {
		fail("Unknown type: ${etype}.")
	}

	$cutlength = inline_template('<%= (rawkey.length+2).to_s %>')
	exec { "/usr/bin/ipa config-mod ${option}'${safe_value}'":
		unless => "/usr/bin/test \"`/usr/bin/ipa config-show --raw --all | /usr/bin/tr -d ' ' | /bin/grep '^${rawkey}:' | /bin/cut -b ${cutlength}- | /usr/bin/paste -sd '${jchar}'`\" = '${safe_value}'",
		logoutput => on_failure,
		require => [
			Exec['ipa-install'],
			Exec['ipa-server-kinit'],
		],
	}
}

class ipa::server::host::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# we don't want to purge the freeipa entry, so we need to exclude it...
	$valid_hostname = $ipa::server::valid_hostname
	$valid_domain = $ipa::server::valid_domain
	$host_always_ignore = ["${valid_hostname}.${valid_domain}"]
	$host_excludes = $ipa::server::host_excludes
	$valid_host_excludes = type($host_excludes) ? {
		'string' => [$host_excludes],
		'array' => $host_excludes,
		'boolean' => $host_excludes ? {
			# TODO: there's probably a better fqdn match expression
			# this is an expression to prevent all fqdn deletion...
			#true => ['^[a-zA-Z0-9\.\-]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]-.]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_host_excludes) != 'array' {
		fail('The $host_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/hosts/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-hosts'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'hosts'
	$ls_cmd = '/usr/bin/ipa host-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep "^fqdn:" | /bin/cut -b 6-'	# show ipa hosts
	# TODO: i don't understand all the implications of the --updatedns arg!
	# we should probably change the dns arg based on if dns is on or not...
	$rm_cmd = $dns ? {	# delete ipa hosts
		true => '/usr/bin/ipa host-del --updatedns ',
		default => '/usr/bin/ipa host-del ',
	}
	$fs_chr = ' '
	$suffix = '.host'
	$regexp = $valid_host_excludes
	$ignore = $host_always_ignore

	# build the clean script
	file { "${vardir}/clean-hosts.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-hosts.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-hosts.sh"],
		],
		alias => 'ipa-clean-hosts',
	}

	# NOTE: it doesn't cause a problem that this dir is inside the hosts dir
	file { "${vardir}/hosts/passwords/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/hosts/"],
	}

	file { "${vardir}/hosts/sshpubkeys/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/hosts/"],
	}
}

# NOTE: this should only be used by a freeipa client and as an exported resource
define ipa::server::host::pwtag() {
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# the existence of this file means that an ipa client has exported it,
	# and that the ipa server collected it and it means that a provisioned
	# ipa client host is notifying the server that a new one time password
	# does not need to be generated at this time. to reprovision the host,
	# you must erase the exported resource that is sending this file here,
	# or rather, in doing so, the ipa server will generate a new password!
	file { "${vardir}/hosts/passwords/${name}.pwtag":
		content => "# This is a password tag for: ${name}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		backup => false,
		before => Exec["ipa-host-verify-password-exists-${name}"],
		require => File["${vardir}/hosts/passwords/"],
		ensure => present,
	}
}

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

define ipa::server::host(
	$domain = $ipa::server::domain,		# default to main domain
	$server = '',		# where the client will find the ipa server...
	$macaddress = '',	# TODO: this should be a list...
	#$ipaddress = '',	# NOTE: this is a bad fit here...
	$sshpubkeys = true,	# leave this at the default to get auto sshkeys
	#$certificate = ???,	# TODO ?

	$password = '',		# one time password used for host provisioning!
	$random = false,	# or set this to true to have us generate it...

	# comment parameters...
	$locality = '',	# host locality (e.g. "Montreal, Canada")
	$location = '',	# host location (e.g. "Lab 42")
	$platform = '',	# host hardware platform (e.g. "Lenovo X201")
	$osstring = '',	# host operating system and version (e.g. "CentOS 6.4")
	$comments = '',	# host description (e.g. "NFS server")

	#$hosts = [],		# TODO: add hosts managed by support

	# client specific parameters...
	$admin = false,	# should client get admin tools installed ?

	# special parameters...
	$watch = true,	# manage all changes to this resource, reverting others
	$modify = true	# modify this resource on puppet changes or not ?
) {
	include ipa::server
	include ipa::server::host::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$dns = $ipa::server::dns			# boolean from main obj

	$valid_domain = downcase($domain)

	$valid_server = "${server}" ? {
		'' => "${::hostname}.${::domain}",
		default => "${server}",
	}

	# NOTE: the valid_fqdn is actually what ipa calls a hostname internally
	# if $name has dots, then we assume it's a fqdn, if not, we add $domain
	$valid_fqdn = delete("${name}", '.') ? {
		"${name}" => "${name}.${valid_domain}",	# had no dots present
		default => "${name}",			# had dots present...
	}

	$valid_sshpubkeys = type($sshpubkeys) ? {
		'string' => "${sshpubkeys}" ? {
			# BUG: lol: https://projects.puppetlabs.com/issues/15813
			'' => [],	# assume managed but empty (rm sshkeys)
			default => ["${sshpubkeys}"],
		},
		'boolean' => $sshpubkeys,
		'array' => $sshpubkeys,
		default => '',	# set an error...
	}
	if "${valid_sshpubkeys}" == '' {
		fail('You must specify a valid type for $sshpubkeys.')
	}

	if $watch and (! $modify) {
		fail('You must be able to $modify to be able to $watch.')
	}

	# NOTE: this is not a good fit for host-* it is part of the dns system,
	# and not the host, and should be managed separately
	#if $dns {
	#	$args00 = "${ipaddress}" ? {
	#		'' => '',
	#		default => "--ip-address='${ipaddress}'",
	#	}
	#} else {
	#	$args00 = ''
	#	# TODO: allow this silently for now...
	#	#warning("Host: '${valid_fqdn}' is setting an IP without DNS.")
	#}

	$args01 = "${macaddress}" ? {
		'' => '',
		default => "--macaddress='${macaddress}'",
	}

	# array means: managed, set these keys exactly, and remove when it's []
	# boolean false means: unmanaged, don't set or get anything... empty ''
	# boolean true means: managed, get the keys automatically (super magic)
	$args02 = type($valid_sshpubkeys) ? {
		# we always have to at least specify the '--sshpubkey=' if this
		# is empty, because otherwise we have no way to remove old keys
		'array' => inline_template('<% if valid_sshpubkeys == [] %>--sshpubkey=<% else %><%= valid_sshpubkeys.map {|x| "--sshpubkey=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => $valid_sshpubkeys ? {	# boolean
			false => '',			# unmanaged, do nothing
			# this large beast loops through all the collected dirs
			# and cats the contents of each file into an individual
			# --sshpubkey argument. if no keys are found, the empty
			# --sshpubkey argument is returned. this is all used to
			# build the ipa commands. i hope this doesn't overflow!
			default => "`a=(); for i in ${vardir}/hosts/sshpubkeys/${name}/*.pub; do [ -e \"\$i\" ] || break; a+=(\"--sshpubkey='\$(/bin/cat \$i)'\"); done; if [ \"\${a[*]}\" == '' ]; then /bin/echo \"--sshpubkey=\"; else /bin/echo \${a[@]}; fi`",
		},
	}

	$args03 = "${locality}" ? {
		'' => '',
		default => "--locality='${locality}'",
	}
	$args04 = "${location}" ? {
		'' => '',
		default => "--location='${location}'",
	}
	$args05 = "${platform}" ? {
		'' => '',
		default => "--platform='${platform}'",
	}
	$args06 = "${osstring}" ? {
		'' => '',
		default => "--os='${osstring}'",
	}
	$args07 = "${comments}" ? {
		'' => '',
		default => "--desc='${comments}'",
	}

	$arglist = ["${args01}", "${args02}", "${args03}", "${args04}", "${args05}", "${args06}", "${args07}"]
	$args = join(delete($arglist, ''), ' ')

	if $random and ("${password}" != '') {
		fail('Specify $random or $password, but not both.')
	}
	$argspass = "${password}" ? {
		'' => $random ? {
			true => '--random',
			default => '',			# no password specified
		},
		#default => "--password='${password}'",	# direct mode, (bad)!
		default => "--password=`/bin/cat '${vardir}/hosts/passwords/${valid_fqdn}.password'`",
	}

	$qarglist = ["${argspass}"]	# NOTE: add any silent arg changes here
	$qargs = join(delete($qarglist, ''), ' ')

	# if we're not modifying, we need to add on the qargs stuff to the add!
	$xarglist = $modify ? {
		false => concat($arglist, $qarglist),
		default => $arglist,
	}
	$xargs = join(delete($xarglist, ''), ' ')

	# NOTE: this file is the subscribe destination for the modify exec when
	# not using watch mode. it is separate from the qhost file (which is
	# used for unwatchable changes), because if we had only one notify
	# source, then a configuration transition from watch to unwatched would
	# actually trigger a modification. this file is also the official file
	# that is used by the clean script for determining which hosts need to
	# be erased. please keep in mind that on accidental notification, or on
	# system rebuild, the differing changes will be erased.
	file { "${vardir}/hosts/${valid_fqdn}.host":
		content => "${valid_fqdn}\n${args}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/hosts/"],
		ensure => present,
	}

	file { "${vardir}/hosts/${valid_fqdn}.qhost":
		content => "${valid_fqdn}\n${qargs}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/hosts/"],
		ensure => present,
	}

	# NOTE: a custom fact, reads from these dirs and collects the passwords
	if $random {
		file { "${vardir}/hosts/passwords/${valid_fqdn}.password":
			# no content! this is a tag, content comes in by echo !
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			notify => $modify ? {
				false => undef,	# can't notify if not modifying
				default => Exec["ipa-server-host-qmod-${name}"],
			},
			require => File["${vardir}/hosts/passwords/"],
			ensure => present,
		}
	} elsif "${password}" != '' {
		file { "${vardir}/hosts/passwords/${valid_fqdn}.password":
			content => "${password}\n",	# top secret (briefly!)
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			notify => $modify ? {
				false => undef,	# can't notify if not modifying
				default => Exec["ipa-server-host-qmod-${name}"],
			},
			before => $modify ? {
				false => undef,
				default => Exec["ipa-server-host-qmod-${name}"],
			},
			require => File["${vardir}/hosts/passwords/"],
			ensure => present,
		}
	}

	file { "${vardir}/hosts/sshpubkeys/${name}/":	# store host ssh keys
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/hosts/sshpubkeys/"],
	}

	# collect host specific ssh keys
	Ipa::Server::Host::Sshpubkeys <<| tag == "${name}" |>> {
		#realname => "${name}",
		#basedir => "${vardir}/hosts/sshpubkeys/${name}/",
	}

	$exists = "/usr/bin/ipa host-show '${valid_fqdn}' > /dev/null 2>&1"
	# NOTE: we don't need to set the password in the host-add, because the
	# host-mod that deals specifically with password stuff will trigger it
	# NOTE: --force is needed when dns is configured for ipa but we're not
	# setting an ip address on host-add. this makes ipa sad, and it fails!
	# NOTE: we don't seem to need --force for host-mod, as it hasn't erred
	$force = "${xargs}" ? {			# if args is empty
		'' => '--force',		# we have no args!
		default => "${xargs} --force",	# pixel perfect...
	}
	$fargs = $dns ? {			# without the dns,
		true => "${force}",		# we don't need to
		default => "${xargs}",		# force everything
	}
	# NOTE: this runs when no host is present...
	#exec { "/usr/bin/ipa host-add '${valid_fqdn}' ${fargs}":
	exec { "ipa-server-host-add-${name}":	# alias
		# this has to be here because the command string gets too long
		# for a puppet $name var and strange things start to happen...
		command => "/usr/bin/ipa host-add '${valid_fqdn}' ${fargs}",
		logoutput => on_failure,
		unless => "${exists}",
		require => $dns ? {
			true => [
				Exec['ipa-server-kinit'],
				File["${vardir}/hosts/sshpubkeys/${name}/"],
			],
			default => [
				Exec['ipa-dns-check'],	# avoid --force errors!
				Exec['ipa-server-kinit'],
				File["${vardir}/hosts/sshpubkeys/${name}/"],
			],
		},
		#alias => "ipa-server-host-add-${name}",
	}

	# NOTE: this runs when we detect that the attributes don't match (diff)
	if $modify and ("${args}" != '') {	# if there are changes to do...
		#exec { "/usr/bin/ipa host-mod '${valid_fqdn}' ${args}":
		exec { "ipa-server-host-mod-${name}":
			command => "/usr/bin/ipa host-mod '${valid_fqdn}' ${args}",
			logoutput => on_failure,
			refreshonly => $watch ? {
				false => true,		# when not watching, we
				default => undef,	# refreshonly to change
			},
			subscribe => $watch ? {
				false => File["${vardir}/hosts/${valid_fqdn}.host"],
				default => undef,
			},
			onlyif => "${exists}",
			unless => $watch ? {
				false => undef,	# don't run the diff checker...
				default => "${exists} && ${vardir}/diff.py host '${valid_fqdn}' ${args}",
			},
			before => "${qargs}" ? {	# only if exec exists !
				'' => undef,
				default => Exec["ipa-server-host-qmod-${name}"],
			},
			require => [
				File["${vardir}/diff.py"],
				Exec['ipa-server-kinit'],
				Exec["ipa-server-host-add-${name}"],
				File["${vardir}/hosts/sshpubkeys/${name}/"],
			],
			#alias => "ipa-server-host-mod-${name}",
		}
	}

	# NOTE: this runs when there should be an attribute change we can't see
	if $modify and ("${qargs}" != '') {		# quiet q changes to do

		# this is a bonus to double check that a password entry exists!
		# once a host is provisioned, it will reset the single use pass
		# and this script would normally try and create a new one back,
		# however if a pwtag is collected, then it won't run the notify
		# this is pretty advanced stuff to understand, but it's useful!
		if $random or ("${password}" != '') {

			# collect any password tags. note i used $name exactly!
			Ipa::Server::Host::Pwtag <<| tag == "${name}" |>> {
			}
			exec { "ipa-host-verify-password-exists-${name}":	# uid
				command => '/bin/true',	# i'm just here for the notify!
				# do not run this if the password tag exists...
				# if it dissapears, that means the host is gone
				unless => "/usr/bin/test -e '${vardir}/hosts/passwords/${name}.pwtag'",
				# only do this if machine is unenrolled, eg see
				# https://git.fedorahosted.org/cgit/freeipa.git
				# /tree/ipalib/plugins/host.py#n642 (approx...)
				# NOTE: this uses a single equals sign for test
				onlyif => [
					"/usr/bin/test \"`/usr/bin/ipa host-show '${valid_fqdn}' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_password:' | /bin/cut -b 14-`\" = 'False'",
					"/usr/bin/test \"`/usr/bin/ipa host-show '${valid_fqdn}' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_keytab:' | /bin/cut -b 12-`\" = 'False'",
				],
				logoutput => on_failure,
				notify => Exec["ipa-server-host-qmod-${name}"],
				# TODO: notify: Exec['again'] so that the facts
				# get refreshed right away, and the password is
				# exported without delay! now go and hack away!
				before => Exec["ipa-server-host-qmod-${name}"],
				require => [
					Exec['ipa-server-kinit'],
					Exec["ipa-server-host-add-${name}"],
					# this file require ensures that if the
					# pwtag disappears (by that dir purge),
					# that right away the new pass is made!
					File["${vardir}/hosts/passwords/"],
				],
			}
		}

		# NOTE: if this runs before a pwtag can prevent it, on a random
		# password it will succeed without error and wipe the password:
		# invalid 'password': Password cannot be set on enrolled host.
		# this isn't a big deal, it just has the side effect of erasing
		# the stored temporary password from locally where it's unused.
		# if this runs before a pwtag can prevent it, on a static pass,
		# this will cause a transient error until the pwtag gets saved.
		# to avoid both of these scenarios, the above exec runs a check
		# to see if the host is unenrolled before running the notify :)
		$qextra = $random ? {	# save the generated password to a file
			true => " --raw | /usr/bin/tr -d ' ' | /bin/grep '^randompassword:' | /bin/cut -b 16- > ${vardir}/hosts/passwords/${valid_fqdn}.password",
			default => '',
		}
		exec { "/usr/bin/ipa host-mod '${valid_fqdn}' ${qargs}${qextra}":
			logoutput => on_failure,
			refreshonly => true,	# needed because we can't "see"
			subscribe => File["${vardir}/hosts/${valid_fqdn}.qhost"],
			onlyif => "${exists}",
			require => [
				Exec['ipa-server-kinit'],
				Exec["ipa-server-host-add-${name}"],
			],
			alias => "ipa-server-host-qmod-${name}",
		}
	}

	# use this password in an exported resource to deploy the ipa client...
	$passfact = regsubst("ipa_host_${valid_fqdn}_password", '\.', '_', 'G')
	$pass = getvar("${passfact}")
	# NOTE: 'include ipa::client::host::deploy' to deploy the ipa client...
	@@ipa::client::host { "${name}":	# this is usually the fqdn
		# NOTE: this should set all the client args it can safely assume
		domain => $valid_domain,
		realm => $realm,
		server => "${valid_server}",
		password => "${pass}",
		admin => $admin,
		#ssh => $ssh,
		#sshd => $sshd,
		#ntp => $ntp,
		#ntp_server => $ntp_server,
		#shorewall => $shorewall,
		#zone => $zone,
		#allow => $allow,
		#ensure => $ensure,
		tag => "${name}",	# bonus
	}
}

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

	package { 'ipa-client':
		ensure => present,
	}

	# an administrator machine requires the ipa-admintools package as well:
	package { 'ipa-admintools':
		ensure => $admin ? {
			true => present,
			false => absent,
		},
		require => Package['ipa-client'],
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
			Package['ipa-client'],
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

define ipa::client::host(
	# NOTE: this should be a copy of most of the params from ipa::client
	$domain = '',
	$realm = '',
	$server = '',
	$password = '',
	$admin = false,
	$ssh = false,
	$sshd = false,
	$ntp = false,
	$ntp_server = '',
	$shorewall = false,
	$zone = 'net',
	$allow = 'all',
	$debug = false,
	$ensure = present	# TODO
) {
	# $name should be a fqdn, split it into the $hostname and $domain args!
	# NOTE: a regexp wizard could possibly write something to match better!
	#$r = '^([a-z][a-z0-9\-]*)\.([a-z0-9\.\-]*)$'
	$r = '^([a-z][a-z0-9\-]*)(\.{0,1})([a-z0-9\.\-]*)$'
	$h = regsubst("${name}", $r, '\1')
	$x = regsubst("${name}", $r, '\2')	# the dot
	$d = regsubst("${name}", $r, '\3')

	$valid_hostname = "${h}"
	$valid_domain = "${d}" ? {
		'' => "${domain}" ? {
			'' => "${::domain}",
			default => "${domain}",
		},
		default => "${d}" ? {	# we need to check this matches $domain
			"${domain}" => "${d}",		# they match, okay phew
			default => '',	# no match, set '' to trigger an error!
		},
	}
	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('A $domain inconsistency was found.')
	}

	class { '::ipa::client':
		# NOTE: this should transfer most of the params from ipa::client
		name => $name,		# often the fqdn, but necessarily
		hostname => $valid_hostname,
		domain => $valid_domain,
		realm => $realm,
		server => $server,
		password => $password,
		admin => $admin,
		ssh => $ssh,
		sshd => $sshd,
		ntp => $ntp,
		ntp_server => $ntp_server,
		shorewall => $shorewall,
		zone => $zone,
		allow => $allow,
		debug => $debug,
		ensure => $ensure,
	}
}

# NOTE: use this to deploy the exported resource @@ipa::client::host on clients
#define ipa::client::host::deploy(
class ipa::client::host::deploy(
	$hostname = $::hostname,
	$domain = $::domain,
	$server = '',
	$nametag = '',				# pick a tag to collect...
	$debug = false
) {
	$valid_domain = downcase($domain)	# TODO: validate ?

	# if $hostname has dots, then assume it's a fqdn, if not, we add $domain
	$valid_fqdn = delete("${hostname}", '.') ? {
		"${hostname}" => "${hostname}.${valid_domain}",	# had no dots present
		default => "${hostname}",			# had dots present...
	}

	# NOTE: the resource collects by fqdn; one good reason to use the fqdn!
	# sure you can override this by choosing your own $name value, but why?
	$valid_tag = "${nametag}" ? {
		'' => "${valid_fqdn}",
		default => "${nametag}",
	}

	# TODO: if i had more than one arg to decide to override, then i would
	# have to build a big tree of nested choices... this is one more place
	# where puppet shows it's really not a mature language yet. oh well...
	if "${server}" == '' {
		Ipa::Client::Host <<| tag == "${valid_tag}" |>> {
			debug => $debug,
		}
	} else {
		Ipa::Client::Host <<| tag == "${valid_tag}" |>> {
			server => "${server}",	# override...
			debug => $debug,
		}
	}
}

class ipa::server::service::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# by default, the following services get installed with freeipa:
	# DNS/ipa.example.com@EXAMPLE.COM
	# dogtagldap/ipa.example.com@EXAMPLE.COM
	# HTTP/ipa.example.com@EXAMPLE.COM
	# ldap/ipa.example.com@EXAMPLE.COM
	# since we don't want to purge them, we need to exclude them...
	$prefix = ['DNS', 'dogtagldap', 'HTTP', 'ldap']
	$valid_hostname = $ipa::server::valid_hostname
	$valid_domain = $ipa::server::valid_domain
	$valid_realm = $ipa::server::valid_realm
	$append = "/${valid_hostname}.${valid_domain}@${valid_realm}"
	$service_always_ignore = suffix($prefix, $append)

	$service_excludes = $ipa::server::service_excludes
	$valid_service_excludes = type($service_excludes) ? {
		'string' => [$service_excludes],
		'array' => $service_excludes,
		'boolean' => $service_excludes ? {
			# TODO: there's probably a better fqdn match expression
			# this is an expression to prevent all fqdn deletion...
			#true => ['^[a-zA-Z0-9\.\-]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]-.]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_service_excludes) != 'array' {
		fail('The $service_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/services/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-services'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'services'
	$ls_cmd = '/usr/bin/ipa service-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep "^krbprincipalname:" | /bin/cut -b 18-'	# show ipa services
	$rm_cmd = '/usr/bin/ipa service-del '	# delete ipa services
	$fs_chr = ' '
	$suffix = '.service'
	$regexp = $valid_service_excludes
	$ignore = $service_always_ignore

	# build the clean script
	file { "${vardir}/clean-services.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-services.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-services.sh"],
		],
		alias => 'ipa-clean-services',
	}
}

define ipa::server::service(
	$service = '',		# nfs, HTTP, ldap
	$host = '',		# should match $name of ipa::server::host
	$domain = '',		# must be the empty string by default
	$realm = '',
	$principal = '',	# after all that, you can override principal...
	$server = '',		# where the client will find the ipa server...

	# args
	$pactype = [],		# bad values are silently discarded, [] is NONE

	#$hosts = [],		# TODO: add hosts managed by support

	# special parameters...
	$watch = true,	# manage all changes to this resource, reverting others
	$modify = true,	# modify this resource on puppet changes or not ?
	$comment = '',
	$ensure = present	# TODO
) {
	include ipa::server
	include ipa::server::service::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$dns = $ipa::server::dns			# boolean from main obj

	# TODO: a better regexp magician could probably do a better job :)
	# nfs/nfs.example.com@EXAMPLE.COM
	$r = '^([a-zA-Z][a-zA-Z0-9]*)(/([a-z][a-z\.\-]*)(@([A-Z][A-Z\.\-]*)){0,1}){0,1}$'

	$a = regsubst("${name}", $r, '\1')	# service (nfs)
	$b = regsubst("${name}", $r, '\3')	# fqdn (nfs.example.com)
	$c = regsubst("${name}", $r, '\5')	# realm (EXAMPLE.COM)

	# service: first try to get value from arg, then fall back to $a (name)
	$valid_service = "${service}" ? {
		'' => "${a}",				# get from $name regexp
		default => "${service}",
	}
	if "${valid_service}" == '' {
		# NOTE: if we see this message it might be a regexp pattern bug
		fail('The $service must be specified.')
	}

	# host: first try to get value from arg, then fall back to $b
	# this is not necessarily the fqdn, but it could be. both are possible!
	$valid_host = "${host}" ? {
		'' => "${b}",				# get from $name regexp
		default => "${host}",
	}
	# this error will probably prevent a later error in $valid_domain
	if "${valid_host}" == '' {
		fail('The $host must be specified.')
	}

	# parse the fqdn from $valid_host
	$r2 = '^([a-z][a-z0-9\-]*)(\.{0,1})([a-z0-9\.\-]*)$'
	#$h = regsubst("${valid_host}", $r2, '\1')	# hostname
	$d = regsubst("${valid_host}", $r2, '\3')	# domain

	$valid_domain = delete("${valid_host}", '.') ? {
		"${valid_host}" => "${domain}" ? {	# no dots, not an fqdn!
			'' => "${ipa::server::domain}" ? {	# NOTE: server!
				'' => "${::domain}",	# default to global val
				default => "${ipa::server::domain}",	# main!
			},
			default => "${domain}",
		},
		default => "${domain}" ? {		# dots, it's an fqdn...
			'' => "${d}",	# okay, used parsed value, it had dots!
			"${d}" => "${domain}",		# they match, okay phew
			default => '',	# no match, set '' to trigger an error!
		},
	}

	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('The $domain must be specified.')
	}

	$valid_fqdn = delete("${valid_host}", '.') ? {	# does it have any dots
		"${valid_host}" => "${valid_host}.${valid_domain}",
		default => "${valid_host}",		# it had dot(s) present
	}

	$valid_realm = "${realm}" ? {
		'' => "${c}" ? {			# get from $name regexp
			'' => upcase($valid_domain),	# a backup plan default
			default => "${c}",		# got from $name regexp
		},
		default => "${realm}",
	}

	# sanity checking, this should probably not happen
	if "${valid_realm}" == '' {
		fail('The $realm must be specified.')
	}

	$valid_server = "${server}" ? {
		'' => "${::hostname}.${::domain}",
		default => "${server}",
	}

	# sanity checking, this should probably not happen
	if "${valid_server}" == '' {
		fail('The $server must be specified.')
	}

	$valid_principal = "${principal}" ? {
		'' => "${valid_service}/${valid_fqdn}@${valid_realm}",
		default => "${principal}",		# just do what you want
	}

	if $watch and (! $modify) {
		fail('You must be able to $modify to be able to $watch.')
	}

	$pactype_valid = ['MS-PAC', 'PAD']	# or 'NONE'
	$pactype_array = type($pactype) ? {
		'array' => $pactype,
		'string' => ["${pactype}"],
		default => [],			# will become 'NONE'
	}
	$valid_pactype = split(inline_template('<%= ((pactype_array.delete_if {|x| not pactype_valid.include?(x)}.length == 0) ? ["NONE"] : pactype_array.delete_if {|x| not pactype_valid.include?(x)}).join("#") %>'), '#')

	$args01 = sprintf("--pac-type='%s'", join($valid_pactype, ','))

	$arglist = ["${args01}"]	# future expansion available :)
	$args = join(delete($arglist, ''), ' ')

	# switch the slashes for a file name friendly character
	$valid_principal_file = regsubst("${valid_principal}", '/', '-', 'G')
	file { "${vardir}/services/${valid_principal_file}.service":
		content => "${valid_principal}\n${args}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/services/"],
		ensure => present,
	}

	$exists = "/usr/bin/ipa service-show '${valid_principal}' > /dev/null 2>&1"
	$force = "${args}" ? {			# if args is empty
		'' => '--force',		# we have no args!
		default => "${args} --force",	# pixel perfect...
	}
	$fargs = $dns ? {			# without the dns,
		true => "${force}",		# we don't need to
		default => "${args}",		# force everything
	}
	# NOTE: this runs when no service is present...
	exec { "ipa-server-service-add-${name}":	# alias
		# this has to be here because the command string gets too long
		# for a puppet $name var and strange things start to happen...
		command => "/usr/bin/ipa service-add '${valid_principal}' ${fargs}",
		logoutput => on_failure,
		unless => "${exists}",
		require => $dns ? {
			true => [
				Exec['ipa-server-kinit'],
			],
			default => [
				Exec['ipa-dns-check'],	# avoid --force errors!
				Exec['ipa-server-kinit'],
			],
		},
	}

	# NOTE: this runs when we detect that the attributes don't match (diff)
	if $modify and ("${args}" != '') {	# if there are changes to do...
		#exec { "/usr/bin/ipa service-mod '${valid_principal}' ${args}":
		exec { "ipa-server-service-mod-${name}":
			command => "/usr/bin/ipa service-mod '${valid_principal}' ${args}",
			logoutput => on_failure,
			refreshonly => $watch ? {
				false => true,		# when not watching, we
				default => undef,	# refreshonly to change
			},
			subscribe => $watch ? {
				false => File["${vardir}/services/${valid_principal_file}.service"],
				default => undef,
			},
			onlyif => "${exists}",
			unless => $watch ? {
				false => undef,	# don't run the diff checker...
				default => "${exists} && ${vardir}/diff.py service '${valid_principal}' ${args}",
			},
			require => [
				File["${vardir}/diff.py"],
				Exec['ipa-server-kinit'],
				Exec["ipa-server-service-add-${name}"],
			],
			#alias => "ipa-server-service-mod-${name}",
		}
	}

	@@ipa::client::service { "${name}":	# this is usually the principal
		# NOTE: this should set all the client args it can safely assume
		service => "${valid_service}",
		host => "${valid_host}",	# this value is used to collect
		domain => "${valid_domain}",
		realm => "${valid_realm}",
		principal => "${valid_principal}",
		server => "${valid_server}",
		comment => "${comment}",
		ensure => $ensure,
		require => Ipa::Client::Host["${name}"],	# should match!
		tag => "${name}",					# bonus
	}
}

# FIXME: if this resource is removed, how do we revoke the key from the keytab?
# FIXME: it seems that after a kdestroy/kinit cycle happens, it is then revoked
# FIXME: a freeipa expert should verify and confirm that it's safe/ok this way!
# this runs ipa-getkeytab magic, to setup the keytab, for a service on a client
define ipa::client::service(
	$service = '',		# nfs, HTTP, ldap
	$host = '',		# should match $name of ipa::client::host
	$domain = '',		# must be the empty string by default
	$realm = '',
	$principal = '',	# after all that, you can override principal...
	$server = '',		# where the client will find the ipa server...
	$keytab = '',		# defaults to /etc/krb5.keytab
	$comment = '',
	$debug = false,
	$ensure = present
) {
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# NOTE: much of the following code is almost identical to that up above
	# TODO: a better regexp magician could probably do a better job :)
	# nfs/nfs.example.com@EXAMPLE.COM
	$r = '^([a-zA-Z][a-zA-Z0-9]*)(/([a-z][a-z\.\-]*)(@([A-Z][A-Z\.\-]*)){0,1}){0,1}$'

	$a = regsubst("${name}", $r, '\1')	# service (nfs)
	$b = regsubst("${name}", $r, '\3')	# fqdn (nfs.example.com)
	$c = regsubst("${name}", $r, '\5')	# realm (EXAMPLE.COM)

	# service: first try to get value from arg, then fall back to $a (name)
	$valid_service = "${service}" ? {
		'' => "${a}",				# get from $name regexp
		default => "${service}",
	}
	if "${valid_service}" == '' {
		# NOTE: if we see this message it might be a regexp pattern bug
		fail('The $service must be specified.')
	}

	# host: first try to get value from arg, then fall back to $b
	# this is not necessarily the fqdn, but it could be. both are possible!
	$valid_host = "${host}" ? {
		'' => "${b}",				# get from $name regexp
		default => "${host}",
	}
	# this error will probably prevent a later error in $valid_domain
	if "${valid_host}" == '' {
		fail('The $host must be specified.')
	}

	# parse the fqdn from $valid_host
	$r2 = '^([a-z][a-z0-9\-]*)(\.{0,1})([a-z0-9\.\-]*)$'
	#$h = regsubst("${valid_host}", $r2, '\1')	# hostname
	$d = regsubst("${valid_host}", $r2, '\3')	# domain

	$valid_domain = delete("${valid_host}", '.') ? {
		"${valid_host}" => "${domain}" ? {	# no dots, not an fqdn!
			'' => "${ipa::client::domain}" ? {	# NOTE: client!
				'' => "${::domain}",	# default to global val
				default => "${ipa::client::domain}",	# main!
			},
			default => "${domain}",
		},
		default => "${domain}" ? {		# dots, it's an fqdn...
			'' => "${d}",	# okay, used parsed value, it had dots!
			"${d}" => "${domain}",		# they match, okay phew
			default => '',	# no match, set '' to trigger an error!
		},
	}

	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('The $domain must be specified.')
	}

	$valid_fqdn = delete("${valid_host}", '.') ? {	# does it have any dots
		"${valid_host}" => "${valid_host}.${valid_domain}",
		default => "${valid_host}",		# it had dot(s) present
	}

	$valid_realm = "${realm}" ? {
		'' => "${c}" ? {			# get from $name regexp
			'' => upcase($valid_domain),	# a backup plan default
			default => "${c}",		# got from $name regexp
		},
		default => "${realm}",
	}

	# sanity checking, this should probably not happen
	if "${valid_realm}" == '' {
		fail('The $realm must be specified.')
	}

	$valid_server = "${server}" ? {
		'' => "${ipa::client::valid_server}",
		default => "${server}",
	}

	# sanity checking, this should probably not happen
	if "${valid_server}" == '' {
		fail('The $server must be specified.')
	}

	$valid_principal = "${principal}" ? {
		'' => "${valid_service}/${valid_fqdn}@${valid_realm}",
		default => "${principal}",		# just do what you want
	}

	$valid_keytab = "${keytab}" ? {			# TODO: validate
		'' => '/etc/krb5.keytab',
		default => "${keytab}",
	}

	if $debug {
		notify { "ipa-client-service-${name}":
			message => "Service: '${name}', principal: '${valid_principal}'",
		}
	}

	# TODO: it would be great to put this kinit code into a single class to
	# be used by each service, but it's not easily possible if puppet stops
	# us from declaring identical class objects when they're seen as dupes!
	# there is ensure_resource, but it's a hack and class might not work...
	# NOTE: i added a lifetime of 1 hour... no sense needing any longer
	$rr = "krbtgt/${valid_realm}@${valid_realm}"
	$tl = '900'	# 60*15 => 15 minutes
	$admin = "host/${valid_fqdn}@${valid_realm}"	# use this principal...
	exec { "/usr/bin/kinit -k -t '${valid_keytab}' ${admin} -l 1h":
		logoutput => on_failure,
		#unless => "/usr/bin/klist -s",	# is there a credential cache
		# NOTE: we need to check if the ticket has at least a certain
		# amount of time left. if not, it could expire mid execution!
		# this should definitely get patched, but in the meantime, we
		# check that the current time is greater than the valid start
		# time (in seconds) and that we have within $tl seconds left!
		unless => "/usr/bin/klist -s && /usr/bin/test \$(( `/bin/date +%s` - `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$1\" \"\$2}' | /bin/date --file=- +%s` )) -gt 0 && /usr/bin/test \$(( `/usr/bin/klist | /bin/grep -F '${rr}' | /bin/awk '{print \$3\" \"\$4}' | /bin/date --file=- +%s` - `/bin/date +%s` )) -gt ${tl}",
		require => [
			Package['ipa-client'],
			Exec['ipa-install'],
			Ipa::Client::Host["${valid_host}"],
		],
		alias => "ipa-server-kinit-${name}",
	}

	$args01 = "--server='${valid_server}'"	# contact this KDC server (ipa)
	$args02 = "--principal='${valid_principal}'"	# the service principal
	$args03 = "--keytab='${valid_keytab}'"

	$arglist = ["${args01}", "${args02}", "${args03}"]
	$args = join(delete($arglist, ''), ' ')

	$kvno_bool = "/usr/bin/kvno -q '${valid_principal}'"
	exec { "/usr/sbin/ipa-getkeytab ${args}":
		logoutput => on_failure,
			# check that the KDC has a valid ticket available there
			# check that the ticket version no. matches our keytab!
		unless => "${kvno_bool} && /usr/bin/klist -k -t '${valid_keytab}' | /bin/awk '{print \$4\": kvno = \"\$1}' | /bin/sort | /usr/bin/uniq | /bin/grep -F '${valid_principal}' | /bin/grep -qxF \"`/usr/bin/kvno '${valid_principal}'`\"",
		require => [
			# these deps are done in the kinit
			#Package['ipa-client'],
			#Exec['ipa-install'],
			#Ipa::Client::Host["${valid_host}"],
			Exec["ipa-server-kinit-${name}"],
		],
		#alias => "ipa-getkeytab-${name}",
	}
}

# NOTE: use this to deploy the exported resource @@ipa::client::service
class ipa::client::service::deploy(
	$server = '',
	$nametag = '',				# pick a tag to collect...
	$debug = false
) {

	# NOTE: the resource collects by fqdn; one good reason to use the fqdn!
	# sure you can override this by choosing your own $name value, but why?
	$valid_tag = "${nametag}" ? {
		'' => "${::fqdn}",	# if we're smart, this is what is used!
		default => "${nametag}",
	}

	# the host field is also the argument passed to the exported resource,
	# and it is the $valid_host variable that came from the server service
	if "${server}" == '' {
		Ipa::Client::Service <<| host == "${valid_tag}" |>> {
			debug => $debug,
		}
	} else {
		Ipa::Client::Service <<| host == "${valid_tag}" |>> {
			server => "${server}",	# override...
			debug => $debug,
		}
	}
}

class ipa::server::user::base {
	include ipa::server
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# by default, the following users get installed with freeipa:
	# admin
	# since we don't want to purge them, we need to exclude them...
	$user_always_ignore = ['admin']
	$user_excludes = $ipa::server::user_excludes
	$valid_user_excludes = type($user_excludes) ? {
		'string' => [$user_excludes],
		'array' => $user_excludes,
		'boolean' => $user_excludes ? {
			# TODO: there's probably a better user match expression
			# this is an expression to prevent all user deletion...
			#true => ['^[a-zA-Z0-9]*$'],
			true => ['^[[:alpha:]]{1}[[:alnum:]]*$'],
			default => false,
		},
		default => false,	# trigger error...
	}

	if type($valid_user_excludes) != 'array' {
		fail('The $user_excludes must be an array.')
	}

	# directory of system tags which should exist (as managed by puppet)
	file { "${vardir}/users/":
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		notify => Exec['ipa-clean-users'],
		require => File["${vardir}/"],
	}

	# these are template variables for the clean.sh.erb script
	$id_dir = 'users'
	$ls_cmd = '/usr/bin/ipa user-find --pkey-only --raw | /usr/bin/tr -d " " | /bin/grep "^uid:" | /bin/cut -b 5-'	# show ipa users
	$rm_cmd = '/usr/bin/ipa user-del '	# delete ipa users
	$fs_chr = ' '
	$suffix = '.user'
	$regexp = $valid_user_excludes
	$ignore = $user_always_ignore

	# build the clean script
	file { "${vardir}/clean-users.sh":
		content => template('ipa/clean.sh.erb'),
		owner => root,
		group => nobody,
		mode => 700,			# u=rwx
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => File["${vardir}/"],
	}

	# run the cleanup
	exec { "${vardir}/clean-users.sh":
		logoutput => on_failure,
		refreshonly => true,
		require => [
			Exec['ipa-server-kinit'],
			File["${vardir}/clean-users.sh"],
		],
		alias => 'ipa-clean-users',
	}

	file { "${vardir}/users/passwords/":	# for storing random passwords
		ensure => directory,		# make sure this is a directory
		recurse => true,		# recursively manage directory
		purge => true,			# purge all unmanaged files
		force => true,			# also purge subdirs and links
		owner => root, group => nobody, mode => 600, backup => false,
		require => File["${vardir}/users/"],
	}
}

define ipa::server::user(	# $login or principal as a unique id
	$login = '',		# usually the same as $name, but set manually
	$instance = '',		# as in: user/instance@REALM
	$domain = '',		# must be the empty string by default
	$realm = '',
	$principal = true,	# after all that, you can override principal...

	# name args
	$first = '',		# required
	$last = '',		# required
	$cn = true,		# full name, defaults to "$first $last"
	$displayname = true,	# defaults to "$first $last"
	$initials = true,	# defaults to $first[0]+$last[0]

	# some of these parameters can be strings, arrays, or boolean specials!
	$email = true,		# comes with a sensible default (false = no)
	$gecos = true,		# old style passwd field, can be set manually

	# special characteristics
	$uid = true,		# either pick a value, or let system assign it!
	$gid = true,		# true means try to match $uid value on create!
	$shell = true,
	$home = true,
	$sshpubkeys = false,

	# password
	$random = false,	# set to true to have the password generated...
	$password_file = false,	# save to file in ${vardir}/ipa/users/passwords/
	$password_mail = false,	# TODO: mail a gpg encrypted password to admin!

	# mailing address section (just plain strings, false is unmanaged)
	$street = false,	# street address
	$city = false,		# city
	$state = false,		# state/province
	$postalcode = false,	# zip/postal code

	# these four accept arrays or a string. false means unmanaged...
	$phone = false,		# telephone number
	$mobile = false,	# mobile telephone number
	$pager = false,		# pager number
	$fax = false,		# fax number

	# other information
	$jobtitle = false,	# job title
	$orgunit = false,	# org. unit (department)
	$manager = false,	# manager (should match an existing user $name)
	$carlicense = false,	# car license (who cares?)

	#$hosts = [],		# TODO: add hosts managed by support if exists!

	# special parameters...
	$watch = true,	# manage all changes to this resource, reverting others
	$modify = true,	# modify this resource on puppet changes or not ?
	$comment = '',
	$ensure = present	# TODO
) {
	include ipa::server
	include ipa::server::user::base
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	# TODO: a better regexp magician could probably do a better job :)
	# james/admin@EXAMPLE.COM
	# james@EXAMPLE.COM
	# james
	$r = '^([a-zA-Z][a-zA-Z0-9]*)((/([a-zA-Z][a-zA-Z0-9]*)){0,1}@([A-Z][A-Z\.\-]*)){0,1}$'

	$a = regsubst("${name}", $r, '\1')	# login (james)
	$b = regsubst("${name}", $r, '\4')	# instance (admin)
	$c = regsubst("${name}", $r, '\5')	# realm (EXAMPLE.COM)

	# user: first try to get value from arg, then fall back to $a (name)
	$valid_login = "${login}" ? {
		'' => "${a}",				# get from $name regexp
		default => "${login}",
	}
	if "${valid_login}" == '' {
		# NOTE: if we see this message it might be a regexp pattern bug
		fail('The $login must be specified.')
	}

	# host: first try to get value from arg, then fall back to $b
	# this is not necessarily the group, but it could be. both are possible
	# empty values are allowed and possibly even common :)
	$valid_instance = "${instance}" ? {
		'' => "${b}",				# get from $name regexp
		default => "${instance}",
	}

	$valid_domain = "${domain}" ? {
		'' => "${ipa::server::domain}" ? {		# NOTE: server!
			'' => "${::domain}",		# default to global val
			default => "${ipa::server::domain}",		# main!
		},
		default => "${domain}",
	}

	# this error condition is very important because '' is used as trigger!
	if "${valid_domain}" == '' {
		fail('The $domain must be specified.')
	}

	$valid_realm = "${realm}" ? {
		'' => "${c}" ? {			# get from $name regexp
			'' => upcase($valid_domain),	# a backup plan default
			default => "${c}",		# got from $name regexp
		},
		default => "${realm}",
	}

	# sanity checking, this should probably not happen
	if "${valid_realm}" == '' {
		fail('The $realm must be specified.')
	}

	# to be used if principal is generated from the available entered data!
	$auto_principal = "${valid_instance}" ? {
		'' => "${valid_login}@${valid_realm}",	# no instance !
		default => "${valid_login}/${valid_instance}@${valid_realm}",
	}

	$valid_principal = type($principal) ? {
		'string' => "${principal}" ? {
			'' => "${auto_principal}",
			default => "${principal}",	# just do what you want
		},
		'boolean' => $principal ? {
			false => '',	# don't use a principal
			default => "${auto_principal}",
		},
		default => '',
	}

	if $watch and (! $modify) {
		fail('You must be able to $modify to be able to $watch.')
	}

	if "${first}" == '' {
		fail("The first name is required for: '${valid_login}'.")
	}
	if "${last}" == '' {
		fail("The last name is required for: '${valid_login}'.")
	}

	$args01 = "${first}" ? {
		'' => '',
		default => "--first='${first}'",
	}
	$args02 = "${last}" ? {
		'' => '',
		default => "--last='${last}'",
	}

	$args03 = type($cn) ? {
		'string' => "--cn='${cn}'",
		'boolean' => $cn ? {
			false => '',
			default => "--cn='${first} ${last}'",
		},
		default => '',
	}

	$args04 = type($displayname) ? {
		'string' => "--displayname='${displayname}'",
		'boolean' => $displayname ? {
			false => '',
			default => "--displayname='${first} ${last}'",
		},
		default => '',
	}

	$args05 = type($initials) ? {
		'string' => "--initials='${displayname}'",
		'boolean' => $initials ? {
			false => '',
			# NOTE: [0,1] is a version robust way to get index 0...
			default => sprintf("--initials='%s'", inline_template('<%= first[0,1]+last[0,1] %>')),
		},
		default => '',
	}

	# email can provide a sensible default
	$default_email_domain = $ipa::server::default_email_domain
	$valid_email = type($email) ? {
		'string' => "${email}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${email}"],
		},
		'array' => $email,
		'boolean' => $email ? {
			false => '',	# unmanaged
			default => ["${valid_login}@${default_email_domain}"],	# sensible default
		},
		default => '',	# unmanaged
	}
	$args06 = type($valid_email) ? {
		'array' => inline_template('<% if valid_email == [] %>--email=<% else %><%= valid_email.map {|x| "--email=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	$args07 = type($gecos) ? {
		'string' => "--gecos='${gecos}'",
		'boolean' => $gecos ? {
			false => '',
			default => "--gecos='${first} ${last}'",
		},
		default => '',
	}

	# TODO: validate id ranges ?
	$args08 = type($uid) ? {
		'string' => "--uid='${uid}'",
		'integer' => "--uid='${uid}'",
		default => '',
	}

	# TODO: validate id ranges ?
	$args09 = type($gid) ? {
		'string' => "--gidnumber='${gid}'",
		'integer' => "--gidnumber='${gid}'",
		'boolean' => $gid ? {
			false => '',
			default => type($uid) ? {	# auto try to match uid
				'string' => "--gidnumber='${uid}'",	# uid !
				'integer' => "--gidnumber='${uid}'",	# uid !
				default => '',	# auto
			},
		},
		default => '',
	}

	$default_shell = $ipa::server::default_shell
	$args10 = type($shell) ? {
		'string' => "--shell='${shell}'",
		'boolean' => $shell ? {
			false => '',
			default => "--shell='${default_shell}'",
		},
		default => '',
	}

	# TODO: the home stuff seems to not use trailing slashes. can i add it?
	$default_homes = $ipa::server::default_homes
	$args11 = type($home) ? {
		'string' => sprintf("--homedir='%s'", regsubst("${home}" , '\/$', '')),
		'boolean' => $home ? {
			false => '',
			default => type($default_homes) ? {
				'string' => sprintf("--homedir='%s/${valid_login}'", regsubst("${default_homes}" , '\/$', '')),
				# TODO: warning ?
				default => '',	# can't manage, parent is false
			},
		},
		default => '',
	}

	# users individual ssh public keys
	$valid_sshpubkeys = type($sshpubkeys) ? {
		'string' => "${sshpubkeys}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${sshpubkeys}"],
		},
		'array' => $sshpubkeys,
		default => '',	# unmanaged
	}
	$args12 = type($valid_sshpubkeys) ? {
		'array' => inline_template('<% if valid_sshpubkeys == [] %>--sshpubkey=<% else %><%= valid_sshpubkeys.map {|x| "--sshpubkey=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	# mailing address section
	$args13 = type($street) ? {
		'string' => "--street='${street}'",
		'boolean' => $street ? {
			true => '--street=',	# managed
			default => '',		# unmanaged
		},
		default => '',			# whatever and unmanaged
	}

	$args14 = type($city) ? {
		'string' => "--city='${city}'",
		'boolean' => $city ? {
			true => '--city=',
			default => '',
		},
		default => '',
	}

	$args15 = type($state) ? {	# or province
		'string' => "--state='${state}'",
		'boolean' => $state ? {
			true => '--state=',
			default => '',
		},
		default => '',
	}

	$args16 = type($postalcode) ? {
		'string' => "--postalcode='${postalcode}'",
		'boolean' => $postalcode ? {
			true => '--postalcode=',
			default => '',
		},
		default => '',
	}

	# the following four phone number types can be arrays
	$valid_phone = type($phone) ? {
		'string' => "${phone}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${phone}"],
		},
		'array' => $phone,
		default => '',	# unmanaged
	}
	$args17 = type($valid_phone) ? {
		'array' => inline_template('<% if valid_phone == [] %>--phone=<% else %><%= valid_phone.map {|x| "--phone=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	$valid_mobile = type($mobile) ? {
		'string' => "${mobile}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${mobile}"],
		},
		'array' => $mobile,
		default => '',	# unmanaged
	}
	$args18 = type($valid_mobile) ? {
		'array' => inline_template('<% if valid_mobile == [] %>--mobile=<% else %><%= valid_mobile.map {|x| "--mobile=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	$valid_pager = type($pager) ? {
		'string' => "${pager}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${pager}"],
		},
		'array' => $pager,
		default => '',	# unmanaged
	}
	$args19 = type($valid_pager) ? {
		'array' => inline_template('<% if valid_pager == [] %>--pager=<% else %><%= valid_pager.map {|x| "--pager=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	$valid_fax = type($fax) ? {
		'string' => "${fax}" ? {
			'' => [],	# assume managed but empty (rm values)
			default => ["${fax}"],
		},
		'array' => $fax,
		default => '',	# unmanaged
	}
	$args20 = type($valid_fax) ? {
		'array' => inline_template('<% if valid_fax == [] %>--fax=<% else %><%= valid_fax.map {|x| "--fax=\'"+x+"\'" }.join(" ") %><% end %>'),
		default => '',	# unmanaged
	}

	# other information
	$args21 = type($jobtitle) ? {	# job title
		'string' => "--title='${jobtitle}'",
		'boolean' => $jobtitle ? {
			true => '--title=',
			default => '',
		},
		default => '',
	}

	$args22 = type($orgunit) ? {
		'string' => "--orgunit='${orgunit}'",
		'boolean' => $orgunit ? {
			true => '--orgunit=',
			default => '',
		},
		default => '',
	}

	# manager requires user exists... this lets us match a user principal
	$valid_manager = regsubst("${manager}", $r, '\1')	# login (james)
	$args23 = type($manager) ? {	# this has to match an existing user...
		'string' => "--manager='${valid_manager}'",
		'boolean' => $manager ? {
			true => '--manager=',
			default => '',
		},
		default => '',
	}

	$args24 = type($carlicense) ? {
		'string' => "--carlicense='${carlicense}'",
		'boolean' => $carlicense ? {
			true => '--carlicense=',
			default => '',
		},
		default => '',
	}

	$arglist = ["${args01}", "${args02}", "${args03}", "${args04}", "${args05}", "${args06}", "${args07}", "${args08}", "${args09}", "${args10}", "${args11}", "${args12}", "${args13}", "${args14}", "${args15}", "${args16}", "${args17}", "${args18}", "${args19}", "${args20}", "${args21}", "${args22}", "${args23}", "${args24}"]
	$args = join(delete($arglist, ''), ' ')

	# switch bad characters for file name friendly characters (unused atm!)
	# this could be useful if we allow login's with $ and others in them...
	$valid_login_file = regsubst("${valid_login}", '\$', '-', 'G')
	file { "${vardir}/users/${valid_login_file}.user":
		content => "${valid_login}\n${args}\n",
		owner => root,
		group => nobody,
		mode => 600,	# u=rw,go=
		require => File["${vardir}/users/"],
		ensure => present,
	}

	if $random and $password_file {
		file { "${vardir}/users/passwords/${valid_login}.password":
			# no content! this is a tag, content comes in by echo !
			owner => root,
			group => nobody,
			mode => 600,	# u=rw,go=
			backup => false,
			require => File["${vardir}/users/passwords/"],
			ensure => present,
		}
	}

	$exists = "/usr/bin/ipa user-show '${valid_login}' > /dev/null 2>&1"
	# this requires ensures the $manager user exists when we can check that
	# this melds together the kinit require which is needed by the user add
	$requires = type($manager) ? {
		'string' => "${manager}" ? {
			'' => Exec['ipa-server-kinit'],
			default => $watch ? {
				false => Exec['ipa-server-kinit'],
				default => [
					Exec['ipa-server-kinit'],
					Ipa::Server::User["${manager}"],
				],
			},
		},
		default => Exec['ipa-server-kinit'],
	}

	# principal is only set on user add... it can't be edited afaict
	$principal_arg = "${valid_principal}" ? {	# not shown in ipa gui!
		'' => '',
		default => "--principal='${valid_principal}'",
	}

	$aargs = "${principal_arg}" ? {			# principal exists
		'' => "${args}",			# just normal args
		default => "${principal_arg} ${args}",	# pixel perfect...
	}

	# NOTE: this runs when no user is present...
	exec { "ipa-server-user-add-${name}":	# alias
		# this has to be here because the command string gets too long
		# for a puppet $name var and strange things start to happen...
		command => "/usr/bin/ipa user-add '${valid_login}' ${aargs}",
		logoutput => on_failure,
		unless => "${exists}",
		require => $requires,
	}

	# NOTE: this runs when we detect that the attributes don't match (diff)
	if $modify and ("${args}" != '') {	# if there are changes to do...
		#exec { "/usr/bin/ipa user-mod '${valid_login}' ${args}":
		exec { "ipa-server-user-mod-${name}":
			command => "/usr/bin/ipa user-mod '${valid_login}' ${args}",
			logoutput => on_failure,
			refreshonly => $watch ? {
				false => true,		# when not watching, we
				default => undef,	# refreshonly to change
			},
			subscribe => $watch ? {
				false => File["${vardir}/users/${valid_login_file}.user"],
				default => undef,
			},
			onlyif => "${exists}",
			unless => $watch ? {
				false => undef,	# don't run the diff checker...
				default => "${exists} && ${vardir}/diff.py user '${valid_login}' ${args}",
			},
			require => [
				File["${vardir}/diff.py"],
				Exec['ipa-server-kinit'],
				# this user-add exec pulls in manager $requires
				Exec["ipa-server-user-add-${name}"],
			],
			#alias => "ipa-server-user-mod-${name}",
		}
	}

	$prog01 = $password_file ? {
		true => "/bin/cat > ${vardir}/users/passwords/${valid_login}.password",
		default => '',
	}

	$gpg_email = $ipa::server::valid_email	# admin email
	#$gpg_key = $ipa::server::TODO
	$prog02 = $password_mail ? {
		#true => "/bin/cat | /usr/bin/gpg TODO | /bin/mailx -s 'GPG encrypted password' '${gpg_email}'",	# FIXME: add this code!
		default => '',
	}

	if $modify and $random {
		$proglist = ["${prog01}", "${prog02}"]
		# eg /usr/bin/tee /dev/null >(prog1) >(prog2) >(progN)
		$progs = join(suffix(prefix(delete($proglist, ''), '>('), ')'), ' ')
		exec { "ipa-server-user-qmod-${name}":
			# bash -c is needed because this command uses bashisms!
			command => "/bin/bash -c \"/usr/bin/ipa user-mod '${valid_login}' --raw --random | /usr/bin/tr -d ' ' | /bin/grep '^randompassword:' | /bin/cut -b 16- | /usr/bin/tee /dev/null ${progs}\"",
			logoutput => on_failure,
			onlyif => "/usr/bin/test \"`/usr/bin/ipa user-show '${valid_login}' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_password:' | /bin/cut -b 14-`\" = 'False'",
			require => [
				Exec['ipa-server-kinit'],
				Exec["ipa-server-user-add-${name}"],
				#Exec["ipa-server-user-mod-${name}"],	# not needed...
			],
			#alias => "ipa-server-user-qmod-${name}",
		}
	}
}

# NOTE: use this to deploy all the @@ipa::client::* exported resources on clients
# the $nametag variable should match the $name value of the server/client::host
class ipa::client::deploy(
	$hostname = $::hostname,
	$domain = $::domain,
	$server = '',
	$nametag = '',				# pick a tag to collect...
	$debug = false
) {
	$valid_domain = downcase($domain)	# TODO: validate ?

	# if $hostname has dots, then assume it's a fqdn, if not, we add $domain
	$valid_fqdn = delete("${hostname}", '.') ? {
		"${hostname}" => "${hostname}.${valid_domain}",	# had no dots present
		default => "${hostname}",			# had dots present...
	}

	# NOTE: the resource collects by fqdn; one good reason to use the fqdn!
	# sure you can override this by choosing your own $name value, but why?
	$valid_tag = "${nametag}" ? {
		'' => "${valid_fqdn}",
		default => "${nametag}",
	}

	# TODO: if i had more than one arg to decide to override, then i would
	# have to build a big tree of nested choices... this is one more place
	# where puppet shows it's really not a mature language yet. oh well...
	# the host field is also the argument passed to the exported resource,
	# and it is the $valid_host variable that came from the server service
	if "${server}" == '' {
		Ipa::Client::Host <<| tag == "${valid_tag}" |>> {
			debug => $debug,
		}
		Ipa::Client::Service <<| host == "${valid_tag}" |>> {
			debug => $debug,
		}
	} else {
		Ipa::Client::Host <<| tag == "${valid_tag}" |>> {
			server => "${server}",	# override...
			debug => $debug,
		}
		Ipa::Client::Service <<| host == "${valid_tag}" |>> {
			server => "${server}",	# override...
			debug => $debug,
		}
	}
}

