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
					"/usr/bin/test \"`/usr/bin/ipa host-show '${valid_fqdn}' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_password:' | /bin/cut -b 14- | /usr/bin/tr '[:upper:]' '[:lower:]'`\" = 'false'",
					"/usr/bin/test \"`/usr/bin/ipa host-show '${valid_fqdn}' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_keytab:' | /bin/cut -b 12- | /usr/bin/tr '[:upper:]' '[:lower:]'`\" = 'false'",
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

# vim: ts=8
