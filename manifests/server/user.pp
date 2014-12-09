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

	# TODO: user @abraverm asked about if we could just $watch, but instead of
	# modifying, just alert the admin, so they could update their own data
	# storage, or alternatively send them a hiera data patch with the change...
	# well, yes this could be possible, but i'm not writing the patch right now
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

# vim: ts=8
