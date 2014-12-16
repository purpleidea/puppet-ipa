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

# FIXME: some values have not been filled in yet. some are missing: --arguments
define ipa::server::config(
	$value
) {
	include ipa::common

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
		logoutput => on_failure,
		onlyif => "${::ipa::common::ipa_installed}",
		unless => "/usr/bin/test \"`/usr/bin/ipa config-show --raw --all | /usr/bin/tr -d ' ' | /bin/grep -i '^${rawkey}:' | /bin/cut -b ${cutlength}- | /usr/bin/paste -sd '${jchar}'`\" = '${safe_value}'",
		require => [
			Exec['ipa-install'],
			Exec['ipa-server-kinit'],
		],
	}
}

# vim: ts=8
