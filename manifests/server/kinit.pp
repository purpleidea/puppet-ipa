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

# FIXME: can we rename this to ipa::kinit and merge with the ipa client kinit ?

class ipa::server::kinit(
	$realm
) {

	include ipa::common

	$valid_realm = "${realm}"

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
		onlyif => "${::ipa::common::ipa_installed}",
		# NOTE: we need the 'require' to actually be a 'before', coming
		# from the ipa-install exec since that may not exist right away
		# if it's a replica that pulls in the exported resource exec...
		require => [
			Exec['ipa-install'],
			#File["${vardir}/admin.password"],
		],
		alias => 'ipa-server-kinit',
	}
}

# vim: ts=8
