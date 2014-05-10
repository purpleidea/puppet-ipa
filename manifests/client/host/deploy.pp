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

# vim: ts=8
