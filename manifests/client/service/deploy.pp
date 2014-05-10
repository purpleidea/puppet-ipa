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

# vim: ts=8
