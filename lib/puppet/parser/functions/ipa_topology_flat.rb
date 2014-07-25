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

# TODO: is 'flat' the correct topological name for what this algorithm outputs?

module Puppet::Parser::Functions
	newfunction(:ipa_topology_flat, :type => :rvalue, :doc => <<-'ENDHEREDOC') do |args|
		Return an ipa N-N topology from a sorted list of hosts

		Example:

			$valid_peers = ipa_topology_flat($peers)
			notice("valid peers is: ${valid_peers}")

		This function is used internally for building automatic topologies.

		ENDHEREDOC

		Puppet::Parser::Functions.function('warning')	# load function
		# signature: replica, bricks -> bricks
		unless args.length == 1
			raise Puppet::ParseError, "ipa_topology_flat(): wrong number of arguments (#{args.length}; must be 1)"
		end
		if not(args[0].is_a?(Array))
			raise Puppet::ParseError, "ipa_topology_flat(): expects the first argument to be an array, got #{args[0].inspect} which is of type #{args[0].class}"
		end

		peers = args[0]

		if peers.uniq.length != peers.length	# there are duplicates!
			raise Puppet::ParseError, "ipa_topology_flat(): duplicates were found in the first argument!"
		end

		# NOTE: need at least one
		if peers.length < 1
			function_warning(["ipa_topology_flat(): peer list is empty"])
			return {}
		end

		# if we only have one peer, and it's me, then topology is empty
		if peers.length == 1 and peers[0] == lookupvar('fqdn')
			return {}
		end

		result = {}

		peers.each do |x|

			same = peers.dup	# copy... to not destroy peers!
			if same.delete(x).nil?	# normally returns the value...
				# TODO: return programming error: delete failed
			end

			# connect to every peer except yourself
			result[x] = same

		end

		result	# return
	end
end

# vim: ts=8
