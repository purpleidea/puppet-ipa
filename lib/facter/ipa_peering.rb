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

require 'facter'

# regexp to match an fqdn pattern, eg: ipa1.example.com
regexp = /^[a-zA-Z]{1}[a-zA-Z0-9\.\-]{0,}$/	# TODO: is this right ?
prefix = 'peer_'

# find the module_vardir
dir = Facter.value('puppet_vardirtmp')		# nil if missing
if dir.nil?					# let puppet decide if present!
	dir = Facter.value('puppet_vardir')
	if dir.nil?
		var = nil
	else
		var = dir.gsub(/\/$/, '')+'/'+'tmp/'	# ensure trailing slash
	end
else
	var = dir.gsub(/\/$/, '')+'/'
end

if var.nil?
	# if we can't get a valid vardirtmp, then we can't continue
	module_vardir = nil
	peerdir = nil
else
	module_vardir = var+'ipa/'
	peerdir = module_vardir+'replica/peering/'
end

# create facts from externally collected peer files
peer = ''
found = []
if not(peerdir.nil?) and File.directory?(peerdir)
	Dir.glob(peerdir+prefix+'*').each do |f|

		b = File.basename(f)
		# strip off leading prefix
		fqdn = b[prefix.length, b.length-prefix.length]
		peer = File.open(f, 'r').read.strip.downcase	# read into str
		if peer.length > 0 and regexp.match(peer) and peer == fqdn
			# avoid: http://projects.puppetlabs.com/issues/22455
			found.push(peer)
		# TODO: print warning on else...
		end
	end
end

# FIXME: alternatively, each host could have a "create" time, and they could be
# sorted according to that time first, and alphabetically second... the idea is
# to be able to provide a consistent ordering that doesn't change with joins...
Facter.add('ipa_server_replica_peers') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		found.sort.join(',')
	}
end

# vim: ts=8
