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

# uuid regexp
regexp = /^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$/
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
	uuidfile = nil
else
	module_vardir = var+'ipa/'
	peerdir = module_vardir+'replica/peering/'
	uuidfile = peerdir+'uuid'
end

# NOTE: module specific mkdirs, needed to ensure there is no blocking/deadlock!
if not(var.nil?) and not File.directory?(var)
	Dir::mkdir(var)
end

if not(module_vardir.nil?) and not File.directory?(module_vardir)
	Dir::mkdir(module_vardir)
end

if not(peerdir.nil?) and not File.directory?(peerdir)
	Dir::mkdir(File.expand_path('..', peerdir))
	Dir::mkdir(peerdir)
end

# NOTE: each host is given a "uuidgen -t" based create time and they are sorted
# according to that time first, and alphabetically second. the idea is that the
# chronological order provides a consistent, but decentralized ordering that is
# needed so that subsequent joins are always sorted to the end of the uuid list

# generate uuid and parent directory if they don't already exist...
if not(module_vardir.nil?) and File.directory?(module_vardir)

	create = false
	# create a uuid and store it in our vardir if it doesn't already exist!
	if File.directory?(peerdir)

		if File.exist?(uuidfile)
			test = File.open(uuidfile, 'r').read.strip.downcase	# read into str
			# skip over uuid's of the wrong length or that don't match (security!!)
			if test.length == 36 and regexp.match(test)
				create = false
			else
				create = true
			end
		else
			create = true
		end
	end

	if create
		# NOTE: this is a time based uuid !
		result = system("/usr/bin/uuidgen -t > '" + uuidfile + "'")
		if not(result)
			# TODO: print warning
		end
	end
end

# create the fact if the uuid file contains a valid uuid
if not(uuidfile.nil?) and File.exist?(uuidfile)
	uuid = File.open(uuidfile, 'r').read.strip.downcase	# read into str
	# skip over uuid's of the wrong length or that don't match (security!!)
	if uuid.length == 36 and regexp.match(uuid)
		Facter.add('ipa_server_replica_uuid') do
			#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
			setcode {
				# don't reuse uuid variable to avoid bug #:
				# http://projects.puppetlabs.com/issues/22455
				uuid
			}
		end
	# TODO: print warning on else...
	end
end

# create facts from externally collected peer files
peer = ''
found = {}
if not(peerdir.nil?) and File.directory?(peerdir)
	Dir.glob(peerdir+prefix+'*').each do |f|

		b = File.basename(f)
		# strip off leading prefix
		fqdn = b[prefix.length, b.length-prefix.length]

		peer = File.open(f, 'r').read.strip.downcase	# read into str
		if peer.length > 0 and regexp.match(peer)
			# avoid: http://projects.puppetlabs.com/issues/22455
			found[fqdn] = peer
		# TODO: print warning on else...
		end
	end
end

# FIXME: ensure that this properly sorts by uuidgen -t times...
# sort chronologically by time based uuid
# thanks to: Pádraig Brady for the sort implementation...
sorted = found.inject({}){ |h,(k,v)| h[k]=v.split('-'); h }.sort_by { |k,v| [v[2], v[1], v[0], v[3], v[4]] }.map { |x| x[0] }

sorted.each do |x|
	Facter.add('ipa_server_replica_uuid_'+x) do
		#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
		setcode {
			found[x]
		}
	end
end

# list of generated ipa_server_replica_uuid's
Facter.add('ipa_server_replica_uuid_facts') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		sorted.collect {|x| 'ipa_server_replica_uuid_'+x }.join(',')
	}
end

Facter.add('ipa_server_replica_peers') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		sorted.join(',')
	}
end

# vim: ts=8
