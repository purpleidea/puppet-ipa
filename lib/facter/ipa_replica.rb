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
prefix = 'replica-info-'
ending = '.gpg'

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
	valid_replicadir = nil
else
	module_vardir = var+'ipa/'
	valid_replicadir = module_vardir.gsub(/\/$/, '')+'/replica/install/'
end

found = []

if not(valid_replicadir.nil?) and File.directory?(valid_replicadir)
	Dir.glob(valid_replicadir+prefix+'*'+ending).each do |f|
		b = File.basename(f)

		g = b.slice(prefix.length, b.length-prefix.length-ending.length)

		if g.length > 0 and regexp.match(g)
			if not found.include?(g)
				found.push(g)
			end
		# TODO: print warning on else...
		end
	end
end

Facter.add('ipa_replica_prepared_fqdns') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		# TODO: facter should support native list types :)
		found.sort.join(',')
	}
end

# vim: ts=8
