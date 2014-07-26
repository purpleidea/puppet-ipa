# Simple ipa templating module by James
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

# NOTE: this fact creates boolean string values that others can read for status
require 'facter'

# regexp to match an fqdn pattern, eg: ipa1.example.com
regexp = /^[a-zA-Z]{1}[a-zA-Z0-9\.\-]{0,}$/	# TODO: is this right ?
prefix = 'master_'

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
	# if we can't get a valid vardirtmp, then we can't collect...
	valid_dir = nil
	masterdir = nil
else
	module_vardir = var+'ipa/'
	valid_dir = module_vardir.gsub(/\/$/, '')+'/'
	masterdir = module_vardir+'replica/master/'
end

# create fact from self-proclaimed master... needed to know who first installed
found = ''

if not(masterdir.nil?) and File.directory?(masterdir)
	Dir.glob(masterdir+prefix+'*').each do |f|

		b = File.basename(f)
		# strip off leading prefix
		fqdn = b[prefix.length, b.length-prefix.length]

		master = File.open(f, 'r').read.strip.downcase	# read into str
		if master.length > 0 and regexp.match(master)
			# avoid: http://projects.puppetlabs.com/issues/22455

			if master != fqdn
				# FIXME: error: i think these should match...
				puts 'ERROR'
			end

			if found != ''
				# FIXME: error, already found...
				puts 'ERROR'
			end

			found = master	# save
			#break	# there should only be one, so no need to break
		# TODO: print warning on else...
		end
	end
end

# put the fqdn of the zero-th replica (the master) into a fact... look first in
# the local installation tag, and then in the found exported file if one exists
# it's inefficient to read the exported file a second time, but simpler to code
["#{valid_dir}ipa_server_replica_master", "#{masterdir}#{prefix}#{found}"].each do |key|
	if File.exists?(key)
		master = File.open(key, 'r').read.strip.downcase	# read into str
		if master.length > 0 and regexp.match(master)

			Facter.add('ipa_server_replica_master') do
				#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
				setcode do
					Facter::Util::Resolution.exec("/bin/cat '"+key+"'")
				end
			end
			break	# there can only be one...
		end
	end
end

# vim: ts=8
