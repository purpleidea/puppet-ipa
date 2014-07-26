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

# NOTE: this fact creates the one time password facts, needed to be exported...
require 'facter'

suffix = '.password'
found = []						# create list of values

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
	valid_hostpassdir = nil
else
	module_vardir = var+'ipa/'
	hostpassdir = module_vardir+'hosts/passwords/'
	valid_hostpassdir = hostpassdir.gsub(/\/$/, '')+'/'
end

if not(valid_hostpassdir.nil?) and File.directory?(valid_hostpassdir)
	Dir.glob(valid_hostpassdir+'*'+suffix).each do |f|
		b = File.basename(f)
		g = b.split('.')	# $name.password
		if g.length >= 2 and ('.'+g.pop()) == suffix
			x = g.join('.')	# in case value had dots in it.

			#has_password = Facter::Util::Resolution.exec("/usr/bin/ipa host-show '"+x+"' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_password:' | /bin/cut -b 14- | /usr/bin/tr '[A-Z]' '[a-z]'") or 'nil'
			key = ('ipa_host_'+x+'_password').gsub(/\./, '_')
			found.push(key)	# make a list of keys

			# NOTE: sadly, empty string facts don't work :(
			Facter.add(key) do
				#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
				setcode do
					Facter::Util::Resolution.exec("/bin/cat '"+f+"'")
					# single equals sign for test !
					#Facter::Util::Resolution.exec("/usr/bin/test \"`/usr/bin/ipa host-show '"+x+"' --raw | /usr/bin/tr -d ' ' | /bin/grep '^has_password:' | /bin/cut -b 14-`\" = 'True' && /bin/cat '"+f+"'")
				end
			end
		end
	end
end

# make a list of keys... might be useful and helps to know this fact is working
Facter.add('ipa_host_passwords') do
	#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
	setcode {
		found.join(',')
	}
end

# vim: ts=8
