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
else
	module_vardir = var+'ipa/'
	valid_dir = module_vardir.gsub(/\/$/, '')+'/'
end

if not(valid_dir.nil?) and File.directory?(valid_dir)
	['ipa_client_installed', 'ipa_server_installed'].each do |key|
		f = valid_dir+''+key	# the full file path
		if File.exists?(f)
			# NOTE: sadly, empty string facts don't work :(
			Facter.add(key) do
				#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
				setcode do
					Facter::Util::Resolution.exec("/bin/cat '"+f+"'")
				end
			end
		end
	end
end

# vim: ts=8
