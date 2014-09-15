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

require 'facter'

# get the yum path. this fact can come from an external fact set in: params.pp
yum = Facter.value('ipa_program_yum').to_s.chomp
if yum == ''
	yum = `which yum 2> /dev/null`.chomp
	if yum == ''
		yum = '/usr/bin/yum'
	end
end

ipa = Facter.value('ipa_package_ipa_server').to_s.chomp
if ipa == ''
	ipa = 'ipa-server'
end

#confine :operatingsystem => %w{CentOS, RedHat, Fedora}
# TODO: add a long TTL to avoid repeated yum noise
cmdout = Facter::Util::Resolution.exec(yum+" info "+ipa+" 2> /dev/null | /bin/grep '^Version' | /bin/awk -F ':' '{print $2}'")
if cmdout != nil
	Facter.add('ipa_version') do
		setcode {
			cmdout.strip
		}
	end
end

# vim: ts=8
