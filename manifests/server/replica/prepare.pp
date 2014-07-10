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

# $name is the fqdn of the server we are preparing for
define ipa::server::replica::prepare(
) {

	include ipa::server::replica::prepare::base
	include ipa::common
	include ipa::vardir
	#$vardir = $::ipa::vardir::module_vardir	# with trailing slash
	$vardir = regsubst($::ipa::vardir::module_vardir, '\/$', '')

	$valid_fqdn = "${name}"	# TODO: validate

	$filename = "replica-info-${valid_fqdn}.gpg"
	$filedest = "replica-info-${::fqdn}.gpg"	# name it with our fqdn
	$prepared = "/var/lib/ipa/${filename}"
	$valid_file = "${vardir}/replica/prepare/${filename}"

	# TODO: ipa-replica-prepare should allow you to pick output path/file
	exec { "/usr/sbin/ipa-replica-prepare --password=`/bin/cat '${vardir}/dm.password'` ${valid_fqdn} && /bin/mv -f '${prepared}' '${valid_file}'":
		logoutput => on_failure,
		creates => "${valid_file}",
		onlyif => "${::ipa::common::ipa_installed}",
		# ipa-server-install or ipa-replica-install must execute first!
		require => Exec['ipa-install'],	# same alias for either install
		alias => "ipa-replica-prepare-${name}",
	}

	# tag this file so it doesn't get purged
	file { "${valid_file}":
		owner => root,
		group => nobody,
		mode => 600,			# u=rw
		backup => false,		# don't backup to filebucket
		ensure => present,
		require => Exec["ipa-replica-prepare-${name}"],
	}

	# add this manually so we don't have to wait for the exported resources
	ssh::recv { "${valid_fqdn}":

	}

	# use a pull, so the remote path is decided over *there*
	# export (@@) the pull, so that it knows the file is already here...
	@@ssh::file::pull { "ipa-replica-prepare-${::fqdn}-${name}":
		user => 'root',				# src user
		host => "${::fqdn}",			# src host
		file => "${valid_file}",		# src file
		path => "${vardir}/replica/install/",	# dest path; overridden
		dest => "${filedest}",			# dest file
		verify => false,			# rely on mtime
		pair => false,			# do it now so it happens fast!
		tag => 'ipa-replica-prepare',	# TODO: can be used as grouping
	}
}

# vim: ts=8
