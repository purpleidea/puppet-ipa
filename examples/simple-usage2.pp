# here is some basic usage of the ipa module, now with services!

# on the ipa server:
$domain = $::domain
class { '::ipa::server':
	domain => "${domain}",
	shorewall => true,	# uses my puppet-shorewall module
}

ipa::server::host { 'nfs':	# NOTE: adding .${domain} is a good idea....
	domain => "${domain}",
	macaddress => "00:11:22:33:44:55",
	random => true,		# set a one time password randomly
	locality => 'Montreal, Canada',
	location => 'Room 641A',
	platform => 'Supermicro',
	osstring => 'CentOS 6.4 x86_64',
	comment => 'Simple NFSv4 Server',
	watch => true,	# read and understand the docs well
}

ipa::server::service { 'nfs':	# this $name should match nfs::server => $ipa
	service => 'nfs',
	host => 'nfs',		# needs to match ipa::server::host $name
	domain => "${domain}",	# used to figure out realm
}

ipa::server::host { 'test1':
	domain => "${domain}",
	password => 'password',
	watch => true,	# read and understand the docs well
}


# and on the nfs server (an ipa client):
class { '::ipa::client::deploy':
	nametag => 'nfs',	# needs to match the ipa:server:host $name
}

# if you use fqdn's for the ipa:server:host $name's, then you can deploy with:
#include ipa::client::host::deploy

# there is now a single "deploy" which can be used for both hosts and services!
include ipa::client::deploy

