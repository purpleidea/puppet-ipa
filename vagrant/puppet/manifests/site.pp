node default {
	# this will get put on every host...
	$url = 'https://ttboj.wordpress.com/'
	file { '/etc/motd':
		content => "This is Puppet-Ipa+Vagrant! (${url})\n",
	}
}

# puppetmaster
node puppet inherits default {

	if "${::vagrant_ipa_firewall}" != 'false' {
		include firewall
	}

	$allow = split("${::vagrant_ipa_allow}", ',')	# ip list fact

	class { '::puppet::server':
		pluginsync => true,	# do we want to enable pluginsync?
		storeconfigs => true,	# do we want to enable storeconfigs?
		autosign => [
			'*',		# FIXME: this is a temporary solution
			#"*.${domain}",	# FIXME: this is a temporary solution
		],
		#allow_duplicate_certs => true,	# redeploy without cert clean
		allow => $allow,	# also used in fileserver.conf
		repo => true,		# automatic repos
		shorewall => "${::vagrant_ipa_firewall}" ? {
			'false' => false,
			default => true,
		},
		start => true,
	}

	class { '::puppet::deploy':
		path => '/vagrant/puppet/',	# puppet folder is put here...
		backup => false,		# don't use puppet to backup...
	}
}

node /^ipa\d+$/ inherits default {	# ipa{1,2,..N}

	if "${::vagrant_ipa_firewall}" != 'false' {
		include firewall
	}

	class { '::puppet::client':
		#start => true,
		start => false,			# useful for testing manually...
	}

	if "${::vagrant_ipa_recipient}" == '' {
		# if no recipient is specified, we use a password of 'password'
		warning("The IPA recipient is empty. This is unsafe!")
	}

	$domain = $::domain
	class { '::ipa::server':
		domain => "${domain}",
		vip => "${::vagrant_ipa_vip}",
		topology => "${::vagrant_ipa_topology}" ? {
			'' => undef,
			default => "${::vagrant_ipa_topology}",
		},
		dm_password => "${::vagrant_ipa_recipient}" ? {
			'' => 'password',	# unsafe !!!
			default => undef,
		},
		admin_password => "${::vagrant_ipa_recipient}" ? {
			'' => 'password',	# unsafe !!!
			default => undef,
		},
		# NOTE: email must exist in the public key if we use gpg_sendemail
		#email => 'root@example.com',
		gpg_recipient => "${::vagrant_ipa_recipient}" ? {
			'' => undef,
			default => "${::vagrant_ipa_recipient}",
		},
		#gpg_publickey => '',
		gpg_keyserver => 'hkp://keys.gnupg.net',	# TODO: variable
		gpg_sendemail => false,
		vrrp => true,
		shorewall => "${::vagrant_ipa_firewall}" ? {
			'false' => false,
			default => true,
		},
	}

}

node /^client\d+$/ inherits default {	# client{1,2,..N}

	if "${::vagrant_ipa_firewall}" != 'false' {
		include firewall
	}

	class { '::puppet::client':
		#start => true,
		start => false,	# useful for testing manually...
	}

}

class firewall {

	$FW = '$FW'			# make using $FW in shorewall easier

	class { '::shorewall::configuration':
		# NOTE: no configuration specifics are needed at the moment
	}

	shorewall::zone { ['net', 'man']:
		type => 'ipv4',
		options => [],	# these aren't really needed right now
	}

	# management zone interface used by vagrant-libvirt
	shorewall::interface { 'man':
		interface => 'MAN_IF',
		broadcast => 'detect',
		physical => 'eth0',	# XXX: set manually!
		options => ['dhcp', 'tcpflags', 'routefilter', 'nosmurfs', 'logmartians'],
		comment => 'Management zone.',	# FIXME: verify options
	}

	# XXX: eth1 'dummy' zone to trick vagrant-libvirt into leaving me alone
	# <no interface definition needed>

	# net zone that ipa uses to communicate
	shorewall::interface { 'net':
		interface => 'NET_IF',
		broadcast => 'detect',
		physical => 'eth2',	# XXX: set manually!
		options => ['tcpflags', 'routefilter', 'nosmurfs', 'logmartians'],
		comment => 'Public internet zone.',	# FIXME: verify options
	}

	# TODO: is this policy really what we want ? can we try to limit this ?
	shorewall::policy { '$FW-net':
		policy => 'ACCEPT',		# TODO: shouldn't we whitelist?
	}

	shorewall::policy { '$FW-man':
		policy => 'ACCEPT',		# TODO: shouldn't we whitelist?
	}

	####################################################################
	#ACTION      SOURCE DEST                PROTO DEST  SOURCE  ORIGINAL
	#                                             PORT  PORT(S) DEST
	shorewall::rule { 'ssh': rule => "
	SSH/ACCEPT   net    $FW
	SSH/ACCEPT   man    $FW
	", comment => 'Allow SSH'}

	shorewall::rule { 'ping': rule => "
	#Ping/DROP    net    $FW
	Ping/ACCEPT  net    $FW
	Ping/ACCEPT  man    $FW
	", comment => 'Allow ping from the `bad` net zone'}

	shorewall::rule { 'icmp': rule => "
	ACCEPT       $FW    net                 icmp
	ACCEPT       $FW    man                 icmp
	", comment => 'Allow icmp from the firewall zone'}
}

