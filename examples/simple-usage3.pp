# here is an example of how to use user excludes and types:

# on the ipa server:
# NOTE: the 'admin' user is automatically excluded from being auto purged...
class { '::ipa::server':
	shorewall => true,
	user_excludes => [
		"^test[0-9]{1,}\$",	# test\d
	],
}

# create an unmanaged user
ipa::server::user { 'james':
	first => 'James',
	last => 'Shubin',
	modify => false,
	watch => false,
}

# create a managed user
ipa::server::user { 'ntesla':
	first => 'Nikola',
	last => 'Tesla',
	city => 'Shoreham',
	state => 'New York',
	postalcode => '11786',
}

# create a user using a full principal as the primary key
# NOTE: the principal itself can't be edited without a remove/add
ipa::server::user { 'aturing/admin@EXAMPLE.COM':
	first => 'Alan',
	last => 'Turning',
	random => true,		# set a password randomly
	password_file => true,	# store the password in plain text ! (bad)
}

# create a user by principal but without the instance set
ipa::server::user { 'arthur@EXAMPLE.COM':
	first => 'Arthur',
	last => 'Guyton',
	jobtitle => 'Physiologist',
	orgunit => 'Research',
}

