# here is an example of how to use host excludes:
class { '::ipa::server':
	shorewall => true,
	host_excludes => [
		"'foo-42.example.com'",			# exact string match
		'"foo-bar.example.com"',		# exact string match
		"^[a-z0-9-]*\\-foo\\.example\\.com$",	# *-foo.example.com or:
		"^[[:alpha:]]{1}[[:alnum:]-]*\\-foo\\.example\\.com$",
		"^foo\\-[0-9]{1,}\\.example\\.com"	# foo-<\d>.example.com
	],
}

# you'll see that you need double \\ to escape out the one we want in the match

# if you just want to match most sane domain strings and avoid auto deletion:
class { '::ipa::server':
	shorewall => true,
	host_excludes => true,	# automatically chooses a match all pattern
}

# please remember that *any* match in the list will exclude a host deletion
# if you prefer to specify only one match, a single string will work too...
# if you want to be more dynamic, you can use something like:

$match_domain = regsubst("${domain}", '\.', '\\.', 'G')
class { '::ipa::server':
	domain => "${domain}",
	shorewall => true,
	host_excludes => [
		"^test[0-9]{1,}\\.${match_domain}\$",	# test\d.domain
	],
}

# i found some notes on available bracket expressions here:
# http://www.regular-expressions.info/posixbrackets.html

