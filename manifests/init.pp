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

# README: this is a rather complicated module to understand. read the comments!

# NOTE: if you ever see a puppet error where an ipa exec returns with:
#	ipa: ERROR: no modifications to be performed
# then please report this as a bug. This puppet module is (supposed to be)
# smart enough to only run exec's when they are actually necessary.

# NOTE: to hack your way into the ipa web ui with ssh port forwarding, when the
# computer you are using is completely isolated from the actual ipa server, you
# could fake the dns entry in your /etc/hosts file by adding/ensuring the line:
#	127.0.0.1 ipa.example.com ipa localhost.localdomain localhost
# exists (replace example.com with your ipa domain of course) and then running:
#	sudo ssh root@ipa -L 80:localhost:80 -L 443:localhost:443 # (as root !)
# to force forwarding on priviledged ports, and then point your web browser to:
#	https://ipa.example.com/ipa/ui/
# and then accept the certificate. but don't do any of this, it's an evil hack!

# NOTE: this expects mit kerberos: http://web.mit.edu/kerberos/krb5-latest/doc/

# NOTE: useful ipa docs at: https://access.redhat.com/site/documentation/en-US/
# Red_Hat_Enterprise_Linux/6/html-single/Identity_Management_Guide/index.html

# NOTE: if on client reinstall ipa-client-install complains with:
#	freeipa LDAP Error: Connect error: TLS error -8054: You are attempting
#	to import a cert with the same issuer/serial as an existing cert, but
#	that is not the same cert.
# just: 'rm /etc/ipa/ca.crt', bug: https://fedorahosted.org/freeipa/ticket/3537

# NOTE: if you wish to use the $dns option, it must be enabled at first install
# subsequent enabling/disabling is currently not supported. this is because of:
#	https://fedorahosted.org/freeipa/ticket/3726
#	(ipa-dns-install needs a --uninstall option)
# and also because the DM_PASSWORD might not be available if we gpg encrypt and
# email it out after randomly generating it. This is a security feature! (TODO) <- CHANGE TO (DONE) when finished!
# we could actually support install and uninstall if that bug was resolved, and
# if we either regenerated the password, or were able to circumvent it with our
# root powers somehow. this is actually quite plausible, but not worth the time

# TODO: maybe we could have an exported resource that creates a .k5login in the
# root home dirs of machines to give access to other admins with their tickets?

# TODO: a ...host::dns type or similar needs to be added to manage and host ips

