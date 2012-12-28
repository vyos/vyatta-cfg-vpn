cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/VPN
libudevdir	 = /lib/udev
etcudevdir	 = /etc/udev
initddir	 = /etc/init.d
logrotatedir     = /etc/logrotate.d
curverdir = $(sysconfdir)/config-migrate/current
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS =
sbin_PROGRAMS =

sbin_SCRIPTS += scripts/vpn-config.pl
sbin_SCRIPTS += scripts/dmvpn-config.pl
sbin_SCRIPTS += scripts/vyatta-vpn-ppp-updown.pl
sbin_SCRIPTS += scripts/is_valid_address.pl
sbin_SCRIPTS += scripts/vyatta-vti-config.pl

sbin_PROGRAMS += src/cfgvti

sbin_cfgvti = src/cfgvti.c

bin_sudo_users_SCRIPTS = scripts/vyatta-ipsec-dhcp.pl
share_perl5_DATA = lib/Vyatta/VPN/Util.pm
share_perl5_DATA += scripts/vtiIntf.pm

logrotate_DATA = etc/logrotate.d/vyatta-ipsec-logs

curver_DATA = cfg-version/ipsec@4

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)/etc/ppp/ip-up.d
	mkdir -p $(DESTDIR)/etc/ppp/ip-down.d
	mkdir -p $(DESTDIR)/etc/dhcp3/dhclient-exit-hooks.d/
	mkdir -p $(DESTDIR)/usr/lib/ipsec/
	cp scripts/vpn-ppp-up $(DESTDIR)/etc/ppp/ip-up.d/
	cp scripts/vpn-ppp-down $(DESTDIR)/etc/ppp/ip-down.d/
	cp scripts/ipsecd-dhclient-hook $(DESTDIR)/etc/dhcp3/dhclient-exit-hooks.d/ipsecd
	cp scripts/vti-up-down.sh $(DESTDIR)/usr/lib/ipsec/
