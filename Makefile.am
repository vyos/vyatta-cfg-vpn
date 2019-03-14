cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/VPN
libudevdir	 = /lib/udev
etcudevdir	 = /etc/udev
initddir	 = /etc/init.d
logrotatedir     = /etc/logrotate.d
curverdir = $(sysconfdir)/config-migrate/current
bin_sudo_usersdir = /usr/libexec/vyos/system

sbin_SCRIPTS =

sbin_SCRIPTS += scripts/vpn-config.pl
sbin_SCRIPTS += scripts/dmvpn-config.pl
sbin_SCRIPTS += scripts/vyatta-vpn-ppp-updown.pl
sbin_SCRIPTS += scripts/vyatta-vti-config.pl

bin_sudo_users_SCRIPTS = scripts/vyatta-ipsec-dhcp.py
share_perl5_DATA = lib/Vyatta/VPN/Util.pm
share_perl5_DATA += lib/Vyatta/VPN/vtiIntf.pm

logrotate_DATA = etc/logrotate.d/vyatta-ipsec-logs

curver_DATA = cfg-version/ipsec@5

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)/etc/ppp/ip-up.d
	mkdir -p $(DESTDIR)/etc/ppp/ip-down.d
	mkdir -p $(DESTDIR)/etc/dhcp/dhclient-exit-hooks.d/
	mkdir -p $(DESTDIR)/usr/lib/ipsec/
	cp scripts/vpn-ppp-up $(DESTDIR)/etc/ppp/ip-up.d/
	cp scripts/vpn-ppp-down $(DESTDIR)/etc/ppp/ip-down.d/
	cp scripts/ipsecd-dhclient-hook $(DESTDIR)/etc/dhcp/dhclient-exit-hooks.d/ipsecd
	cp scripts/vti-up-down $(DESTDIR)/usr/lib/ipsec/
