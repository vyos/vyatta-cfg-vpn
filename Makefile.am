cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5/Vyatta/VPN
libudevdir	 = /lib/udev
etcudevdir	 = /etc/udev
initddir	 = /etc/init.d
curverdir = $(sysconfdir)/config-migrate/current

sbin_SCRIPTS =

sbin_SCRIPTS += scripts/vpn-config.pl
sbin_SCRIPTS += scripts/vyatta-vpn-ppp-updown.pl

share_perl5_DATA = lib/Vyatta/VPN/Util.pm

curver_DATA = cfg-version/ipsec@1

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)/etc/ppp/ip-up.d
	mkdir -p $(DESTDIR)/etc/ppp/ip-down.d
	cp scripts/vpn-ppp-up $(DESTDIR)/etc/ppp/ip-up.d/
	cp scripts/vpn-ppp-down $(DESTDIR)/etc/ppp/ip-down.d/
