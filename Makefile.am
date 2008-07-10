cfgdir		 = $(datadir)/vyatta-cfg/templates
share_perl5dir	 = $(datarootdir)/perl5
libudevdir	 = /lib/udev
etcudevdir	 = /etc/udev
initddir	 = /etc/init.d
curverdir = $(sysconfdir)/config-migrate/current

sbin_SCRIPTS =

sbin_SCRIPTS += scripts/vpn-config.pl

share_perl5_DATA = scripts/VyattaVPNUtil.pm

curver_DATA = cfg-version/ipsec@1

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)

