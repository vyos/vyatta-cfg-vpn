#
# Module: VyattaVPNUtil.pm
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2005, 2006, 2007 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Marat
# Date: 2007
# Description:
#
# **** End License ****
#

package VyattaVPNUtil;

use strict;
use warnings;

use VyattaConfig;


use constant LOCAL_KEY_FILE_DEFAULT  => '/opt/vyatta/etc/config/ipsec.d/rsa-keys/localhost.key';

sub is_vpn_running {
    return ( -e '/var/run/pluto/pluto.ctl');
}

sub rsa_get_local_key_file {
    my $file = LOCAL_KEY_FILE_DEFAULT;
    
    #
    # Read configuration tree
    #
    my $vc = new VyattaConfig();
    $vc->setLevel('vpn');
    my $key_file_override = $vc->returnOrigValue('rsa-keys local-key file');
    
    #
    # We'll assume validation for valid path/file was handled in the
    # commit.
    #
    $file = $key_file_override if defined($key_file_override);
    
    return $file
}

sub rsa_get_local_pubkey {
    my ($file) = @_;
    
    unless ( -r $file) {
	return 0;
    }
    
    open(DAT, $file) || die("Could not open file $file!");
    my @raw_data=<DAT>;
    close(DAT);
    
    foreach my $line (@raw_data) {
	my $file_pubkey;
	if (($file_pubkey) = ($line =~ m/\s+\#pubkey=(\S+)/)) {
	    return $file_pubkey;
	}
    }
    return 0;
}

sub vpn_debug {
    use POSIX;
    my $timestamp = strftime("%Y%m%d-%H:%M.%S", localtime);
    open LOG, ">>", "/var/log/vpn-debug.log";
    print LOG "$timestamp: ", @_ , "\n";
    close LOG;
}

sub vpn_log {
    my ($msg) = @_;
    
    open LOG, ">> /tmp/ipsec.log";
    
    use POSIX;
    my $timestamp = strftime("%Y-%m-%d %H:%M.%S", localtime);
    
    print LOG "$timestamp\nLog: $msg\n";
    close LOG;
}

sub vpn_system {
    my ($cmdline) = @_;
    vpn_debug("START      $cmdline");
    my $ret = system($cmdline);
    if ($ret) {
	vpn_debug("END ERROR  $cmdline");
    } else {
	vpn_debug("END OK     $cmdline");
    }
}

sub enableICMP {
    my ($enable) = @_;
    
    opendir DIR, '/proc/sys/net/ipv4/conf/' or return undef;
    my @nodes = grep !/^\./, readdir DIR;
    closedir DIR;
    
    foreach my $node (@nodes) {
	my $OUT;
	open OUT, ">/proc/sys/net/ipv4/conf/$node/accept_redirects" or return undef;
	print OUT $enable;
	close OUT;
	open OUT, ">/proc/sys/net/ipv4/conf/$node/send_redirects" or return undef;
	print OUT $enable;
	close OUT;
    }
    return 1;
}

1;

