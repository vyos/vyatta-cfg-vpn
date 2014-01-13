#!/usr/bin/perl -w
#
# Module: vyatta-vpn-pppoe
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
# Portions created by Vyatta are Copyright (C) 2006, 2007 Vyatta, Inc.
# All Rights Reserved.
# 
# Authors: Stig Thormodsrud
# Date: July 2008
# Description: bring up/down vpn tunnel for pppoe/pppoa interfaces
#
# **** End License ****
# 

use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use POSIX;
use strict;
use warnings;

my $conf_file    = '/etc/ipsec.conf';
my $log_file     = '/var/log/pppoe-vpn.log';


sub logit {
    my $timestamp = strftime("%Y%m%d-%H:%M.%S", localtime);
    open my $fh, ">>", $log_file;
    print $fh "$timestamp: ", @_ , "\n";
    close $fh;
}

sub find_next_ipsec {
    my $list = shift;
    
    my $last = -1;

    while ($list =~ s/ipsec([0-9]+)\=\w+\d+//) {
	$last = $1 if $1 > $last;
    }
    return $last + 1;
}

sub is_dup {
    my ($line, $intf) = @_;

    while ($line =~ s/ipsec[0-9]+\=(\w+\d+)//) {
	return 1 if $1 eq $intf;
    }
    return 0;
}

sub vpn_add_intf {
    my ($line, $intf) = @_;

    logit("UP $intf");
    
    return (0, $line) if is_dup($line, $intf);

    my $intf_list;
    my $new_line;
    my $defaultroute = '';
    if ($line !~ /interfaces\=\"(.*)\"/) {
	return (0, $line);
    }
    $intf_list = $1;
    if ($intf_list =~ s/ \%defaultroute//) {
	$defaultroute = ' %defaultroute';
    } 
    my $ipsec_num = find_next_ipsec($intf_list);
    $intf_list .= " ipsec$ipsec_num\=$intf";
    $new_line = "     interfaces=\"$intf_list$defaultroute\"";
    return (1, $new_line);
}

sub vpn_remove_intf {
    my ($line, $intf) = @_;

    logit("DOWN $intf");
    if ($line =~ s/ipsec[0-9]+\=$intf//) {
	return (1, $line);
    } else {
	return (0, $line);
    }

}


my $pppoe_intf  = $ARGV[0];
my $mode        = $ARGV[1];

my $config = new Vyatta::Config;
$config->setLevel("vpn ipsec ipsec-interfaces");
my @ipsec_intfs = $config->returnOrigValues("interface");

#
# done if no vpn interfaces
#
exit 0 if scalar(@ipsec_intfs) == 0;

my $found = 0;
foreach my $intf (@ipsec_intfs) {
    $found++ if $pppoe_intf eq $intf;
}

#
# done if interface comming up isn't in vpn ipsec-interfaces
#
exit 0 if $found == 0;

#
# read current ipsec.conf
#
open(my $FD, '<', $conf_file)
    or die "Can't open [$conf_file] for read";
my @lines = <$FD>;
close $FD;

my @new_config = ();
my $changed = 0;
foreach my $line (@lines) {
    if ($line =~ /interfaces=\"/) {
	my $new_line;
	if ($mode eq 'up') {
	    ($changed, $new_line) = vpn_add_intf($line, $pppoe_intf);
	    $new_line .= "\n";
	} else {
	    ($changed, $new_line) = vpn_remove_intf($line, $pppoe_intf);
	}
	push @new_config, $new_line;
	chomp $line; chomp $new_line;
	logit("replacing [$line]");
	logit("with      [$new_line]");
    } else {
	push @new_config, $line;
    }
}

exit 0 if $changed == 0;

#
# write out new ipsec.conf
#
my $tmp_conf = "/tmp/ipsec.conf.$$";
open($FD, '>', $tmp_conf)
    or die "Can't open [$tmp_conf] for write";
print $FD @new_config;
close $FD;

my ($cmd, $rc);
$cmd = "mv $tmp_conf $conf_file";
$rc =system($cmd);
logit("$cmd = $rc");
my $update_interval = `cli-shell-api returnActiveValue vpn ipsec auto-update`;
if ($update_interval == ''){
  $cmd = "/usr/sbin/ipsec restart 2> /dev/null";
  $rc =system($cmd);
  logit("$cmd = $rc");
} else {
  $cmd = "/usr/sbin/ipsec restart --auto-update ".$update_interval." 2> /dev/null";
  $rc =system($cmd);
  logit("$cmd = $rc");
}

$cmd = "/usr/sbin/ipsec rereadall 2> /dev/null";
$rc = system($cmd);
logit("$cmd = $rc");

exit 0;

# end of file
