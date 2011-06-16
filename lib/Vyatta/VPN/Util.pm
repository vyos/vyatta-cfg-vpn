#
# Module: Vyatta::VPNUtil.pm
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

package Vyatta::VPN::Util;
use strict;
use warnings;

our @EXPORT = qw(rsa_get_local_key_file LOCAL_KEY_FILE_DEFAULT rsa_get_local_pubkey
                 is_vpn_running vpn_debug enableICMP is_tcp_udp get_protocols conv_protocol);
use base qw(Exporter);

use Vyatta::Config;
use POSIX qw(strftime);

use constant LOCAL_KEY_FILE_DEFAULT 
    => '/opt/vyatta/etc/config/ipsec.d/rsa-keys/localhost.key';

sub is_vpn_running {
    return ( -e '/var/run/pluto.ctl');
}

sub get_protocols {
  my $cmd = "sudo cat /etc/protocols";
  open(my $PROTOCOLS, "-|", $cmd);
  my @protocols = [];
  while(<$PROTOCOLS>){
    push (@protocols, $_);
  }
  my %protohash = ();
  foreach my $line (@protocols) {
    next if ($line =~ /^\#/);
    if ($line =~ /(\S+)\s+(\d+)\s+(\S+)\s+\#(.*)/){
      my ($name, $number, $desc) = ($1,$2,$4);
      if (not exists $protohash{$number}){
        $protohash{$number} = {
          _name => $name,
          _number => $number,
          _desc => $desc
        };
      }
    }
  }
  return %protohash;
}
 
sub conv_protocol {
  my $proto = pop(@_);
  my %protohash = get_protocols();
  foreach my $key (keys %protohash){
    if ("$key" == "$proto") {
      return $protohash{$key}->{_name};
    }
  }
  return $proto;
}


sub is_tcp_udp {
  my $protocol = pop @_;
  return 1 if (($protocol eq '6')  || ($protocol eq 'tcp') ||
               ($protocol eq '17') || ($protocol eq 'udp'));
  return 0;
}

sub rsa_get_local_key_file {
    my $file = LOCAL_KEY_FILE_DEFAULT;
    
    #
    # Read configuration tree
    #
    my $vc = new Vyatta::Config();
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
    
    open(my $dat, '<', $file) 
	or return 0;
    my @raw_data=<$dat>;
    close($dat);
    
    foreach my $line (@raw_data) {
	my $file_pubkey;
	if (($file_pubkey) = ($line =~ m/\s+\#pubkey=(\S+)/)) {
	    return $file_pubkey;
	}
    }
    return 0;
}

sub vpn_debug {
    my $timestamp = strftime("%Y%m%d-%H:%M.%S", localtime);

    open my $log, '>>', "/var/log/vpn-debug.log"
	or return;
    print {$log} "$timestamp: ", @_ , "\n";
    close $log;
}

sub vpn_log {
    my ($msg) = @_;
    
    open my $log, '>>', "/var/log/vyatta/ipsec.log"
	or return;
    
    my $timestamp = strftime("%Y-%m-%d %H:%M.%S", localtime);
    
    print {$log} "$timestamp\nLog: $msg\n";
    close $log;
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
    
    opendir my $dir, '/proc/sys/net/ipv4/conf/' 
	or return;
    my @nodes = grep !/^\./, readdir $dir;
    closedir $dir;
    
    foreach my $node (@nodes) {
	open my $out, '>', "/proc/sys/net/ipv4/conf/$node/accept_redirects"
	    or return;
	print {$out} $enable;
	close $out;
	open $out, '>', "/proc/sys/net/ipv4/conf/$node/send_redirects" 
	    or return;
	print {$out} $enable;
	close $out;
    }
    return 1;
}

1;
