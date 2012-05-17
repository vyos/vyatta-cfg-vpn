#!/usr/bin/perl -w
#
# Module: vpn-config.pl
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
# Portions created by Vyatta are Copyright (C) 2006, 2007, 2008, 2009 Vyatta, Inc.
# All Rights Reserved.
#
# Authors: Justin Fletcher, Marat Nepomnyashy
# Date: 2012
# Description: setup the vti tunnel
#
# **** End License ****
#
#
# For each VTI tunnel (vpn ipsec site-to-site peer ip-address sti); find the vti tunnel, local address, mark.
#   Find the corresponding tunnel (interfaces vti vtiXXX), tunnel address, disable, mtu
#        if not configured: ip tunnel add vtiXXX mode esp local $local remote $remote i_key $mark
#                           if (mtu): configure mtu
#                           if (tunnel-addres): configur ip link vtiXXX address
#                           if (!disable): enable the interface.
#

use strict;
use lib "/opt/vyatta/share/perl5";

use Vyatta::TypeChecker;
use Vyatta::VPN::Util;
use Getopt::Long;
use Vyatta::Misc;
use NetAddr::IP;


my $vti_cfg_err = "VPN VTI configuration error:";
my $gencmds = "";
my $result = 0;

#
# Prepare Vyatta::Config object
#
use Vyatta::Config;
my $vcIntf = new Vyatta::Config();
my $vcVPN  = new Vyatta::Config();
$vcVPN->setLevel('vpn');
$vcIntf->setLevel('interfaces');

if (!$vcVPN->exists('ipsec') ) {
    exit $result;
}
if (!$vcVPN->exists('ipsec site-to-site') ) {
    exit $result;
}

my @peers = $vcVPN->listNodes('ipsec site-to-site peer');
if (@peers == 0) {
    exit $result;
}
    foreach my $peer (@peers) {
        if (! $vcVPN->exists("ipsec site-to-site peer $peer vti")) {
            next;
        }
        #
        # we have the vti configured.
        #
        my $lip = $vcVPN->returnValue("ipsec site-to-site peer $peer local-address");
        my $mark = $vcVPN->returnValue("ipsec site-to-site peer $peer vti mark");
        my $tunName = $vcVPN->returnValue("ipsec site-to-site peer $peer vti bind");

        # Check local address is valid.
        if (!defined($lip)) {
            print STDERR "$vti_cfg_err local-address not defined.\n";
            exit -1;
        }

        if ($lip eq "" || $lip eq "0.0.0.0") {
            print STDERR "$vti_cfg_err Invalid local-address \"$lip\".\n";
            exit -1;
        }
        # Check mark is valid.
        if (!defined($mark) || $mark eq "" || $mark eq "0") {
            print STDERR "$vti_cfg_err Invalid mark \"$mark\".\n";
            exit -1;
        }
        # Check tunName is valid.
        if (!defined($tunName) || $tunName eq ""  || ! $vcIntf->exists("vti $tunName") ) {
            print STDERR "$vti_cfg_err Invalid tunnel name vti \"$tunName\".\n";
            exit -1;
        }
        #
        # Get the tunnel parameters.
        #
        # ip address's
        my @tunIPs = $vcIntf->returnValues("vti $tunName address");
        # mtu
        my $mtu = $vcIntf->returnValue("vti $tunName mtu");
        if (!defined($mtu) || $mtu eq "") {
            $mtu = 1500;
        }
        # disabled or not.
        my $disabled = $vcIntf->exists("vti $tunName disabled");
        #my $exists = `ls -l /sys/class/net/$tunName &> /dev/null`;

        # description.
        my $description = $vcIntf->returnValue("vti $tunName description");

        #
        # Set the configuration into the output string.
        #
        # By default we delete the tunnel...
        $gencmds .= "sudo /sbin/ip tunnel del $tunName &> /dev/null\n";
        $gencmds .= "sudo /sbin/ip tunnel add $tunName mode esp remote $peer local $lip ikey $mark\n";
        foreach my $tunIP (@tunIPs) {
            $gencmds .= "sudo /sbin/ip addr add $tunIP dev $tunName\n";
        }
        $gencmds .= "sudo /sbin/ip link set $tunName mtu $mtu\n";

        if (! $disabled) {
            # @SM TODO: Don not bring the tunnel link-state up till strongswan does it.
            $gencmds .= "sudo /sbin/ip link set $tunName up\n";
            # @SM TODO: Add the static routes over this tunnel...
        }
        if (defined($description)) {
            $gencmds .= "sudo /sbin/ip tunnel show $tunName || sudo echo \"$description\" > /sys/class/net/$tunName/ifalias\n";
        }
    }

if ($gencmds ne "") {
    open my $output_config, '>', '/tmp/vti_config' or die "Can't open /tmp/vti_config $!";
    print ${output_config} "#!/bin/sh\n";
    print ${output_config} $gencmds;
    close $output_config;
    `chmod 755 /tmp/vti_config`;
    #$result=`/tmp/vti_config`;
    #@SM TODO: remove /tmp/vti_config;
}
exit $result;
