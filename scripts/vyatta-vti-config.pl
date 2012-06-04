#!/usr/bin/perl -w
#
# Module: vyatta-vti-config.pl
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
# Authors: Saurabh Mohan
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

use Getopt::Long;


my $vti_cfg_err = "VPN VTI configuration error:";
my $gencmds = "";
my $result = 0;
my $updown="";
my $intfName="";
my $action="";

GetOptions(
    "updown" => \$updown,
    "intf=s"   => \$intfName,
    "action=s" => \$action,
);


#
# --updown intfName --action=[up|down]
#
if ($updown ne '') {
    if (!(defined $intfName) || $intfName eq '' ) {
        # invalid
        exit -1;
    }
    if (!(defined $action) || $action eq '' ) {
        # invalid
        exit -1;
    }
    vti_handle_updown($intfName, $action);
    exit 0;
}

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
        if (!defined($mark)) {
            print STDERR "$vti_cfg_err mark not defined.\n";
            exit -1;
        }
        if ($mark eq "" || $mark eq "0") {
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
        #my $exists = `ls -l /sys/class/net/$tunName &> /dev/null`;

        # description.
        my $description = $vcIntf->returnValue("vti $tunName description");

        #
        # Set the configuration into the output string.
        #
        # By default we delete the tunnel...
        $gencmds .= "sudo /sbin/ip link delete $tunName type vti &> /dev/null\n";
        $gencmds .= "sudo /sbin/ip link add $tunName type vti key $mark remote $peer local $lip\n";
        foreach my $tunIP (@tunIPs) {
            $gencmds .= "sudo /sbin/ip addr add $tunIP dev $tunName\n";
        }
        $gencmds .= "sudo /sbin/ip link set $tunName mtu $mtu\n";

        if (defined($description)) {
            $gencmds .= "if [ -d /sys/class/net/$tunName ] ; then\n\tsudo echo \"$description\" > /sys/class/net/$tunName/ifalias\nfi\n";
        }
    }

if ($gencmds ne "") {
    open my $output_config, '>', '/tmp/vti_config' or die "Can't open /tmp/vti_config $!";
    print ${output_config} "#!/bin/sh\n";
    print ${output_config} $gencmds;
    close $output_config;
    `chmod 755 /tmp/vti_config`;
    system("/tmp/vti_config");
    $result = $? >> 8;
    #@SM TODO: remove /tmp/vti_config;
}
exit $result;


#
# Handle VTI tunnel state based on input from strongswan and configuration.
#
sub vti_handle_updown {
    my ($intfName, $action) = @_;
    use Vyatta::Config;
    my $vcIntf = new Vyatta::Config();
    $vcIntf->setLevel('interfaces');
    my $disabled = $vcIntf->exists("vti $intfName disabled");
    if (!defined($disabled) || ! $disabled) {
        system("sudo /sbin/ip link set $intfName $action\n");
    }
}
