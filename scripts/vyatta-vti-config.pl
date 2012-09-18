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
use Vyatta::VPN::vtiIntf;


my $vti_cfg_err = "VPN VTI configuration error:";
my $gencmds = "";
my $result = 0;
my $updown="";
my $intfName="";
my $action="";
my $checkref="";

GetOptions(
    "updown" => \$updown,
    "intf=s"   => \$intfName,
    "action=s" => \$action,
    "checkref" => \$checkref,
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
# --checkref --intf=<intfName>
# Return 1 if the interface reference exits.
#
if ($checkref ne '' ) {
    if (!(defined $intfName) || $intfName eq '' ) {
        # invalid
        exit -1;
    }
    my $rval = vti_check_reference($intfName);
    exit $rval;
}

###
# Following code is to configure the vti.
#

vtiIntf::discoverVtiIntfs();

#
# Prepare Vyatta::Config object
#
use Vyatta::Config;
my $vcIntf = new Vyatta::Config();
my $vcVPN  = new Vyatta::Config();
$vcVPN->setLevel('vpn');
$vcIntf->setLevel('interfaces');

if (!$vcVPN->exists('ipsec') ) {
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}
if (!$vcVPN->exists('ipsec site-to-site') ) {
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}

    my %binds = ();
    my %vtiVpns = ();
    my @peers = $vcVPN->listNodes('ipsec site-to-site peer');
    foreach my $peer (@peers) {
        if (! $vcVPN->exists("ipsec site-to-site peer $peer vti")) {
            next;
        }
        #
        # we have the vti configured.
        #
        my $mark;
        my $lip = $vcVPN->returnValue("ipsec site-to-site peer $peer local-address");
        my $tunName = $vcVPN->returnValue("ipsec site-to-site peer $peer vti bind");
        my $change = 0;

        # Check local address is valid.
        if (!defined($lip)) {
            print STDERR "$vti_cfg_err local-address not defined.\n";
            exit -1;
        }

        if ($lip eq "" || $lip eq "0.0.0.0") {
            print STDERR "$vti_cfg_err Invalid local-address \"$lip\".\n";
            exit -1;
        }
        # Check tunName is valid.
        if (!defined($tunName) || $tunName eq ""  || ! $vcIntf->exists("vti $tunName") ) {
	    if (defined($tunName)) {
	            vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
			    "Invalid tunnel name vti \"$tunName\".\n");
	    } else {
	            vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
			    "tunnel name is empty.\n");
	    }
        }
        $vtiVpns{ $tunName } = 1;

        if (exists $binds{ $tunName }) {
                vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
                    "vti bind $tunName already used.\n");
        } else {
            $binds{ $tunName } = 1;
        }

        $gencmds .= "# For peer $peer local $lip, $tunName.\n";
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

        # Check if the tunnel exists already: by tunnel addresses.
        my $vtiPresent = vtiIntf::isVtinamepresent($peer, $lip);
        if (defined($vtiPresent) && !($vtiPresent eq "")) {
            if ($vtiPresent ne $tunName) {
                # Binding changed.
		my $currMark = vtiIntf::isVtimarkpresent($peer, $lip);
		$gencmds .= "sudo /sbin/ip link delete $vtiPresent &> /dev/null\n";
		$gencmds .= iptableDelMark($peer, $lip, $currMark);
		vtiIntf::deleteVtibyname($vtiPresent);
                $change = 1;
            }
        }

        my $existingMark = vtiIntf::isVtimarkpresent($peer, $lip);
        if (defined($existingMark) && !($existingMark eq "")) {
	    $mark = $existingMark;
        } else {
	    $mark = vtiIntf::allocVtiMark();
	    if ($mark == 0) {
                vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti"],
                    "vti failed to create (not able to allocate a mark)\n");
	    }
            $change = 1;
        }

        vtiIntf::deleteVtinamepresent($peer, $lip);
	vtiIntf::deleteVtibyname($tunName);
        if ($change eq 0) {
            next;
        }

        #
        # Set the configuration into the output string.
        #
        # By default we delete the tunnel...
        my $genmark = $mark;
        $gencmds .= "sudo /sbin/ip link delete $tunName &> /dev/null\n";
        $gencmds .= "sudo /opt/vyatta/sbin/cfgvti add name $tunName key $genmark remote $peer local $lip\n";
        foreach my $tunIP (@tunIPs) {
            $gencmds .= "sudo /sbin/ip addr add $tunIP dev $tunName\n";
        }
        $gencmds .= "sudo /sbin/ip link set $tunName mtu $mtu\n";

        if (defined($description)) {
            $gencmds .= "if [ -d /sys/class/net/$tunName ] ; then\n\tsudo echo \"$description\" > /sys/class/net/$tunName/ifalias\nfi\n";
        }

        # setup the new mark.
        $gencmds .= iptableAddMark($peer, $lip, $mark);
    }

    cleanupVtiNotConfigured();
    checkUnrefIntfVti($vcIntf, %vtiVpns);
    $result = execGenCmds();
    exit $result;


#
# Handle VTI tunnel state based on input from strongswan and configuration.
#
sub vti_handle_updown {
    my ($intfName, $action) = @_;
    use Vyatta::Config;
    my $vcIntf = new Vyatta::Config();
    $vcIntf->setLevel('interfaces');
    my $disabled = $vcIntf->existsOrig("vti $intfName disabled");
    if (!defined($disabled) || ! $disabled) {
        system("sudo /sbin/ip link set $intfName $action\n");
    }
}

sub vti_check_reference {
    my ($intfName) = @_;
    use Vyatta::Config;
    my $vcVPN = new Vyatta::Config();
    $vcVPN->setLevel('vpn ipsec site-to-site');
    my @peers = $vcVPN->listNodes('peer');
    if (@peers == 0) {
        return 0;
    }
    foreach my $peer (@peers) {
        if (! $vcVPN->exists("peer $peer vti")) {
            next;
        }
        if ( $vcVPN->exists("peer $peer vti bind $intfName")) {
            return 1;
        }
    }
    return 0;
}

sub iptableDelMark {
	my ($remote, $local, $mark) = @_;
	my $opcmd="";

	$opcmd .= "sudo iptables -t mangle -D PREROUTING -s $remote -d $local -p esp -j MARK --set-mark $mark\n";
	$opcmd .= "sudo iptables -t mangle -D PREROUTING -s $remote -d $local -p udp --dport 4500 -j MARK --set-mark $mark\n";
	return $opcmd;
}

sub iptableAddMark {
	my ($remote, $local, $mark) = @_;
	my $opcmd="";

	$opcmd .= "sudo iptables -t mangle -A PREROUTING -s $remote -d $local -p esp -j MARK --set-mark $mark\n";
	$opcmd .= "sudo iptables -t mangle -A PREROUTING -s $remote -d $local -p udp --dport 4500 -j MARK --set-mark $mark\n";
	return $opcmd;
}

sub cleanupVtiNotConfigured {
    # for all remaining entries in the Vtinamepresent hash
    # remove them from the system.
    my $localVtiNames = vtiIntf::getVtiNames();
    my $localVtibyNames = vtiIntf::getVtibyNames();
    while (my ($tunKey, $presentVtiName) =  each(%$localVtiNames) ) {
        my ($remote, $local) = vtiIntf::extractRemoteLocal($tunKey);
        my $existingMark = vtiIntf::isVtimarkpresent($remote, $local);
        $gencmds .= "# For peer $remote local $local.\n";
        $gencmds .= iptableDelMark($remote, $local, $existingMark);
        vtiIntf::freeVtiMark($existingMark);
    }
    for my $name (keys %$localVtibyNames) {
	$gencmds .= "#For tunnel name $name.\n";
        $gencmds .= "sudo /sbin/ip link delete $name &> /dev/null\n";
    }
}

sub execGenCmds {
    if ($gencmds ne "") {
        open my $output_config, '>', '/tmp/vti_config' or die "Can't open /tmp/vti_config $!";
        print ${output_config} "#!/bin/sh\n";
        print ${output_config} $gencmds;
        close $output_config;
        `chmod 755 /tmp/vti_config`;
        system("/tmp/vti_config");
        $result = $? >> 8;
        #TODO: remove /tmp/vti_config;
        return $result;
    }
    return 0;
}

sub vti_die {
  my (@path,$msg) = @_;
  Vyatta::Config::outputError(@path, $msg);
  exit 1;
}

#
# Check if there are any VTI's defined under 'interface vti'
# but not specified under VPN configuration
# For now just print a warning.
#
sub checkUnrefIntfVti {
    my $vcIntf = shift;
    my (%vtiVpns) = @_;

    my @vtiIntfs = $vcIntf->listNodes("vti");
    foreach my $tunName (@vtiIntfs) {
        if ( ! exists($vtiVpns{ $tunName }) ) {
            print STDOUT "Warning: [interface vti $tunName] defined but not used under VPN configuration\n";
        }
    }
}
