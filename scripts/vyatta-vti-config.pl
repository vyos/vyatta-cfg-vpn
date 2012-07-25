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

# Collect set of existing Vti's.
my %existingVtiName = ();
my %existingVtiMark = ();

my @currentVtis = `/sbin/ip tunnel | grep "^vti"`;
if (@currentVtis != 0) {
	my ($remote, $local, $name, $mark);
	my $key;
	foreach my $curVti (@currentVtis) {
		($remote, $local, $name, $mark) = parseVtiTun($curVti);
		$key = "remote $remote local $local";
		$existingVtiName{$key} = $name;
		$existingVtiMark{$key} = $mark;
	}
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
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}
if (!$vcVPN->exists('ipsec site-to-site') ) {
    cleanupVtiNotConfigured();
    $result = execGenCmds();
    exit $result;
}

    my %marks = ();
    my %binds = ();
    my @peers = $vcVPN->listNodes('ipsec site-to-site peer');
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
            print STDERR "$vti_cfg_err Invalid tunnel name vti \"$tunName\".\n";
            exit -1;
        }
        if (exists $binds{ $tunName }) {
                vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti","bind"],
                    "vti bind $tunName already used.\n");
        } else {
            $binds{ $tunName } = 1;
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
        if (exists $marks{ $mark }) {
                vti_die(["vpn","ipsec","site-to-site","peer",$peer,"vti","mark"],
                    "vti mark $mark already used.\n");
        } else {
            $marks{ $mark } = 1;
        }

        $gencmds .= "# For peer $peer local $lip.\n";
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

        # Check if the tunnel exists already.
        my $vtiPresent = isVtinamepresent($peer, $lip);
        if (defined($vtiPresent) && !($vtiPresent eq "")) {
            if ($vtiPresent ne $tunName) {
                # Binding changed.
    			$gencmds .= "sudo /sbin/ip link delete $vtiPresent &> /dev/null\n";
                $change = 1;
            }
        }

        my $existingMark = isVtimarkpresent($peer, $lip);
        if (defined($existingMark) && !($existingMark eq "")) {
            if ($existingMark ne $mark) {
                # Mark changed.
                $gencmds .= iptableDelMark($peer, $lip, $existingMark);
                $change = 1;
            }
        } else {
            $change = 1;
        }

        if ($change eq 0) {
            # now remove it from the exisiting tunnel list as
            # we've already configured it.
            deleteVtinamepresent($peer, $lip);
            next;
        }

        #
        # Set the configuration into the output string.
        #
        # By default we delete the tunnel...
        $gencmds .= "sudo /sbin/ip link delete $tunName &> /dev/null\n";
        $gencmds .= "sudo /opt/vyatta/sbin/cfgvti add name $tunName key $mark remote $peer local $lip\n";
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

#
# Api takes as input the o/p of 'ip tunnel show' and
#  returns a list with {remote,local,name,mark}
# Example input:
# vti2: ip/ip  remote 12.0.0.2  local 12.0.0.1  ttl inherit  nopmtudisc key 15
# 
sub parseVtiTun {
	my ($tunop) = @_;
	my ($tunName, $remote, $local, $mark);
	if ($tunop =~ m/(^vti.*): .*/) {
		$tunName = $1;
	}
	if ($tunop =~ m/remote ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
		$remote = $1;
	}
	if ($tunop =~ m/local ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
		$local = $1;
	}
	if ($tunop =~ m/key ([0-9\.]+)/) {
		$mark = $1;
	}
	return($remote, $local, $tunName, $mark);
}

sub extractRemoteLocal {
	my ($key) = @_;
	my ($remote, $local);
	if ($key =~ m/remote ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
		$remote = $1;
	}
	if ($key =~ m/local ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
		$local = $1;
	}
	return($remote, $local);
}

sub isVtinamepresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiName{$key} ) {
		return $existingVtiName{$key};
	}
	return ""; 
}

sub deleteVtinamepresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiName{$key} ) {
		delete $existingVtiName{$key};
	}
}

sub isVtimarkpresent {
	my ($remote, $local) = @_;
	my $key = "remote $remote local $local";

	if (exists $existingVtiMark{$key} ) {
		return $existingVtiMark{$key};
	}
	return ""; 
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
    while (my ($tunKey, $presentVtiName) =  each(%existingVtiName) ) {
        my ($remote, $local) = extractRemoteLocal($tunKey);
        my $existingMark = isVtimarkpresent($remote, $local);
        $gencmds .= "# For peer $remote local $local.\n";
        $gencmds .= "sudo /sbin/ip link delete $presentVtiName &> /dev/null\n";
        $gencmds .= iptableDelMark($remote, $local, $existingMark);
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
