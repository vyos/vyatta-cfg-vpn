#!/usr/bin/perl -w
#
# module to find and store exisiting vti tunnels.

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
# Portions created by Vyatta are Copyright (C) 2012 Vyatta, Inc.
# All Rights Reserved.
#
# Authors: Saurabh Mohan
# Date: 2012
# Description: Find and store exisiting vti tunnels
#
# **** End License ****
#
#

package vtiIntf;

use strict;

# Collect set of existing Vti's.
my %existingVtiName = ();
my %existingVtibyName = ();
my %existingVtiMark = ();
my @VtiMarks;
my $vtiMarkBase = 0x90000000;
my $maxMarks = 2048;

sub discoverVtiIntfs {
    my @currentVtis = `/sbin/ip tunnel | grep "^vti"`;
    if (@currentVtis != 0) {
    	my ($remote, $local, $name, $mark);
    	my $key;
    	foreach my $curVti (@currentVtis) {
    		($remote, $local, $name, $mark) = parseVtiTun($curVti);
    		$key = "remote $remote local $local";
    		$existingVtiName{$key} = $name;
    		$existingVtiMark{$key} = $mark;
    		$VtiMarks[$mark-$vtiMarkBase] = 1;
            $existingVtibyName{$name} = 1;
    	}
    }
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

#
# Pass a referenct to the existing Vti names.
#
sub getVtiNames {
	return (\%existingVtiName);
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

sub allocVtiMark {
	for my $cmark (1 .. ($maxMarks-1)) {
		if (! defined($VtiMarks[$cmark])) {
			$VtiMarks[$cmark] = 1;
			return $cmark + $vtiMarkBase ;
		}
	}
	return 0;
}

sub freeVtiMark {
	my ($freeMark) = @_;
	if ($freeMark > 0 && $freeMark < $maxMarks) {
		$VtiMarks[$freeMark] = 0;
	}
	return 0;
}

sub isVtibynamepresent {
    my ($name) = @_;
    if (exists $existingVtibyName{$name} ) {
        return $existingVtibyName{$name};
    }
    return 0;
}

sub deleteVtibyname {
    my ($name) = @_;
    if (exists $existingVtibyName{$name} ) {
        delete $existingVtibyName{$name};
    }
}

sub getVtibyNames {
    return (\%existingVtibyName);
}

1;
