#!/usr/bin/perl
# Check a single IPv4 or IPv6 address

use NetAddr::IP;

$ip = $ARGV[0];

if( !defined($ip) ||
    $ip =~ "/"    || # Ensure it doesn't have prefix length
    !($addr = new NetAddr::IP $ip)
  ) {
      exit 1;
}

exit 0;
