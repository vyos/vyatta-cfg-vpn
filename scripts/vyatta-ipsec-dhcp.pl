#!/usr/bin/perl
use Getopt::Long;
use strict;

my $config_file = "/etc/ipsec.conf";
my $secrets_file = "/etc/ipsec.secrets";

sub logger {
  my $msg = pop(@_);
  my $FACILITY = "daemon";
  my $LEVEL = "notice";
  my $TAG = "ipsec-dhclient-hook";
  my $LOGCMD = "logger -t $TAG -p $FACILITY.$LEVEL";
  system("$LOGCMD $msg");
}

my ($iface, $config_iface, $nip, $oip, $reason);
GetOptions("interface=s"    => \$iface,
           "new_ip=s"       => \$nip,
           "old_ip=s"       => \$oip,
           "reason=s"       => \$reason);

# check if an update is needed
exit(0) if (($oip eq $nip) && ($reason ne "BOUND"));
logger("DHCP address updated to $nip from $oip: Updating ipsec configuration.");

# open ipsec config
open (my $FD, '<', $config_file);
my $header = '';
my $footer = '';
my $finheader = 0;
my %connhash = ();
my $curconn = '';
foreach my $line (<$FD>){
  next if (($line =~/^\s*$/) && $finheader);
  if ($line =~ /\#conn.*/){
    $curconn = '';
    next;
  }
  if ($line =~ /(peer-.*-tunnel.*)/){
    $finheader = 1;
    my $connid = $1;
    $curconn = $connid;
    if (not exists $connhash{$connid}){
      $connhash{$connid} = {
          _dhcp_iface => undef,
          _lip        => undef,
          _lines      => []
      };
    }
  } elsif (($line =~ /dhcp-interface=(.*)/) && ($curconn ne '') ){
    $connhash{$curconn}->{_dhcp_iface}=$1;
  } elsif (($line =~ /left=(.*)/) && ($curconn ne '') ){
    $connhash{$curconn}->{_lip}=$1;
  } elsif (!$finheader){
    $header .= $line;
  } elsif ($curconn ne ''){
    push (@{$connhash{"$curconn"}->{_lines}}, $line);
  } elsif ($curconn eq ''){
    $footer .= $line;
  }
}
close($FD);

# output new ipsec.conf
open my $output_config, '>', $config_file
    or die "Can't open $config_file: $!";

print ${output_config} "$header\n";
foreach my $connid ( keys (%connhash)){
  print ${output_config} "conn $connid\n";
  if (defined($connhash{$connid}->{_dhcp_iface})){
    if ($connhash{$connid}->{_dhcp_iface} eq $iface){
      $connhash{$connid}->{_lip} = $nip;
    }
    print ${output_config} "\t\#dhcp-interface=$connhash{$connid}->{_dhcp_iface}\n";
  }
  print ${output_config} "\tleft=$connhash{$connid}->{_lip}\n";
  foreach my $line (@{$connhash{$connid}->{_lines}}){
    print ${output_config} $line;
  }
  print ${output_config} "\#conn $connid\n\n";
}
print ${output_config} "$footer\n";
close $output_config;

# change ipsec.secrets
open (my $FD, '<', $secrets_file);
my @lines = <$FD>;
close FD;
open my $output_secrets, '>', $secrets_file
  or die "Can't open $secrets_file";
foreach my $line (@lines){
  if (($line =~ /(.*)\#dhcp-interface=(.*)\#/) && ($2 eq $iface)){
    my $secretline = $1;
    $nip = "#" if ($nip eq '');
    $secretline =~ /(.*?) (.*?) : PSK (.*)/;
    $line = "$nip $2 : PSK $3\#dhcp-interface=$iface\#\n";
  }
  print ${output_secrets} $line;
}
close $output_secrets;
system ("/usr/sbin/ipsec rereadall > /dev/null 2>&1");
system ("/usr/sbin/ipsec update > /dev/null 2>&1");
