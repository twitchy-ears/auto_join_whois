#!/usr/bin/perl
use strict;
use Socket qw(:addrinfo SOCK_RAW);
use vars qw($VERSION %IRSSI);

$VERSION = "0.0.1";
%IRSSI = (
  authors     => "Twitchy Ears",
  contact     => '',
  name        => "auto_join_whois",
  description => "Automatically whois joining users and extract details from their domain if not under a cloak",
  license     => "GPLv2",
  url         => "",
  changed     => "2023-03-13",
  modules     => ""
);

# This has room for improvement
#
# Takes an IP address either v4 or v6 shells out to whois then extracts the
# first instance of a number of keys from the response.
#
# Returns them comma seperated after the initial address given.
sub whois_and_extract {
  my $address = lc(shift) or return "unknown - no address given";
  
  $address =~ s/[^a-f:\.0-9]//g;

  my @out = qx{ whois '$address' };
  my $err = $?;
  return undef if ($err != 0);
  chomp(@out);

  my @data;

  # Extract the first key matching each of these
  foreach my $key (qw(netname organization organisation route origin country)) {
    my @d = grep(/^\s*${key}:\s+/i, @out);

    next if (! defined($d[0]) || ! $d[0]);

    $d[0] =~ s/^\s*\S+\:\s*//i;
    if ($d[0]) {
      push(@data, "$key: " . $d[0]);
    }
  }

  return $address . " " . join(", ", @data);
}

# Takes either an IP address or a hostname, attempts to resolve it back to one
# or more numeric hosts, calls whois_and_extract() on them one by one and
# returns the details of the first one that gets a whois response.
sub lookup_details {
  my $address = shift or return "lookup_details(): no arguments";
  my ($err, @res) = getaddrinfo($address, "", {socktype => SOCK_RAW});
  return "lookup_details: failure to resolve host" if ($err);

  my @errors;
  push(@errors, "lookup_details() errors: ");

  # Run through the addresses we get back and attempt to get information for
  # each, stop as soon as we get anything.
  foreach my $ai (@res) {
    my ($err, $ipaddr) = getnameinfo($ai->{addr}, NI_NUMERICHOST, NIx_NOSERV);
    if (! $err) {
      my $info = whois_and_extract($ipaddr);
      if (defined($info) && $info) {
	return $info;
      }
    }

    # Accumulate errors
    else {
      push(@errors, "Error: '$err'");
    }
  }

  return join(", ", @errors);
}

# Handler for people joining
sub event_message_join ($$$$) {
  my ($server, $channel, $nick, $raw_address) = @_;

  my $address = $raw_address;
  $address =~ s/^.*@//;

  if ($address !~ m!/!) { # Skip cloaks
    my $data = lookup_details($address);
    $server->print($channel, "auto-whois: $nick!$raw_address " . $data, MSGLEVEL_JOINS);
  }

  # $server->print($channel, "server '$server', channel '$channel', nick '$nick', address '$address'", MSGLEVEL_JOINS);
}				

Irssi::signal_add('message join', 'event_message_join');
