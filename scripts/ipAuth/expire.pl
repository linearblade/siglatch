#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin";
use grantLib;
use grantConfig;
use POSIX qw(strftime);

print "RUNNING EXPIRE\n";

# Parse context
my ($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload) = @ARGV;
my $entry = parseEntry($ip, $uid, $uname, $actcode, $actname, $encrypted, $b64payload);

writeLog($grantConfig::grantLog, $entry);

# Perform expiration with user-supplied context
my $grants = readGrants($grantConfig::grantTable);
expireCron($grants, "expired by $uname\@$ip");
